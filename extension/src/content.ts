// The content script, in every http(s) frame. It notices login fields,
// offers the saved logins for this frame's site in a menu, fills the one the
// user picks (with a real click or key press), and passes a sent login form
// to the background so the top frame can offer to save it.
//
// Nothing is filled on its own: a page can't make the extension fill a
// field without the user choosing a login in the menu. Events a page script
// makes up (`isTrusted` false) open nothing, move nothing into the menu and
// send no login to the background.

import {
  fill,
  isPassword,
  isVisible,
  type LoginFields,
  loginFieldsFor,
  onScreen,
  scopeOf,
  typedIn,
} from './content/fields';
import { LoginMenu, SaveBanner, type SaveOffer } from './content/surfaces';
import { ext } from './shared/ext';
import { t } from './shared/i18n';
import type {
  FillReply,
  LoginsReply,
  PendingSaveReply,
  SaveReply,
  ToBackground,
} from './shared/messages';

const MARK = '__sshkmAutofill';

function send<T>(message: ToBackground): Promise<T | null> {
  return (ext.runtime.sendMessage(message) as Promise<T | null>).catch(() => null);
}

function start(): void {
  let active: { input: HTMLInputElement; fields: LoginFields } | null = null;
  /** Bumped when the user types: a menu asked for before then stays closed. */
  let keystrokes = 0;
  let lastCapture = { at: 0, key: '' };

  const menu = new LoginMenu({
    onPick: (login) => void pick(login.id),
    onUnlock: () => {
      menu.hide();
      void send({ kind: 'unlock' });
    },
    onLeave: () => {
      const input = active?.input;
      menu.hide();
      input?.focus();
    },
  });

  const banner = new SaveBanner({
    onSave: async (offer: SaveOffer) => {
      const reply = await send<SaveReply>({ kind: 'save', id: offer.id });
      if (reply?.ok)
        return { ok: true, message: reply.mode === 'update' ? t('updated') : t('saved') };
      if (reply?.problem === 'locked') {
        void send({ kind: 'unlock' });
        return { ok: false, message: t('saveLocked') };
      }
      return { ok: false, message: t('saveFailed') };
    },
    onDismiss: (offer) => void send({ kind: 'dismissSave', id: offer.id }),
  });

  async function offer(input: HTMLInputElement): Promise<void> {
    const fields = loginFieldsFor(input);
    if (!fields) {
      menu.hide();
      return;
    }
    active = { input, fields };
    const asked = keystrokes;
    const reply = await send<LoginsReply>({ kind: 'logins' });
    if (document.activeElement !== input || active?.input !== input || keystrokes !== asked) return;
    // A field the page focused without scrolling to it is out of sight.
    if (!isVisible(input) || !onScreen(input)) {
      menu.hide();
      return;
    }
    if (reply?.state === 'ready' && reply.logins.length > 0) menu.showLogins(input, reply.logins);
    else if (reply?.state === 'locked' && fields.password) menu.showLocked(input);
    else menu.hide();
  }

  async function pick(entryId: string): Promise<void> {
    const current = active;
    if (!current) return;
    const reply = await send<FillReply>({ kind: 'fill', entryId });
    if (!reply?.ok) {
      if (reply?.problem === 'locked') menu.showLocked(current.input);
      else menu.hide();
      return;
    }
    const { username, password } = current.fields;
    if (username && reply.username) fill(username, reply.username);
    if (password) fill(password, reply.password);
    menu.hide();
    (password ?? username)?.focus();
  }

  function capture(scope: ParentNode): void {
    const typed = typedIn(scope);
    if (!typed) return;
    // A click on the button and the submit event that follows are one login.
    const key = `${typed.username}\n${typed.password.length}`;
    if (key === lastCapture.key && Date.now() - lastCapture.at < 2000) return;
    lastCapture = { at: Date.now(), key };
    void send({ kind: 'capture', ...typed });
  }

  async function offerSave(): Promise<void> {
    if (window !== window.top) return;
    const pending = await send<PendingSaveReply>({ kind: 'pendingSave' });
    if (pending) banner.show(pending);
  }

  document.addEventListener(
    'focusin',
    (event) => {
      if (!event.isTrusted) return;
      const target = event.target;
      if (menu.contains(target) || banner.contains(target)) return;
      if (target instanceof HTMLInputElement) void offer(target);
      else menu.hide();
    },
    true,
  );

  document.addEventListener(
    'focusout',
    (event) => {
      if (event.target === active?.input && !menu.contains(event.relatedTarget)) {
        // Let a click on the menu land first.
        setTimeout(() => {
          if (!menu.contains(document.activeElement) && document.activeElement !== active?.input) {
            menu.hide();
          }
        }, 150);
      }
    },
    true,
  );

  document.addEventListener(
    'pointerdown',
    (event) => {
      if (!event.isTrusted) return;
      const target = event.target;
      if (menu.contains(target)) return;
      // A click into the field that already has focus opens the menu again.
      if (target instanceof HTMLInputElement && target === document.activeElement) {
        if (!menu.shown) void offer(target);
        return;
      }
      menu.hide();
    },
    true,
  );

  document.addEventListener(
    'keydown',
    (event) => {
      const target = event.target;
      if (!event.isTrusted || !(target instanceof HTMLInputElement)) return;
      if (menu.shown && target === active?.input) {
        if (event.key === 'ArrowDown') {
          event.preventDefault();
          menu.focusFirst();
        } else if (event.key === 'Escape') {
          menu.hide();
        }
      }
      if (event.key === 'Enter' && isPassword(target)) capture(scopeOf(target));
    },
    true,
  );

  document.addEventListener(
    'input',
    (event) => {
      if (!event.isTrusted) return;
      keystrokes += 1;
      if (event.target === active?.input) menu.hide();
    },
    true,
  );

  document.addEventListener(
    'submit',
    (event) => {
      if (event.isTrusted && event.target instanceof HTMLFormElement) capture(event.target);
    },
    true,
  );

  // Many sign-in pages send the form with script on a button click.
  document.addEventListener(
    'click',
    (event) => {
      if (!event.isTrusted || !(event.target instanceof Element)) return;
      const button = event.target.closest('button, input[type=submit], [role=button]');
      if (!button) return;
      const scope =
        button instanceof HTMLButtonElement || button instanceof HTMLInputElement
          ? (button.form ?? null)
          : null;
      const password = (scope ?? document).querySelector<HTMLInputElement>('input[type=password]');
      if (password?.value) capture(scope ?? scopeOf(password));
    },
    true,
  );

  ext.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== ext.runtime.id) return undefined;
    if ((message as { kind?: string } | null)?.kind === 'offerSave') void offerSave();
    return undefined;
  });

  void offerSave();
}

/**
 * Whether this document's origin is opaque: a sandboxed frame, whose URL
 * may be a site's though its content isn't that site's to vouch for. The
 * background refuses such frames by the origin the browser reports; this
 * covers a browser that reports none.
 */
function opaqueOrigin(): boolean {
  if (self.origin === 'null') return true;
  try {
    // Throws in a sandboxed document without `allow-same-origin`.
    void document.cookie;
    return false;
  } catch {
    return true;
  }
}

if (/^https?:$/.test(location.protocol) && !opaqueOrigin() && !(MARK in window)) {
  Object.defineProperty(window, MARK, { value: true });
  start();
}
