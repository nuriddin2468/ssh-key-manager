// The content script, in every http(s) frame. It notices login fields,
// offers the saved logins for this frame's site in a menu, fills the one the
// user picks (with a real click or key press), and passes a sent login form
// to the background so the top frame can offer to save it.
//
// The menu stays out of the way of a login already there: it doesn't open by
// itself on a form whose password field holds something (typed, or filled by
// the page or the browser), only on Down Arrow. Logins for the username the
// user typed come first. The username sent with the first step of a two-step
// login goes to the background too, to name the password sent next.
//
// A password-change form passes on its new password, flagged as such
// (content/fields.ts tells such forms apart), so the banner offers to update
// the saved login with it.
//
// When the user sends a form with a login filled from the menu, and the
// site's sign-in form comes back empty moments later (the page reloaded or
// redrew it), the top frame says the saved password may be out of date,
// once per login per tab: the background keeps track (background.ts).
//
// Nothing is filled on its own: a page can't make the extension fill a
// field without the user choosing a login in the menu. Events a page script
// makes up (`isTrusted` false) open nothing, move nothing into the menu and
// send no login to the background. Some a page script causes are marked as
// trusted all the same, so more is asked of them:
// - focus: `focus()` and `autofocus` open no menu. The menu opens when the
//   user clicks a field, moves to it with Tab, or presses Down Arrow in it.
// - sending: `requestSubmit()` sends a form with a trusted `submit` event.
//   A login goes to the background only with a password the user put in
//   themselves (content/typing.ts), and only when the user sent it: with
//   Enter, a click, or a `submit` right after their own key press or click.

import {
  fill,
  holdsValue,
  isPassword,
  isVisible,
  type LoginFields,
  loginFieldsFor,
  onScreen,
  scopeOf,
  signInFormAgain,
  typedIn,
  usernameStep,
  usernameStepIn,
} from './content/fields';
import { forUsername } from './content/logins';
import { LoginMenu, SaveBanner, type SaveOffer, SignInBanner } from './content/surfaces';
import { Typing } from './content/typing';
import type { Problem } from './shared/client';
import { ext } from './shared/ext';
import { changeProblem, type Key, t } from './shared/i18n';
import type {
  FillReply,
  LoginsReply,
  PendingSaveReply,
  RemoveReply,
  SaveReply,
  SignInCheckReply,
  ToBackground,
} from './shared/messages';

const MARK = '__sshkmAutofill';
/** A fill that takes longer than this is waiting for the user in the app. */
const CONFIRM_NOTICE_AFTER = 400;
/** How long the menu says why nothing was filled. */
const NOTICE_FOR = 4000;
/**
 * How soon after the user's own click on a field, or Tab key press, focus
 * coming to it opens the menu; and how soon after their own key press or
 * click a sent form counts as sent by them. Either follows within the same
 * moment, as the browser handles the press.
 */
const USER_WITHIN = 1000;
/**
 * When to look whether the sign-in form came back after a sign-in was sent:
 * after the page loaded, and after the form was sent on a page that stays.
 * Past the last, the background no longer asks (it allows 20 seconds).
 */
const SIGN_IN_LOOKS_ON_LOAD = [700, 2500, 6000];
const SIGN_IN_LOOKS_AFTER_SEND = [1500, 4000, 9000];

/** What the menu says when the app filled nothing. */
const NOT_FILLED: Partial<Record<Problem, Key>> = {
  denied: 'fillDenied',
  expired: 'fillExpired',
  busy: 'fillBusy',
  tooMany: 'fillTooMany',
};

function send<T>(message: ToBackground): Promise<T | null> {
  return (ext.runtime.sendMessage(message) as Promise<T | null>).catch(() => null);
}

function start(): void {
  let active: { input: HTMLInputElement; fields: LoginFields } | null = null;
  /** Bumped when the user types: a menu asked for before then stays closed. */
  let keystrokes = 0;
  let lastCapture = { at: 0, key: '' };
  /** The username of a two-step login's first step last passed on. */
  let lastUsername = '';
  const typing = new Typing();
  /** When the user last pressed a key or a pointer button, outside the menu and the banner. */
  let pressedAt = Number.NEGATIVE_INFINITY;
  /** The field the user last pressed a pointer button on, before it has focus. */
  let pointed: { input: HTMLInputElement; at: number } | null = null;
  /** When the user last pressed Tab, outside the menu and the banner. */
  let tabbedAt = Number.NEGATIVE_INFINITY;
  /** The password field the menu last filled, until the user sends it. */
  let filledPassword: HTMLInputElement | null = null;
  /** The login the "couldn't sign in?" banner names, and the password field it is about. */
  let failed: { entryId: string; field: HTMLInputElement } | null = null;

  /**
   * Whether focus came to `target` by the user's own click on it, or Tab key
   * press. Each press counts for the one focus change that follows it.
   */
  function focusedByUser(target: EventTarget | null): boolean {
    const now = performance.now();
    const clicked = pointed !== null && pointed.input === target && now - pointed.at < USER_WITHIN;
    const tabbed = now - tabbedAt < USER_WITHIN;
    pointed = null;
    tabbedAt = Number.NEGATIVE_INFINITY;
    return clicked || tabbed;
  }

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
    onSave: async (offer: SaveOffer, username?: string) => {
      const reply = await send<SaveReply>({ kind: 'save', id: offer.id, username });
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

  const signIn = new SignInBanner({
    onUpdate: () => {
      if (failed?.field.isConnected) failed.field.focus();
    },
    onRemove: async () => {
      if (!failed) return { ok: false, message: t('changeFailed') };
      const reply = await send<RemoveReply>({ kind: 'removeLogin', entryId: failed.entryId });
      if (reply?.ok) return { ok: true, message: t('movedToBin') };
      return { ok: false, message: t(changeProblem(reply?.problem)) };
    },
    onDismiss: () => undefined,
  });

  /**
   * Shows the logins for `input`'s form. Unless the user asked with Down
   * Arrow (`asked`), not over a password already there: the user, the page
   * or the browser filled it.
   */
  async function offer(input: HTMLInputElement, asked = false): Promise<void> {
    const fields = loginFieldsFor(input);
    if (!fields || (!asked && holdsValue(fields.password))) {
      menu.hide();
      return;
    }
    active = { input, fields };
    const typedBefore = keystrokes;
    const reply = await send<LoginsReply>({ kind: 'logins' });
    if (document.activeElement !== input || active?.input !== input || keystrokes !== typedBefore)
      return;
    // A field the page focused without scrolling to it is out of sight.
    if (!isVisible(input) || !onScreen(input)) {
      menu.hide();
      return;
    }
    if (reply?.state === 'ready' && reply.logins.length > 0)
      menu.showLogins(input, forUsername(reply.logins, fields.username?.value ?? ''));
    else if (reply?.state === 'locked' && fields.password) menu.showLocked(input);
    else menu.hide();
  }

  async function pick(entryId: string): Promise<void> {
    const current = active;
    if (!current) return;
    // The app asks the user before a login first fills a page: say where.
    const slow = setTimeout(
      () => menu.showNotice(current.input, t('fillConfirm')),
      CONFIRM_NOTICE_AFTER,
    );
    const reply = await send<FillReply>({ kind: 'fill', entryId });
    clearTimeout(slow);
    if (!reply?.ok) {
      const why = reply ? NOT_FILLED[reply.problem] : undefined;
      if (reply?.problem === 'locked') menu.showLocked(current.input);
      else if (why) showNotice(current.input, t(why));
      else menu.hide();
      return;
    }
    const { username, password } = current.fields;
    if (username && reply.username) fill(username, reply.username);
    if (password) {
      fill(password, reply.password);
      typing.filled(password);
      filledPassword = password;
      void send({ kind: 'filled', entryId });
    }
    menu.hide();
    (password ?? username)?.focus();
  }

  let notices = 0;

  /** Says why nothing was filled, for a few seconds. */
  function showNotice(input: HTMLInputElement, text: string): void {
    menu.showNotice(input, text);
    const notice = ++notices;
    setTimeout(() => {
      if (notice === notices && menu.showsNotice) menu.hide();
    }, NOTICE_FOR);
  }

  /**
   * Notes that the user sent `scope` with the password the menu filled, as
   * it was filled: if the sign-in form comes back, it may be out of date.
   */
  function noteSent(scope: ParentNode): void {
    const password = filledPassword;
    if (!password?.isConnected || !scope.contains(password)) return;
    if (!password.value || typing.byUser(password)) return;
    filledPassword = null;
    void send({ kind: 'signInSent' }).then(() => lookForFailedSignIn(SIGN_IN_LOOKS_AFTER_SEND));
  }

  /**
   * Looks, at each of `delays`, whether a sign-in sent moments ago with a
   * filled login came back as an empty sign-in form; says so once if it did.
   * Only in the top frame, and not over the save banner.
   */
  function lookForFailedSignIn(delays: number[]): void {
    if (window !== window.top) return;
    let done = false;
    for (const delay of delays) {
      setTimeout(async () => {
        if (done || signIn.shown || banner.shown) return;
        const login = await send<SignInCheckReply>({ kind: 'signInCheck' });
        if (!login) {
          done = true;
          return;
        }
        if (done || signIn.shown || banner.shown) return;
        const field = signInFormAgain(document, login.username);
        if (!field) return;
        done = true;
        failed = { entryId: login.entryId, field };
        signIn.show(login);
        void send({ kind: 'signInWarned', entryId: login.entryId });
      }, delay);
    }
  }

  function capture(scope: ParentNode): void {
    noteSent(scope);
    const typed = typedIn(scope, (input) => typing.byUser(input));
    if (!typed) return;
    // A click on the button and the submit event that follows are one login.
    const key = `${typed.username}\n${typed.password.length}`;
    if (key === lastCapture.key && Date.now() - lastCapture.at < 2000) return;
    lastCapture = { at: Date.now(), key };
    void send({ kind: 'capture', ...typed });
  }

  /** Passes on the username of a two-step login's first step, sent by the user. */
  function captureUsername(username: string): void {
    if (!username || username === lastUsername) return;
    lastUsername = username;
    void send({ kind: 'username', username });
  }

  async function offerSave(): Promise<void> {
    if (window !== window.top) return;
    const pending = await send<PendingSaveReply>({ kind: 'pendingSave' });
    if (pending) {
      signIn.hide();
      banner.show(pending);
    }
  }

  document.addEventListener(
    'focusin',
    (event) => {
      if (!event.isTrusted) return;
      const target = event.target;
      if (menu.contains(target) || banner.contains(target) || signIn.contains(target)) return;
      // A page's own `focus()` is trusted too: it opens nothing.
      if (focusedByUser(target) && target instanceof HTMLInputElement) void offer(target);
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
      if (!banner.contains(target) && !signIn.contains(target)) pressedAt = performance.now();
      if (target instanceof HTMLInputElement) {
        // A click into the field that already has focus opens the menu again.
        if (target === document.activeElement) {
          if (!menu.shown) void offer(target);
          return;
        }
        // Focus comes next, as the browser handles the press.
        pointed = { input: target, at: performance.now() };
      }
      menu.hide();
    },
    true,
  );

  document.addEventListener(
    'keydown',
    (event) => {
      const target = event.target;
      if (!event.isTrusted) return;
      typing.observe(event);
      if (menu.contains(target) || banner.contains(target) || signIn.contains(target)) return;
      pressedAt = performance.now();
      if (event.key === 'Tab') tabbedAt = pressedAt;
      if (!(target instanceof HTMLInputElement)) return;
      if (menu.shown && target === active?.input) {
        if (event.key === 'ArrowDown') {
          event.preventDefault();
          menu.focusFirst();
        } else if (event.key === 'Escape') {
          menu.hide();
        }
      } else if (
        event.key === 'ArrowDown' &&
        !event.shiftKey &&
        !event.ctrlKey &&
        !event.metaKey &&
        target === document.activeElement
      ) {
        // The keyboard's way to the menu of a field the page focused, or of
        // a login already filled in.
        void offer(target, true);
      }
      if (event.key === 'Enter') {
        if (isPassword(target)) capture(scopeOf(target));
        else captureUsername(usernameStep(target));
      }
    },
    true,
  );

  // What the user puts into fields, for `typing`.
  for (const type of ['paste', 'drop', 'compositionstart', 'compositionend']) {
    document.addEventListener(
      type,
      (event) => {
        if (event.isTrusted) typing.observe(event);
      },
      true,
    );
  }

  /** The last field outside a form the user typed into; its "Next" button may be beside it. */
  let typedUsername: HTMLInputElement | null = null;

  document.addEventListener(
    'input',
    (event) => {
      if (!event.isTrusted) return;
      typing.observe(event);
      keystrokes += 1;
      const target = event.target;
      if (target instanceof HTMLInputElement && !target.form && !isPassword(target))
        typedUsername = target;
      if (event.target === active?.input) menu.hide();
    },
    true,
  );

  document.addEventListener(
    'submit',
    (event) => {
      // `requestSubmit()` sends a trusted `submit` too: count one only right
      // after the user's own key press or click.
      if (!event.isTrusted || !(event.target instanceof HTMLFormElement)) return;
      if (performance.now() - pressedAt < USER_WITHIN) {
        capture(event.target);
        captureUsername(usernameStepIn(event.target));
      }
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
      else if (scope) captureUsername(usernameStepIn(scope));
      else if (typedUsername?.isConnected && near(typedUsername, button))
        captureUsername(usernameStep(typedUsername));
    },
    true,
  );

  ext.runtime.onMessage.addListener((message, sender) => {
    if (sender.id !== ext.runtime.id) return undefined;
    if ((message as { kind?: string } | null)?.kind === 'offerSave') void offerSave();
    return undefined;
  });

  void offerSave();
  lookForFailedSignIn(SIGN_IN_LOOKS_ON_LOAD);
}

/** Whether `button` is close to `field`: within the few boxes around it. */
function near(field: HTMLInputElement, button: Element): boolean {
  let node: HTMLElement | null = field.parentElement;
  for (let depth = 0; node && depth < 4; depth += 1) {
    if (node.contains(button)) return true;
    node = node.parentElement;
  }
  return false;
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
