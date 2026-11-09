// The popup's list of the logins saved for the tab's site, where the user
// changes a login's username or password, or moves it to the vault's
// recycle bin. The site is the tab's origin as the browser reports it
// (`activeTab`), never what the page says; the app checks each change
// against it too, so a login of another site can't be touched from here.
//
// A new password replaces the saved one only if the user typed one: the
// field starts empty. The app keeps the old version in the entry's history,
// and a removed login stays in the recycle bin, where the app restores it;
// the popup asks before it removes one all the same.

import { changeLogin, type LoginOffer, request } from './shared/client';
import { button, h } from './shared/dom';
import { ext } from './shared/ext';
import { changeProblem, loginName, t } from './shared/i18n';
import type { FromPage } from './shared/messages';

/** Longest username the app takes from a browser. */
const MAX_USERNAME = 256;

/** The web origin of the tab the popup was opened on, or `null` for any other page. */
export async function tabOrigin(): Promise<string | null> {
  try {
    const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return null;
    const url = new URL(tab.url);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
    return url.origin;
  } catch {
    return null;
  }
}

let fieldIds = 0;

const SVG = 'http://www.w3.org/2000/svg';
const EYE = [
  'M2.06 12.35a1 1 0 0 1 0-.7 10.75 10.75 0 0 1 19.88 0 1 1 0 0 1 0 .7 10.75 10.75 0 0 1-19.88 0',
  'M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6',
];
const EYE_OFF = [
  'M10.73 5.08A10.43 10.43 0 0 1 12 5c4.4 0 8.3 2.7 9.94 6.65a1 1 0 0 1 0 .7 10.75 10.75 0 0 1-1.44 2.49',
  'M14.08 14.16a3 3 0 0 1-4.24-4.24',
  'M17.48 17.5A10.75 10.75 0 0 1 2.06 12.35a1 1 0 0 1 0-.7 10.75 10.75 0 0 1 4.45-5.14',
  'm2 2 20 20',
];

function icon(paths: string[]): SVGSVGElement {
  const svg = document.createElementNS(SVG, 'svg');
  for (const [name, value] of Object.entries({
    viewBox: '0 0 24 24',
    fill: 'none',
    stroke: 'currentColor',
    'stroke-width': '2',
    'stroke-linecap': 'round',
    'stroke-linejoin': 'round',
    'aria-hidden': 'true',
  })) {
    svg.setAttribute(name, value);
  }
  for (const d of paths) {
    const path = document.createElementNS(SVG, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

/** A labelled text field, with an optional hint under it and a button inside it. */
function field(
  label: string,
  input: HTMLInputElement,
  hint?: string,
  inside?: HTMLElement,
): { box: HTMLElement; input: HTMLInputElement } {
  const id = `field-${++fieldIds}`;
  input.id = id;
  const control = inside ? h('div', { className: 'input-wrap' }, input, inside) : input;
  const children: (Node | null)[] = [h('label', { for: id }, label), control];
  if (hint) {
    const hintId = `${id}-hint`;
    input.setAttribute('aria-describedby', hintId);
    children.push(h('p', { id: hintId, className: 'hint' }, hint));
  }
  return { box: h('div', { className: 'field' }, ...children), input };
}

/**
 * The section listing the logins of `origin`'s site. `onChanged` runs after
 * a change, so the rest of the extension stops offering what it had cached.
 */
export function siteLogins(origin: string): HTMLElement {
  const site = new URL(origin).host;
  const list = h('ul', { className: 'login-list', 'aria-labelledby': 'logins-title' });
  // What happened last, said once and kept until the next change.
  const status = h('p', { className: 'logins-status success', role: 'status' });
  const section = h(
    'section',
    { className: 'setting logins', 'aria-labelledby': 'logins-title' },
    h('h2', { id: 'logins-title', tabindex: '-1' }, t('siteLogins', { site })),
    list,
    status,
  );

  const say = (text: string) => {
    status.textContent = text;
  };

  const changed = () => {
    const message: FromPage = { kind: 'loginsChanged', origin };
    void (ext.runtime.sendMessage(message) as Promise<unknown>).catch(() => undefined);
  };

  /** Loads the list again; then focuses the row of `focusId`, or the heading. */
  const load = async (focusId?: string) => {
    const reply = await request<{ logins: LoginOffer[] }>({ logins: { origin } });
    list.replaceChildren();
    if (!reply.ok) {
      list.append(h('li', { className: 'empty' }, t('siteLoginsFailed')));
      return;
    }
    if (reply.value.logins.length === 0) {
      list.append(h('li', { className: 'empty' }, t('siteLoginsNone')));
    }
    for (const login of reply.value.logins) list.append(row(login));
    if (focusId !== undefined) {
      const edit = list.querySelector<HTMLButtonElement>(`[data-id="${CSS.escape(focusId)}"]`);
      (edit ?? section.querySelector<HTMLElement>('h2'))?.focus();
    }
  };

  /** One login: its title and username, and Edit. */
  const row = (login: LoginOffer): HTMLElement => {
    const item = h('li', { className: 'login' });
    const show = () => {
      const edit = h(
        'button',
        {
          type: 'button',
          className: 'btn ghost small',
          'data-id': login.id,
          'aria-label': t('editLogin', { login: loginName(login) }),
        },
        t('edit'),
      );
      edit.addEventListener('click', () => {
        status.textContent = '';
        editor(login, item, show);
      });
      item.replaceChildren(
        h(
          'div',
          { className: 'login-text' },
          h('span', { className: 'login-title' }, login.title),
          h(
            'span',
            { className: login.username ? 'login-user' : 'login-user none' },
            login.username || t('noUsername'),
          ),
        ),
        edit,
      );
      return edit;
    };
    show();
    return item;
  };

  /** Turns `item` into a form that edits `login`; `back` shows the row again. */
  const editor = (login: LoginOffer, item: HTMLElement, back: () => HTMLButtonElement) => {
    const username = h('input', {
      type: 'text',
      autocomplete: 'off',
      spellcheck: 'false',
      maxlength: String(MAX_USERNAME),
    });
    username.value = login.username;
    const password = h('input', { type: 'password', autocomplete: 'new-password' });
    // One name, "Show password"; whether it shows is the pressed state.
    const reveal = h('button', {
      type: 'button',
      className: 'reveal',
      'aria-pressed': 'false',
      'aria-label': t('showPassword'),
      title: t('showPassword'),
    });
    const setRevealed = (shown: boolean) => {
      password.type = shown ? 'text' : 'password';
      reveal.setAttribute('aria-pressed', String(shown));
      reveal.title = shown ? t('hidePassword') : t('showPassword');
      reveal.replaceChildren(icon(shown ? EYE_OFF : EYE));
    };
    setRevealed(false);
    reveal.addEventListener('click', () => setRevealed(password.type === 'password'));
    const user = field(t('usernameField'), username);
    const pass = field(t('newPassword'), password, t('newPasswordHint'), reveal);
    const problem = h('p', { className: 'problem', role: 'alert' });
    const cancel = button(t('cancel'), () => back().focus());
    const save = h('button', { type: 'submit', className: 'btn primary' }, t('save'));
    const remove = button(t('moveToBin'), () => confirmRemove(), 'danger');
    const form = h(
      'form',
      { className: 'login-edit', 'aria-label': t('editLogin', { login: loginName(login) }) },
      user.box,
      pass.box,
      problem,
      h('div', { className: 'edit-actions' }, h('span', { className: 'spacer' }), cancel, save),
      // Apart from Save, so it isn't hit by mistake.
      h('div', { className: 'remove-row' }, remove),
    );

    const busy = (on: boolean) => {
      for (const control of form.querySelectorAll<HTMLButtonElement | HTMLInputElement>(
        'button, input',
      )) {
        control.disabled = on;
      }
      form.setAttribute('aria-busy', String(on));
    };

    form.addEventListener('submit', (event) => {
      event.preventDefault();
      void (async () => {
        const newName = username.value.trim();
        const edit: { entryId: string; username?: string; password?: string } = {
          entryId: login.id,
        };
        if (newName !== login.username) edit.username = newName;
        if (password.value) edit.password = password.value;
        if (edit.username === undefined && edit.password === undefined) {
          back().focus();
          return;
        }
        busy(true);
        const result = await changeLogin(origin, { edit });
        password.value = '';
        if (!result.ok) {
          busy(false);
          problem.textContent = t(changeProblem(result.problem));
          (result.problem === 'notFound' ? cancel : save).focus();
          return;
        }
        changed();
        say(t('loginChanged'));
        await load(login.id);
      })();
    });
    form.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        back().focus();
      }
    });

    /** Asks before the login goes to the recycle bin. */
    const confirmRemove = () => {
      const question = h(
        'p',
        { id: `remove-${login.id}`, className: 'confirm-text' },
        t('moveToBinConfirm', { login: loginName(login) }),
      );
      const removeProblem = h('p', { className: 'problem', role: 'alert' });
      const keep = button(t('keepLogin'), () => back().focus());
      const confirm = button(t('moveToBin'), () => void removeIt(), 'danger');
      confirm.classList.add('solid');
      const box = h(
        'div',
        {
          className: 'login-edit',
          role: 'alertdialog',
          'aria-modal': 'false',
          'aria-describedby': question.id,
          'aria-label': t('moveToBin'),
        },
        question,
        removeProblem,
        h('div', { className: 'edit-actions' }, h('span', { className: 'spacer' }), keep, confirm),
      );
      box.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          back().focus();
        }
      });
      const removeIt = async () => {
        keep.disabled = true;
        confirm.disabled = true;
        const result = await changeLogin(origin, { remove: { entryId: login.id } });
        if (!result.ok) {
          keep.disabled = false;
          confirm.disabled = false;
          removeProblem.textContent = t(changeProblem(result.problem));
          keep.focus();
          return;
        }
        changed();
        say(t('movedToBin'));
        await load('');
      };
      item.replaceChildren(box);
      // The safe choice has focus: Enter keeps the login.
      keep.focus();
    };

    item.replaceChildren(form);
    username.focus();
  };

  void load();
  return section;
}
