import { afterEach, describe, expect, it, vi } from 'vitest';
import { click, fireTrusted, press, type } from './test/user';
import './content';

// The browser, as far as the content script uses it; set up before it loads.
// jsdom marks the events it makes itself, as for `focus()` and
// `requestSubmit()`, as trusted, and those a test dispatches as not; the
// user's own come from test/user.ts.
const world = vi.hoisted(() => {
  const state = { sent: [] as { kind: string; [key: string]: unknown }[] };
  const login = { id: 'e1', title: 'Bank', username: 'alice', exact: true };
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: {
      id: 'ext',
      sendMessage: async (message: { kind: string }) => {
        state.sent.push(message);
        return message.kind === 'logins' ? { state: 'ready', logins: [login] } : null;
      },
      onMessage: { addListener: () => undefined },
    },
  };
  return state;
});

function kinds(): string[] {
  return world.sent.map((message) => message.kind);
}

function captures(): unknown[] {
  return world.sent.filter((message) => message.kind === 'capture');
}

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

/** A sign-in form; `password` is what the page put in the password field. */
function loginForm(
  username = 'alice',
  password = '',
): {
  form: HTMLFormElement;
  user: HTMLInputElement;
  pass: HTMLInputElement;
} {
  document.body.innerHTML = `<form>
    <input id="user" type="text" name="login" value="${username}">
    <input id="pass" type="password" value="${password}">
    <button>Sign in</button>
  </form>`;
  const form = document.querySelector('form') as HTMLFormElement;
  const user = document.querySelector('#user') as HTMLInputElement;
  const pass = document.querySelector('#pass') as HTMLInputElement;
  form.addEventListener('submit', (event) => event.preventDefault());
  return { form, user, pass };
}

afterEach(() => {
  (document.activeElement as HTMLElement | null)?.blur();
  document.body.innerHTML = '';
  world.sent.length = 0;
});

describe('events a page makes up', () => {
  it('open no menu', async () => {
    const { pass } = loginForm();
    pass.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
    pass.dispatchEvent(new PointerEvent('pointerdown', { bubbles: true }));
    pass.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    await settle();
    expect(kinds()).not.toContain('logins');
  });

  it('move no focus into the menu', async () => {
    const { pass } = loginForm();
    click(pass);
    await settle();
    const down = new KeyboardEvent('keydown', {
      key: 'ArrowDown',
      bubbles: true,
      cancelable: true,
    });
    pass.dispatchEvent(down);
    expect(down.defaultPrevented).toBe(false);
    expect(document.activeElement).toBe(pass);
  });

  it('send no typed login', async () => {
    const { form, pass } = loginForm('alice', 'hunter2');
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    pass.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await settle();
    expect(captures()).toEqual([]);
  });
});

describe('the menu', () => {
  it('opens when the user clicks a field', async () => {
    const { pass } = loginForm();
    click(pass);
    await settle();
    expect(kinds()).toEqual(['logins']);
  });

  it('opens when the user moves to a field with Tab', async () => {
    const { user, pass } = loginForm();
    press(user, 'Tab');
    pass.focus();
    await settle();
    expect(kinds()).toEqual(['logins']);
    // That key press moved focus once.
    user.focus();
    await settle();
    expect(kinds()).toEqual(['logins']);
  });

  it('opens on Down Arrow in a field the page focused, and not on that focus', async () => {
    const { pass } = loginForm();
    // A page's `focus()` (or `autofocus`): trusted, but not the user's.
    pass.focus();
    await settle();
    expect(kinds()).not.toContain('logins');
    press(pass, 'ArrowDown');
    await settle();
    expect(kinds()).toEqual(['logins']);
  });

  it('stays closed when the page moves focus after the user clicked elsewhere', async () => {
    const { user, pass } = loginForm();
    fireTrusted(user, new PointerEvent('pointerdown', { bubbles: true, cancelable: true }));
    pass.focus();
    await settle();
    expect(kinds()).not.toContain('logins');
  });
});

describe('typed logins', () => {
  it('are sent when the user typed the password and pressed Enter', async () => {
    const { pass } = loginForm('alice');
    type(pass, 'hunter2');
    press(pass, 'Enter');
    await settle();
    expect(captures()).toEqual([{ kind: 'capture', username: 'alice', password: 'hunter2' }]);
  });

  it('are sent when a click or key press of the user sends the form', async () => {
    const { form, pass } = loginForm('bob');
    type(pass, 'swordfish');
    // The page sends it with script, in the same moment.
    form.requestSubmit();
    await settle();
    expect(captures()).toEqual([{ kind: 'capture', username: 'bob', password: 'swordfish' }]);
  });

  it('are not sent when the page sends the form later by itself', async () => {
    const { form, pass } = loginForm('carol');
    type(pass, 'opensesame');
    const later = performance.now() + 5000;
    vi.spyOn(performance, 'now').mockReturnValue(later);
    form.requestSubmit();
    await settle();
    expect(captures()).toEqual([]);
  });

  it('are not sent with a password the page set or changed', async () => {
    // Set by the page: `requestSubmit()` sends a trusted `submit`, and
    // `execCommand` a trusted `input`.
    const { form, pass } = loginForm('dave', 'guess1');
    press(pass, 'Enter');
    form.requestSubmit();
    pass.value = 'guess2';
    fireTrusted(pass, new InputEvent('input', { inputType: 'insertText', data: 'guess2' }));
    press(pass, 'Enter');
    // Typed by the user, then changed by the page.
    pass.value = '';
    type(pass, 'hunter2');
    pass.value = 'guess3';
    press(pass, 'Enter');
    await settle();
    expect(captures()).toEqual([]);
  });
});
