import { afterEach, describe, expect, it, vi } from 'vitest';
import './content';

// The browser, as far as the content script uses it; set up before it loads.
// jsdom marks the events it makes itself, as for `focus()` and
// `requestSubmit()`, as trusted, and those a test dispatches as not.
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

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

function loginForm(): { form: HTMLFormElement; user: HTMLInputElement; pass: HTMLInputElement } {
  document.body.innerHTML = `<form>
    <input id="user" type="text" name="login" value="alice">
    <input id="pass" type="password" value="hunter2">
    <button>Sign in</button>
  </form>`;
  const form = document.querySelector('form') as HTMLFormElement;
  const user = document.querySelector('#user') as HTMLInputElement;
  const pass = document.querySelector('#pass') as HTMLInputElement;
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
    await settle();
    expect(kinds()).not.toContain('logins');

    pass.focus();
    await settle();
    expect(kinds()).toContain('logins');
  });

  it('move no focus into the menu', async () => {
    const { pass } = loginForm();
    pass.focus();
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
    const { form } = loginForm();
    form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
    form
      .querySelector('#pass')
      ?.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    await settle();
    expect(kinds()).not.toContain('capture');

    form.addEventListener('submit', (event) => event.preventDefault());
    form.requestSubmit();
    await settle();
    expect(world.sent).toContainEqual({ kind: 'capture', username: 'alice', password: 'hunter2' });
  });
});
