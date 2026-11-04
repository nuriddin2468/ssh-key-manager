import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fill, loginFieldsFor, typedIn } from './fields';

function page(html: string): void {
  document.body.innerHTML = html;
}

function input(selector: string): HTMLInputElement {
  const element = document.querySelector<HTMLInputElement>(selector);
  if (!element) throw new Error(`no ${selector}`);
  return element;
}

afterEach(() => {
  document.body.innerHTML = '';
});

describe('login fields', () => {
  it('pairs a password with the username before it', () => {
    page(`<form>
      <input id="search" type="search">
      <input id="user" type="text" name="login">
      <input id="pass" type="password">
      <button>Sign in</button>
    </form>`);
    const fields = { username: input('#user'), password: input('#pass') };
    expect(loginFieldsFor(input('#pass'))).toEqual(fields);
    expect(loginFieldsFor(input('#user'))).toEqual(fields);
    expect(loginFieldsFor(input('#search'))).toBeNull();
  });

  it('prefers fields marked as the username', () => {
    page(`<form>
      <input id="email" type="email" autocomplete="username">
      <input id="other" type="text" name="nickname">
      <input id="pass" type="password" autocomplete="current-password">
    </form>`);
    expect(loginFieldsFor(input('#pass'))?.username).toBe(input('#email'));
    expect(loginFieldsFor(input('#other'))).toBeNull();
  });

  it('works without a form element', () => {
    page(`<div><div><input id="user" type="email"></div><input id="pass" type="password"></div>`);
    expect(loginFieldsFor(input('#user'))?.password).toBe(input('#pass'));
  });

  it('offers the username alone on the first step of a two-step login', () => {
    page(`<form><input id="id" type="email" autocomplete="username"><button>Next</button></form>`);
    expect(loginFieldsFor(input('#id'))).toEqual({ username: input('#id'), password: null });
    page(`<form><input id="q" type="text" name="query"></form>`);
    expect(loginFieldsFor(input('#q'))).toBeNull();
  });

  it('leaves new-password, hidden, disabled and one-time-code fields alone', () => {
    page(`<form>
      <input id="user" type="text">
      <input id="new" type="password" autocomplete="new-password">
      <input id="hidden" type="password" style="display:none">
      <input id="off" type="password" disabled>
      <input id="otp" type="text" autocomplete="one-time-code">
    </form>`);
    for (const id of ['#new', '#hidden', '#off', '#otp']) {
      expect(loginFieldsFor(input(id)), id).toBeNull();
    }
  });
});

describe('visibility', () => {
  // jsdom has no layout: give each element a box, as a browser would.
  function box(selector: string, left: number, top: number, width: number, height: number) {
    const element = document.querySelector<HTMLElement>(selector);
    if (!element) throw new Error(`no ${selector}`);
    const rect = { left, top, width, height, right: left + width, bottom: top + height };
    element.getBoundingClientRect = () => ({ ...rect, x: left, y: top, toJSON: () => rect });
  }

  beforeEach(() => {
    Object.defineProperty(Element.prototype, 'checkVisibility', {
      configurable: true,
      value: () => true,
    });
  });
  afterEach(() => {
    delete (Element.prototype as { checkVisibility?: unknown }).checkVisibility;
  });

  function login(passwordStyle = '', wrapperStyle = '') {
    page(`<form><div id="wrap" style="${wrapperStyle}">
      <input id="pass" type="password" style="${passwordStyle}">
    </div></form>`);
    box('#wrap', 0, 0, 300, 40);
  }

  it('offers fields big enough to see', () => {
    login();
    box('#pass', 10, 10, 200, 30);
    expect(loginFieldsFor(input('#pass'))).not.toBeNull();
    box('#pass', 10, 10, 8, 8);
    expect(loginFieldsFor(input('#pass'))).not.toBeNull();
  });

  it('leaves tiny fields alone', () => {
    login();
    box('#pass', 10, 10, 6, 6);
    expect(loginFieldsFor(input('#pass'))).toBeNull();
    box('#pass', 10, 10, 200, 4);
    expect(loginFieldsFor(input('#pass'))).toBeNull();
  });

  it('leaves nearly transparent fields alone, counting their ancestors', () => {
    login('opacity: 0.05');
    box('#pass', 10, 10, 200, 30);
    expect(loginFieldsFor(input('#pass'))).toBeNull();
    login('opacity: 0.3', 'opacity: 0.3');
    box('#pass', 10, 10, 200, 30);
    expect(loginFieldsFor(input('#pass'))).toBeNull();
    login('opacity: 0.5');
    box('#pass', 10, 10, 200, 30);
    expect(loginFieldsFor(input('#pass'))).not.toBeNull();
  });

  it('leaves fields clipped to a sliver alone', () => {
    login('', 'overflow-x: hidden; overflow-y: hidden');
    box('#wrap', 0, 0, 300, 2);
    box('#pass', 10, 10, 200, 30);
    expect(loginFieldsFor(input('#pass'))).toBeNull();
    // An absolutely placed field escapes a static box around it.
    login('position: absolute', 'overflow-x: hidden; overflow-y: hidden; position: static');
    box('#wrap', 0, 0, 300, 2);
    box('#pass', 10, 10, 200, 30);
    expect(loginFieldsFor(input('#pass'))).not.toBeNull();
  });

  it('leaves fields off the page alone', () => {
    login();
    box('#pass', -9999, 10, 200, 30);
    expect(loginFieldsFor(input('#pass'))).toBeNull();
  });
});

describe('typed logins', () => {
  const all = () => true;

  it('reads the username and password of a sent form', () => {
    page(`<form>
      <input id="user" type="text" value=" alice ">
      <input id="pass" type="password" value="hunter2">
    </form>`);
    expect(typedIn(input('#user').form as HTMLFormElement, all)).toEqual({
      username: 'alice',
      password: 'hunter2',
    });
  });

  it('takes the new password of a sign-up or password change', () => {
    page(`<form>
      <input id="user" type="email" value="bob@example.com">
      <input type="password" autocomplete="current-password" value="old">
      <input type="password" autocomplete="new-password" value="new1">
      <input type="password" autocomplete="new-password" value="new1">
    </form>`);
    expect(typedIn(input('#user').form as HTMLFormElement, all)).toEqual({
      username: 'bob@example.com',
      password: 'new1',
    });
  });

  it('ignores forms without a typed password', () => {
    page(`<form><input id="user" value="x"><input type="password"></form>`);
    expect(typedIn(input('#user').form as HTMLFormElement, all)).toBeNull();
  });

  it('reads only passwords the user put in', () => {
    page(`<form>
      <input id="user" type="email" value="bob@example.com">
      <input id="typed" type="password" autocomplete="current-password" value="hunter2">
      <input id="set" type="password" autocomplete="new-password" value="guess">
    </form>`);
    const form = input('#user').form as HTMLFormElement;
    expect(typedIn(form, all)?.password).toBe('guess');
    expect(typedIn(form, (field) => field.id === 'typed')).toEqual({
      username: 'bob@example.com',
      password: 'hunter2',
    });
    expect(typedIn(form, () => false)).toBeNull();
  });
});

describe('filling', () => {
  it('sets the value and tells the page', () => {
    page(`<input id="user">`);
    const field = input('#user');
    const seen = vi.fn();
    field.addEventListener('input', () => seen(field.value));
    fill(field, 'alice');
    expect(field.value).toBe('alice');
    expect(seen).toHaveBeenCalledWith('alice');
  });
});
