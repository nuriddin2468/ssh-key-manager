import { afterEach, describe, expect, it, vi } from 'vitest';
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

describe('typed logins', () => {
  it('reads the username and password of a sent form', () => {
    page(`<form>
      <input id="user" type="text" value=" alice ">
      <input id="pass" type="password" value="hunter2">
    </form>`);
    expect(typedIn(input('#user').form as HTMLFormElement)).toEqual({
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
    expect(typedIn(input('#user').form as HTMLFormElement)).toEqual({
      username: 'bob@example.com',
      password: 'new1',
    });
  });

  it('ignores forms without a typed password', () => {
    page(`<form><input id="user" value="x"><input type="password"></form>`);
    expect(typedIn(input('#user').form as HTMLFormElement)).toBeNull();
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
