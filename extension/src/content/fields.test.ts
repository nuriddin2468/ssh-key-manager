import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { changeFields, fill, loginFieldsFor, signInFormAgain, typedIn } from './fields';

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
      change: true,
    });
  });

  it('takes the new password of an unmarked change form whose last two match', () => {
    page(`<form id="f">
      <input name="display" value="Bob B.">
      <input type="password" value="old">
      <input type="password" value="new1">
      <input type="password" value="new1">
    </form>`);
    const form = document.getElementById('f') as HTMLFormElement;
    // The display name isn't marked as a username: none is taken.
    expect(typedIn(form, all)).toEqual({ username: '', password: 'new1', change: true });
  });

  it('offers nothing when the new password and its copy differ', () => {
    page(`<form id="f">
      <input type="password" autocomplete="current-password" value="old">
      <input type="password" autocomplete="new-password" value="new1">
      <input type="password" autocomplete="new-password" value="new2">
    </form>`);
    expect(typedIn(document.getElementById('f') as HTMLFormElement, all)).toBeNull();
    page(`<form id="f">
      <input type="password" value="old">
      <input type="password" value="new1">
      <input type="password" value="new2">
    </form>`);
    expect(typedIn(document.getElementById('f') as HTMLFormElement, all)).toBeNull();
  });

  it('takes the new password when the current one was filled from the vault', () => {
    page(`<form id="f">
      <input type="hidden" autocomplete="username" value="carol">
      <input id="old" type="password" autocomplete="current-password" value="saved">
      <input id="new" type="password" autocomplete="new-password" value="fresh">
    </form>`);
    const form = document.getElementById('f') as HTMLFormElement;
    expect(typedIn(form, (field) => field.id === 'new')).toEqual({
      username: 'carol',
      password: 'fresh',
      change: true,
    });
  });

  it('tells change forms from sign-ups and sign-ins', () => {
    page(`<form>
      <input id="a" type="password" value="x">
      <input id="b" type="password" autocomplete="new-password" value="y">
      <input id="c" type="password" autocomplete="new-password" value="y">
      <input id="d" type="password" value="x">
    </form>`);
    const [a, b, c, d] = ['#a', '#b', '#c', '#d'].map(input) as HTMLInputElement[];
    expect(
      changeFields([a as HTMLInputElement, b as HTMLInputElement, c as HTMLInputElement]),
    ).toEqual({ current: a, next: b, confirm: c });
    // A sign-up: a new password and its copy, nothing current.
    expect(changeFields([b as HTMLInputElement, c as HTMLInputElement])).toBeNull();
    // A sign-in, or a sign-up without hints.
    expect(changeFields([a as HTMLInputElement])).toBeNull();
    expect(changeFields([a as HTMLInputElement, d as HTMLInputElement])).toBeNull();
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

describe('a sign-in form that came back', () => {
  /** jsdom has no layout: give every field a place in the window. */
  const placed = () => {
    for (const input of document.querySelectorAll('input')) {
      const rect = { left: 10, top: 10, width: 200, height: 30, right: 210, bottom: 40 };
      input.getBoundingClientRect = () => ({ ...rect, x: 10, y: 10, toJSON: () => rect });
    }
  };

  it('is found with an empty password, for the same or no username', () => {
    page(`<form><input id="user" value="Alice"><input id="pass" type="password"></form>`);
    placed();
    expect(signInFormAgain(document, ' alice ')).toBe(input('#pass'));
    input('#user').value = '';
    expect(signInFormAgain(document, 'alice')).toBe(input('#pass'));
  });

  it('is not one for another username, or with a password in it', () => {
    page(`<form><input id="user" value="bob"><input id="pass" type="password"></form>`);
    placed();
    expect(signInFormAgain(document, 'alice')).toBeNull();
    input('#user').value = 'alice';
    input('#pass').value = 'kept';
    expect(signInFormAgain(document, 'alice')).toBeNull();
  });

  it('is not a page without a sign-in form', () => {
    page(`<form><input type="password" autocomplete="new-password"></form><p>Welcome</p>`);
    placed();
    expect(signInFormAgain(document, 'alice')).toBeNull();
  });
});
