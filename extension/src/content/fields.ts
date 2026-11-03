// Finding the username and password fields of a login form, filling them,
// and reading what the user typed when the form is sent.
//
// Heuristics, kept simple and predictable:
// - a login form has a visible password field that isn't for a new password;
// - its username is the field marked `autocomplete="username"` or `email`,
//   else the last visible text-like field before the password;
// - a form with a username but no password (the first step of a two-step
//   login) gets the username alone, if the field looks like one.

const TEXT_TYPES = new Set(['text', 'email', 'tel', '']);
const USERNAME_HINT = /user|login|e-?mail|account|identifier|phone/i;

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

export interface Typed {
  username: string;
  password: string;
}

/** On screen and big enough to be meant for people. */
export function isVisible(input: HTMLElement): boolean {
  if (input.hidden) return false;
  if (typeof input.checkVisibility === 'function') {
    if (!input.checkVisibility({ opacityProperty: true, visibilityProperty: true })) return false;
    const rect = input.getBoundingClientRect();
    return rect.width >= 4 && rect.height >= 4;
  }
  // jsdom: no layout to ask.
  const style = getComputedStyle(input);
  return style.display !== 'none' && style.visibility !== 'hidden';
}

function usable(input: HTMLInputElement): boolean {
  return !input.disabled && !input.readOnly && isVisible(input);
}

function autocomplete(input: HTMLInputElement): string[] {
  return (input.getAttribute('autocomplete') ?? '').toLowerCase().split(/\s+/);
}

export function isPassword(input: HTMLInputElement): boolean {
  return input.type === 'password';
}

function isNewPassword(input: HTMLInputElement): boolean {
  return autocomplete(input).includes('new-password');
}

function isTextLike(input: HTMLInputElement): boolean {
  return TEXT_TYPES.has(input.type) && !autocomplete(input).includes('one-time-code');
}

function looksLikeUsername(input: HTMLInputElement): boolean {
  const hints = autocomplete(input);
  if (hints.includes('username') || hints.includes('email')) return true;
  if (input.type === 'email') return true;
  if (input.type === 'search' || input.getAttribute('role') === 'combobox') return false;
  return USERNAME_HINT.test(`${input.name} ${input.id}`);
}

/** The form a field belongs to, or the nearest ancestor that holds a password field. */
export function scopeOf(input: HTMLInputElement): ParentNode {
  if (input.form) return input.form;
  let node: HTMLElement | null = input.parentElement;
  for (let depth = 0; node && depth < 6; depth += 1) {
    if (node.querySelector('input[type=password]')) return node;
    node = node.parentElement;
  }
  return input.ownerDocument;
}

function inputs(scope: ParentNode): HTMLInputElement[] {
  return [...scope.querySelectorAll('input')].filter(usable);
}

function before(a: Node, b: Node): boolean {
  return Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
}

/** The username field that goes with `password`. */
export function usernameFor(
  scope: ParentNode,
  password: HTMLInputElement,
): HTMLInputElement | null {
  const candidates = inputs(scope).filter((input) => isTextLike(input) && before(input, password));
  const marked = candidates.filter((input) => {
    const hints = autocomplete(input);
    return hints.includes('username') || hints.includes('email');
  });
  return marked.at(-1) ?? candidates.at(-1) ?? null;
}

/** The login fields that `input` is one of, or `null` if it isn't a login field. */
export function loginFieldsFor(input: HTMLInputElement): LoginFields | null {
  if (!usable(input)) return null;
  const scope = scopeOf(input);
  if (isPassword(input)) {
    if (isNewPassword(input)) return null;
    return { username: usernameFor(scope, input), password: input };
  }
  if (!isTextLike(input)) return null;
  const passwords = inputs(scope).filter((field) => isPassword(field) && !isNewPassword(field));
  const password = passwords.find((field) => before(input, field));
  if (password) {
    return usernameFor(scope, password) === input ? { username: input, password } : null;
  }
  if (passwords.length === 0 && looksLikeUsername(input))
    return { username: input, password: null };
  return null;
}

/** Fills a field the way typing would, so page scripts and frameworks see it. */
export function fill(input: HTMLInputElement, value: string): void {
  // The setter of this content script's own world; the page can't replace it.
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
  if (setter) setter.call(input, value);
  else input.value = value;
  input.dispatchEvent(new Event('input', { bubbles: true, composed: true }));
  input.dispatchEvent(new Event('change', { bubbles: true }));
}

/**
 * What the user typed into the login or sign-up form in `scope`, when it is
 * sent. A new password wins over the current one (a sign-up or a password
 * change).
 */
export function typedIn(scope: ParentNode): Typed | null {
  const passwords = [...scope.querySelectorAll('input')].filter(
    (input) => isPassword(input) && input.value !== '' && isVisible(input),
  );
  if (passwords.length === 0) return null;
  const password = passwords.filter(isNewPassword).at(-1) ?? passwords[0];
  if (!password) return null;
  const username = usernameFor(scope, passwords[0] ?? password)?.value.trim() ?? '';
  return { username, password: password.value };
}
