// Finding the username and password fields of a login form, filling them,
// and reading what the user typed when the form is sent.
//
// Heuristics, kept simple and predictable:
// - a login form has a visible password field that isn't for a new password;
// - its username is the field marked `autocomplete="username"` or `email`,
//   else the last visible text-like field before the password;
// - a form with a username but no password (the first step of a two-step
//   login) gets the username alone, if the field looks like one;
// - a sent form whose username isn't shown (the second step of a two-step
//   login) may still name it in a hidden field marked as the username;
// - a password-change form has the current password, then the new one and
//   often a copy to confirm it: told by `autocomplete="current-password"` /
//   `"new-password"`, or by three password fields whose last two match. Its
//   username counts only from a field marked as one: such forms sit among
//   other settings, and the nearest text field may be anything.

const TEXT_TYPES = new Set(['text', 'email', 'tel', '']);
const USERNAME_HINT = /user|login|e-?mail|account|identifier|phone/i;

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

export interface Typed {
  username: string;
  password: string;
  /** Sent from a password-change form: `password` is the new one. */
  change?: boolean;
}

/** Smaller than this either way, what shows of a field isn't meant for people. */
const MIN_SIZE = 8;
/** Fainter than this, a field is as good as invisible. */
const MIN_OPACITY = 0.1;
/** The `overflow` values that cut off what sticks out. */
const CLIPPING = new Set(['hidden', 'clip', 'scroll', 'auto']);

/**
 * On screen and big enough to be meant for people: not hidden, not nearly
 * transparent, and not cut down to a sliver by the boxes around it. A page
 * that focuses a field nobody can see gets no menu under it.
 */
export function isVisible(input: HTMLElement): boolean {
  if (input.hidden) return false;
  if (typeof input.checkVisibility === 'function') {
    if (!input.checkVisibility({ opacityProperty: true, visibilityProperty: true })) return false;
    const shown = shownSize(input);
    if (shown.width < MIN_SIZE || shown.height < MIN_SIZE) return false;
  } else {
    // jsdom: no layout to ask.
    const style = getComputedStyle(input);
    if (style.display === 'none' || style.visibility === 'hidden') return false;
  }
  return opacityOf(input) >= MIN_OPACITY;
}

/** An element's opacity times its ancestors'. */
function opacityOf(element: Element): number {
  let opacity = 1;
  for (let node: Element | null = element; node; node = node.parentElement) {
    const own = Number.parseFloat(getComputedStyle(node).opacity);
    if (!Number.isNaN(own)) opacity *= own;
  }
  return opacity;
}

/**
 * How much of an element's box shows: what the boxes it is laid out in let
 * through where they clip their overflow, and nothing left of or above the
 * page's start, where no scrolling reaches. The page's own `html` and `body`
 * are left out: their overflow is the window's.
 */
function shownSize(element: HTMLElement): { width: number; height: number } {
  const rect = element.getBoundingClientRect();
  let left = Math.max(rect.left, -window.scrollX);
  let top = Math.max(rect.top, -window.scrollY);
  let right = rect.right;
  let bottom = rect.bottom;
  const { body, documentElement } = element.ownerDocument;
  // Only the boxes it is positioned in can clip it: an absolutely positioned
  // element escapes the static ones around it, a fixed one all of them.
  let position = getComputedStyle(element).position;
  for (let node = element.parentElement; node; node = node.parentElement) {
    if (node === body || node === documentElement || position === 'fixed') break;
    const style = getComputedStyle(node);
    if (position === 'absolute' && style.position === 'static') continue;
    const box = node.getBoundingClientRect();
    if (CLIPPING.has(style.overflowX)) {
      left = Math.max(left, box.left);
      right = Math.min(right, box.right);
    }
    if (CLIPPING.has(style.overflowY)) {
      top = Math.max(top, box.top);
      bottom = Math.min(bottom, box.bottom);
    }
    position = style.position;
  }
  return { width: Math.max(0, right - left), height: Math.max(0, bottom - top) };
}

/** Whether at least a few pixels of `input` are inside the window. */
export function onScreen(input: HTMLElement): boolean {
  const rect = input.getBoundingClientRect();
  const width = Math.min(rect.right, window.innerWidth) - Math.max(rect.left, 0);
  const height = Math.min(rect.bottom, window.innerHeight) - Math.max(rect.top, 0);
  return width >= MIN_SIZE && height >= MIN_SIZE;
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

/** Whether the browser's own autofill filled `input`: its value isn't readable until the user acts. */
export function autofilled(input: HTMLInputElement): boolean {
  for (const selector of [':autofill', ':-webkit-autofill']) {
    try {
      return input.matches(selector);
    } catch {
      // Not known here (jsdom): try the next name.
    }
  }
  return false;
}

/** Whether `field` already holds something: put in by the user, the page or the browser. */
export function holdsValue(field: HTMLInputElement | null): boolean {
  return field !== null && (field.value !== '' || autofilled(field));
}

function isNewPassword(input: HTMLInputElement): boolean {
  return autocomplete(input).includes('new-password');
}

function isCurrentPassword(input: HTMLInputElement): boolean {
  return autocomplete(input).includes('current-password');
}

/** The fields of a password-change form, in the order they show. */
export interface ChangeFields {
  current: HTMLInputElement;
  next: HTMLInputElement;
  /** The new password again, if the form asks for it. */
  confirm: HTMLInputElement | null;
}

/**
 * The current, new and confirming fields among a form's filled password
 * fields `passwords` (in page order), if it changes a password: a current
 * password before a new one, by their `autocomplete`; or three fields,
 * the last two for the new password (they may differ: a typo, which the
 * form refuses).
 */
export function changeFields(passwords: HTMLInputElement[]): ChangeFields | null {
  const next = passwords.find(isNewPassword);
  if (next) {
    const current = passwords.find((field) => !isNewPassword(field) && before(field, next));
    if (!current) return null;
    const confirm = passwords.find((field) => field !== current && before(next, field)) ?? null;
    return { current, next, confirm };
  }
  if (passwords.length === 3 && !passwords.some(isCurrentPassword)) {
    const [current, second, third] = passwords as [
      HTMLInputElement,
      HTMLInputElement,
      HTMLInputElement,
    ];
    return { current, next: second, confirm: third };
  }
  if (passwords.length === 3) {
    const current = passwords.find(isCurrentPassword);
    const rest = passwords.filter((field) => field !== current);
    if (current && rest.length === 2 && rest.every((field) => before(current, field))) {
      const [second, third] = rest as [HTMLInputElement, HTMLInputElement];
      return { current, next: second, confirm: third };
    }
  }
  return null;
}

/** A username the form marks as one, shown or hidden. */
function markedUsername(scope: ParentNode): string {
  for (const input of scope.querySelectorAll('input')) {
    if (NOT_USERNAME.has(input.type)) continue;
    const hints = autocomplete(input);
    const marked = hints.includes('username') || hints.includes('email') || input.type === 'email';
    if (!marked) continue;
    const value = input.value.trim();
    if (value) return value;
  }
  return '';
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

/** Input types that never hold a username. */
const NOT_USERNAME = new Set([
  'password',
  'checkbox',
  'radio',
  'submit',
  'button',
  'file',
  'image',
]);

/**
 * A username the page keeps out of sight next to a password: the second
 * step of a two-step login often repeats it in a hidden field marked as the
 * username, for password managers.
 */
function hiddenUsername(scope: ParentNode): string {
  for (const input of scope.querySelectorAll('input')) {
    if (NOT_USERNAME.has(input.type)) continue;
    const hints = autocomplete(input);
    const marked = hints.includes('username') || hints.includes('email') || input.type === 'email';
    const value = input.value.trim();
    if (marked && value) return value;
  }
  return '';
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
 * sent. Only password fields that `byUser` says hold what the user put in
 * count (see `Typing`), not ones a page script filled. A new password wins
 * over the current one (a sign-up or a password change).
 */
export function typedIn(
  scope: ParentNode,
  byUser: (input: HTMLInputElement) => boolean,
): Typed | null {
  const filled = [...scope.querySelectorAll('input')].filter(
    (input) => isPassword(input) && input.value !== '' && isVisible(input),
  );
  const change = changeFields(filled);
  // The new password, typed by the user and confirmed as typed; the current
  // one may have been filled from the vault. One the page set goes the
  // usual way below, without it.
  if (change && byUser(change.next)) {
    if (change.confirm && change.confirm.value !== change.next.value) return null;
    return { username: markedUsername(scope), password: change.next.value, change: true };
  }
  const passwords = filled.filter(byUser);
  if (passwords.length === 0) return null;
  const password = passwords.filter(isNewPassword).at(-1) ?? passwords[0];
  if (!password) return null;
  const shown = usernameFor(scope, passwords[0] ?? password)?.value.trim() ?? '';
  return { username: shown || hiddenUsername(scope), password: password.value };
}

/**
 * The username sent with the first step of a two-step login: `field`'s
 * value, if it is the only login field of its form. Empty otherwise.
 */
export function usernameStep(field: HTMLInputElement): string {
  const fields = loginFieldsFor(field);
  if (!fields || fields.password || fields.username !== field) return '';
  return field.value.trim();
}

/** The username-only login field in `scope` that holds something, if there is one. */
export function usernameStepIn(scope: ParentNode): string {
  for (const input of inputs(scope)) {
    const username = usernameStep(input);
    if (username) return username;
  }
  return '';
}

/**
 * The password field of a sign-in form showing again, empty, for `username`:
 * what a site shows when a sign-in failed. Its username field, if any, must
 * be empty or hold `username` (without case or outer spaces). `null` if
 * there is none.
 */
export function signInFormAgain(doc: Document, username: string): HTMLInputElement | null {
  const wanted = username.trim().toLowerCase();
  for (const input of doc.querySelectorAll('input')) {
    if (!isPassword(input) || !onScreen(input)) continue;
    const fields = loginFieldsFor(input);
    if (!fields?.password || holdsValue(fields.password)) continue;
    const shown = fields.username?.value.trim().toLowerCase() ?? '';
    if (shown === '' || shown === wanted) return fields.password;
  }
  return null;
}
