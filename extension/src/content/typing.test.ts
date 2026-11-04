import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { fireTrusted, press, type } from '../test/user';
import { Typing } from './typing';

const EVENTS = ['keydown', 'paste', 'drop', 'compositionstart', 'compositionend', 'input'];

let typing: Typing;
let field: HTMLInputElement;
const observe = (event: Event) => {
  if (event.isTrusted) typing.observe(event);
};

beforeEach(() => {
  typing = new Typing();
  document.body.innerHTML = '<input id="pass" type="password">';
  field = document.querySelector('#pass') as HTMLInputElement;
  for (const name of EVENTS) document.addEventListener(name, observe, true);
});

afterEach(() => {
  for (const name of EVENTS) document.removeEventListener(name, observe, true);
  document.body.innerHTML = '';
});

/** An `input` event the browser marks as trusted, as `execCommand` gets one. */
function changed(inputType: string, data: string | null): void {
  fireTrusted(field, new InputEvent('input', { inputType, data, bubbles: true }));
}

describe('what the user put in', () => {
  it('counts what they typed, deleted from the end or typed over', () => {
    type(field, 'hunter2');
    expect(typing.byUser(field)).toBe(true);

    press(field, 'Backspace');
    field.value = 'hunter';
    changed('deleteContentBackward', null);
    expect(typing.byUser(field)).toBe(true);

    // All of it selected, then a key.
    press(field, 'x');
    field.value = 'x';
    changed('insertText', 'x');
    expect(typing.byUser(field)).toBe(true);
  });

  it('counts a paste, a drop and a composition', () => {
    fireTrusted(field, new Event('paste', { bubbles: true }));
    field.value = 'correct horse';
    changed('insertFromPaste', 'correct horse');
    expect(typing.byUser(field)).toBe(true);

    fireTrusted(field, new Event('drop', { bubbles: true }));
    field.value = 'correct horse battery';
    changed('insertFromDrop', ' battery');
    expect(typing.byUser(field)).toBe(true);

    // A dead key: what is shown while composing is replaced at the end.
    press(field, 'Dead');
    fireTrusted(field, new CompositionEvent('compositionstart', { bubbles: true }));
    field.value = 'correct horse battery´';
    fireTrusted(
      field,
      new InputEvent('input', { inputType: 'insertCompositionText', data: '´', isComposing: true }),
    );
    field.value = 'correct horse batteryé';
    fireTrusted(field, new CompositionEvent('compositionend', { data: 'é', bubbles: true }));
    expect(typing.byUser(field)).toBe(true);
  });

  it('counts what the extension filled', () => {
    field.value = 'from the vault';
    typing.filled(field);
    expect(typing.byUser(field)).toBe(true);
  });

  it('counts nothing in an empty field', () => {
    expect(typing.byUser(field)).toBe(false);
    typing.filled(field);
    expect(typing.byUser(field)).toBe(false);
  });
});

describe('what a page script put in', () => {
  it('never counts a value it set', () => {
    field.value = 'guess1';
    expect(typing.byUser(field)).toBe(false);
    type(field, 'hunter2');
    field.value = 'guess2';
    expect(typing.byUser(field)).toBe(false);
  });

  it('never counts a change execCommand makes, though its input event is trusted', () => {
    field.focus();
    field.value = 'guess';
    changed('insertText', 'guess');
    expect(typing.byUser(field)).toBe(false);
    // Nor right after the user typed something there: one key, one change.
    field.value = '';
    type(field, 'a');
    expect(typing.byUser(field)).toBe(true);
    field.value = 'aguess';
    changed('insertText', 'guess');
    expect(typing.byUser(field)).toBe(false);
  });

  it('never counts its own text in place of a key press, a paste or a drop', () => {
    // It cancels the key, and puts in its own text.
    field.addEventListener('keydown', (event) => event.preventDefault(), { once: true });
    press(field, 'a');
    field.value = 'guess';
    changed('insertText', 'guess');
    expect(typing.byUser(field)).toBe(false);

    fireTrusted(field, new Event('paste', { bubbles: true }));
    field.value = 'guess';
    changed('insertText', 'guess');
    expect(typing.byUser(field)).toBe(false);

    // A modifier key puts in nothing of its own.
    press(field, 'Shift');
    field.value = 'g';
    changed('insertText', 'g');
    expect(typing.byUser(field)).toBe(false);
  });

  it('never counts a key press that lands on what it set', () => {
    // It sets all but the last character of a guess; the user types one key.
    type(field, 'abc');
    field.value = 'abcgues';
    type(field, 's');
    expect(field.value).toBe('abcguess');
    expect(typing.byUser(field)).toBe(false);

    // Or it moves the caret, so the key lands elsewhere.
    field.value = '';
    type(field, 'abc');
    press(field, 'x');
    field.value = 'xabc';
    changed('insertText', 'x');
    expect(typing.byUser(field)).toBe(false);
  });

  it('never counts a composition that ends on what it set', () => {
    type(field, 'abc');
    fireTrusted(field, new CompositionEvent('compositionstart', { bubbles: true }));
    field.value = 'abcguessé';
    fireTrusted(field, new CompositionEvent('compositionend', { data: 'é', bubbles: true }));
    expect(typing.byUser(field)).toBe(false);
  });
});
