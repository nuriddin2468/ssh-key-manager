// The user's own input, for tests. The browser marks the events of real key
// presses, clicks and pastes as trusted, and a page script can't make such
// events; jsdom marks only those it fires itself (as for `focus()`), and
// `dispatchEvent` never. Tests that stand for the user fire theirs the way
// jsdom fires its own.

import { implForWrapper } from 'jsdom/lib/generated/idl/utils.js';

/** Fires `event` at `target` marked as trusted; returns whether nothing cancelled it. */
export function fireTrusted(target: EventTarget, event: Event): boolean {
  const targetImpl = implForWrapper(target);
  const eventImpl = implForWrapper(event);
  if (!targetImpl || !eventImpl) throw new Error('not a jsdom object');
  eventImpl.isTrusted = true;
  return targetImpl._dispatch(eventImpl);
}

/** A key press in `target`, as the browser sends it: `keydown`, then what the key changes. */
export function press(target: HTMLElement, key: string, init: KeyboardEventInit = {}): boolean {
  return fireTrusted(
    target,
    new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true, composed: true, ...init }),
  );
}

/**
 * Types `text` into `input` one key at a time, as a person does: each key's
 * `keydown`, the character put in at the end, and the `input` event.
 */
export function type(input: HTMLInputElement, text: string): void {
  for (const key of text) {
    if (!press(input, key)) continue;
    input.value += key;
    fireTrusted(
      input,
      new InputEvent('input', {
        inputType: 'insertText',
        data: key,
        bubbles: true,
        composed: true,
      }),
    );
  }
}

/** A press of the main pointer button on `target`, and the focus it gives a field. */
export function click(target: HTMLElement): void {
  fireTrusted(
    target,
    new PointerEvent('pointerdown', { bubbles: true, cancelable: true, composed: true }),
  );
  target.focus();
}
