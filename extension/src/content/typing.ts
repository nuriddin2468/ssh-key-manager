// Which fields hold what the user put in themselves. A sent login goes to
// the app to be checked only with a password the user typed, pasted or
// dropped into its field, or the extension filled, and only as they left
// it: whether the banner appears tells the page the app's answer, so a page
// that could have passwords of its choosing checked could guess saved ones.
//
// A page script can set a field's value without any event, and with
// `execCommand` it can change it so that the browser fires an `input` event
// marked as trusted. It can't press a key, paste or drop. So a change counts
// as the user's only when:
// - it follows their own key press, paste, drop or composition (a dead key,
//   an input method) in that field;
// - a key press put in that key's character, a paste or a drop what was
//   pasted or dropped;
// - it adds to the end of what the user left there, takes from its end, or
//   replaces all of it.
// Any other change leaves the field not the user's until they type it anew.

/** Keys that don't name the character they put in. */
const COMPOSING_KEYS = new Set(['Dead', 'Process', 'Unidentified']);

/** What the next change to a field may come from. */
interface Cause {
  input: HTMLInputElement;
  /** The key pressed; none for a paste or a drop. */
  key?: string;
  /** The `inputType` of the change a paste or a drop makes. */
  inputType?: 'insertFromPaste' | 'insertFromDrop';
}

export class Typing {
  /** What the user, or a fill, left in each field. */
  private readonly left = new WeakMap<HTMLInputElement, string>();
  private cause: Cause | null = null;
  /** A composition in a field, and what the user had left there when it began. */
  private composing: { input: HTMLInputElement; from: string | undefined } | null = null;

  /**
   * Takes in a `keydown`, `paste`, `drop`, `compositionstart`,
   * `compositionend` or `input` event the browser marked as the user's own.
   */
  observe(event: Event): void {
    const input = event.target instanceof HTMLInputElement ? event.target : null;
    switch (event.type) {
      case 'keydown': {
        const key = event as KeyboardEvent;
        this.cause = input ? { input, key: key.key } : null;
        if (!key.isComposing) this.composing = null;
        break;
      }
      case 'paste':
        this.cause = input ? { input, inputType: 'insertFromPaste' } : null;
        break;
      case 'drop':
        this.cause = input ? { input, inputType: 'insertFromDrop' } : null;
        break;
      case 'compositionstart':
        this.composing = input ? { input, from: this.held(input) } : null;
        break;
      case 'compositionend':
        if (input && this.composing?.input === input) {
          const { from } = this.composing;
          this.composing = null;
          const data = (event as CompositionEvent).data ?? '';
          this.judge(input, from !== undefined && input.value === from + data);
        }
        break;
      case 'input':
        if (input) this.changed(input, event as InputEvent);
        break;
    }
  }

  /** The extension filled `input`. */
  filled(input: HTMLInputElement): void {
    this.left.set(input, input.value);
  }

  /** Whether `input` holds something, and just what the user (or a fill) left there. */
  byUser(input: HTMLInputElement): boolean {
    return input.value !== '' && this.left.get(input) === input.value;
  }

  /** What the user left in `input` if it still holds that; an empty field holds nobody's. */
  private held(input: HTMLInputElement): string | undefined {
    if (input.value === '') return '';
    return this.left.get(input) === input.value ? input.value : undefined;
  }

  private changed(input: HTMLInputElement, event: InputEvent): void {
    // A composition counts once it ends.
    if (event.isComposing || this.composing?.input === input) return;
    // One key press, paste or drop makes one change.
    const cause = this.cause?.input === input ? this.cause : null;
    this.cause = null;
    const left = this.left.get(input);
    const after = input.value;
    if (after === left) return;
    const data = event.data ?? '';
    let ok = false;
    if (cause && event.inputType.startsWith('delete')) {
      ok = after === '' || (left?.startsWith(after) ?? false);
    } else if (cause && data !== '' && event.inputType === (cause.inputType ?? 'insertText')) {
      const typed =
        cause.key === undefined ||
        cause.key === data ||
        (COMPOSING_KEYS.has(cause.key) && [...data].length === 1);
      ok = typed && (after === data || after === `${left ?? ''}${data}`);
    }
    this.judge(input, ok);
  }

  private judge(input: HTMLInputElement, ok: boolean): void {
    if (ok) this.left.set(input, input.value);
    else this.left.delete(input);
  }
}
