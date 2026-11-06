import { describe, expect, it } from 'vitest';
import { acceleratorOf, formatAccelerator, hasCommandKey } from './shortcut';

const press = (
  code: string,
  mods: Partial<Record<'ctrl' | 'alt' | 'shift' | 'meta', boolean>>,
) => ({
  code,
  ctrlKey: Boolean(mods.ctrl),
  altKey: Boolean(mods.alt),
  shiftKey: Boolean(mods.shift),
  metaKey: Boolean(mods.meta),
});

describe('acceleratorOf', () => {
  it('spells modifiers in the backend’s order', () => {
    expect(acceleratorOf(press('Space', { meta: true, shift: true }))).toBe('Shift+Super+Space');
    expect(acceleratorOf(press('KeyK', { alt: true, ctrl: true }))).toBe('Ctrl+Alt+KeyK');
  });

  it('waits while only modifiers are down', () => {
    expect(acceleratorOf(press('ShiftLeft', { shift: true }))).toBeNull();
    expect(acceleratorOf(press('MetaRight', { meta: true }))).toBeNull();
  });
});

describe('hasCommandKey', () => {
  it('needs Ctrl, Alt or Super', () => {
    expect(hasCommandKey('Shift+Super+Space')).toBe(true);
    expect(hasCommandKey('Shift+KeyA')).toBe(false);
    expect(hasCommandKey('F5')).toBe(false);
  });
});

describe('formatAccelerator', () => {
  it('shows symbols on macOS and names elsewhere', () => {
    expect(formatAccelerator('Shift+Super+Space', 'macos')).toBe('⇧⌘Space');
    expect(formatAccelerator('Ctrl+Alt+KeyK', 'macos')).toBe('⌃⌥K');
    expect(formatAccelerator('Ctrl+Shift+Space', 'windows')).toBe('Ctrl+Shift+Space');
    expect(formatAccelerator('Shift+Super+Digit1', 'windows')).toBe('Shift+Win+1');
    expect(formatAccelerator('Super+ArrowUp', 'linux')).toBe('Super+↑');
  });
});
