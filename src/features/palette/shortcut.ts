// The quick search shortcut as the backend spells it
// (src-tauri/src/quick/shortcut.rs): `Ctrl`, `Alt`, `Shift`, `Super` in this
// order, then the key as `KeyboardEvent.code` names it.

import { type Platform, platform } from '@/lib/platform';

const MODIFIER_CODES = new Set([
  'ShiftLeft',
  'ShiftRight',
  'ControlLeft',
  'ControlRight',
  'AltLeft',
  'AltRight',
  'MetaLeft',
  'MetaRight',
  'OSLeft',
  'OSRight',
  'CapsLock',
  'Fn',
]);

type KeyPress = Pick<KeyboardEvent, 'code' | 'ctrlKey' | 'altKey' | 'shiftKey' | 'metaKey'>;

/** The keys pressed as a shortcut; `null` while only modifiers are down. */
export function acceleratorOf(event: KeyPress): string | null {
  if (!event.code || MODIFIER_CODES.has(event.code)) return null;
  const parts: string[] = [];
  if (event.ctrlKey) parts.push('Ctrl');
  if (event.altKey) parts.push('Alt');
  if (event.shiftKey) parts.push('Shift');
  if (event.metaKey) parts.push('Super');
  parts.push(event.code);
  return parts.join('+');
}

/** Has Ctrl, Alt or ⌘ / the Windows key, as the backend requires. */
export function hasCommandKey(accelerator: string): boolean {
  return accelerator
    .split('+')
    .slice(0, -1)
    .some((part) => part === 'Ctrl' || part === 'Alt' || part === 'Super');
}

const MAC_MODIFIERS: Record<string, string> = { Ctrl: '⌃', Alt: '⌥', Shift: '⇧', Super: '⌘' };
const MAC_KEYS: Record<string, string> = {
  Enter: '↩',
  Escape: '⎋',
  Backspace: '⌫',
  Delete: '⌦',
  Tab: '⇥',
};
const KEYS: Record<string, string> = {
  Escape: 'Esc',
  ArrowUp: '↑',
  ArrowDown: '↓',
  ArrowLeft: '←',
  ArrowRight: '→',
  Backquote: '`',
  Minus: '-',
  Equal: '=',
  BracketLeft: '[',
  BracketRight: ']',
  Backslash: '\\',
  Semicolon: ';',
  Quote: "'",
  Comma: ',',
  Period: '.',
  Slash: '/',
};

function keyName(code: string, on: Platform): string {
  if (on === 'macos' && code in MAC_KEYS) return MAC_KEYS[code] ?? code;
  if (code in KEYS) return KEYS[code] ?? code;
  return code.replace(/^Key|^Digit/, '').replace(/^Numpad/, 'Num ');
}

/** How a shortcut is shown: ⇧⌘Space on macOS, Ctrl+Shift+Space elsewhere. */
export function formatAccelerator(accelerator: string, on: Platform): string {
  const parts = accelerator.split('+');
  const key = keyName(parts.at(-1) ?? '', on);
  const modifiers = parts.slice(0, -1);
  if (on === 'macos') {
    return `${modifiers.map((part) => MAC_MODIFIERS[part] ?? part).join('')}${key}`;
  }
  const superName = on === 'windows' ? 'Win' : 'Super';
  return [...modifiers.map((part) => (part === 'Super' ? superName : part)), key].join('+');
}

/** How the app shows one of its own shortcuts: ⇧⌘N on macOS, Ctrl+Shift+N elsewhere. */
export function shortcutLabel(key: string, shift = false): string {
  if (platform === 'macos') return `${shift ? '⇧' : ''}⌘${key}`;
  return `Ctrl+${shift ? 'Shift+' : ''}${key}`;
}
