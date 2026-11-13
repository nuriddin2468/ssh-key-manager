import { useSyncExternalStore } from 'react';

/** Per-user preferences, kept in the webview's local storage. */
export interface Settings {
  defaultAlgorithm: 'ed25519' | 'rsa' | 'ecdsa';
  /** Seconds to keep keys unlocked; `null` until logout. */
  defaultLifetime: number | null;
  /** Audit finding ids the user chose to ignore. */
  ignoredFindings: string[];
  /** Look for a newer release at startup and every few hours. */
  autoUpdate: boolean;
  /** The shell local sessions open in (an id from `terminal_shells`); `null` for the system's. */
  defaultShell: string | null;
  /** Sidebar groups the user folded, by name (`library`, `system`). */
  foldedNav: string[];
  /**
   * Light or dark; `system` follows the system's appearance. `public/theme-boot.js`
   * reads it too, before the first paint.
   */
  appearance: 'system' | 'light' | 'dark';
}

const KEY = 'sshkm.settings';
const DEFAULTS: Settings = {
  defaultAlgorithm: 'ed25519',
  defaultLifetime: 3600,
  ignoredFindings: [],
  autoUpdate: true,
  defaultShell: null,
  foldedNav: [],
  appearance: 'system',
};

function load(): Settings {
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? { ...DEFAULTS, ...(JSON.parse(raw) as Partial<Settings>) } : DEFAULTS;
  } catch {
    return DEFAULTS;
  }
}

let current = load();
const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) listener();
}

export function updateSettings(patch: Partial<Settings>): void {
  current = { ...current, ...patch };
  try {
    localStorage.setItem(KEY, JSON.stringify(current));
  } catch {
    // Without storage the change lasts until the app quits.
  }
  notify();
}

// The app's windows share the storage: a change made in one (the theme in
// Settings) reaches the others, such as an open quick search window.
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event) => {
    if (event.key !== KEY && event.key !== null) return;
    current = load();
    notify();
  });
}

/** Calls `listener` after every change, here or in another window. Returns the unsubscribe. */
export function subscribeSettings(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** The settings now, outside React. */
export function currentSettings(): Settings {
  return current;
}

export function useSettings(): Settings {
  return useSyncExternalStore(subscribeSettings, () => current);
}

export const LIFETIMES = [3600, 8 * 3600, null] as const;
