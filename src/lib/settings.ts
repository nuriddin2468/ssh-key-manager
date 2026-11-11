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
  /** The project the app opens on: an id, or `personal` (also the first time). */
  lastProject: string;
  /** Sidebar groups the user folded, by name (`library`, `system`). */
  foldedNav: string[];
}

const KEY = 'sshkm.settings';
const DEFAULTS: Settings = {
  defaultAlgorithm: 'ed25519',
  defaultLifetime: 3600,
  ignoredFindings: [],
  autoUpdate: true,
  defaultShell: null,
  lastProject: 'personal',
  foldedNav: [],
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

export function updateSettings(patch: Partial<Settings>): void {
  current = { ...current, ...patch };
  try {
    localStorage.setItem(KEY, JSON.stringify(current));
  } catch {
    // Without storage the change lasts until the app quits.
  }
  for (const listener of listeners) listener();
}

/** The settings now, outside React. */
export function currentSettings(): Settings {
  return current;
}

export function useSettings(): Settings {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}

export const LIFETIMES = [3600, 8 * 3600, null] as const;
