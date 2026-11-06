// What the command palette and the quick search window ran lately, newest
// first: item ids such as `host:prod:connect` or `entry:<uuid>:password`,
// never anything secret. Kept in the webview's local storage, which both
// windows share.

import { useSyncExternalStore } from 'react';

const KEY = 'sshkm.palette.recent';
export const RECENT_LIMIT = 12;

export function loadRecent(storage: Pick<Storage, 'getItem'> | undefined): string[] {
  try {
    const list: unknown = JSON.parse(storage?.getItem(KEY) ?? '[]');
    return Array.isArray(list)
      ? list.filter((id): id is string => typeof id === 'string').slice(0, RECENT_LIMIT)
      : [];
  } catch {
    return [];
  }
}

/** Puts `id` first, without duplicates, keeping at most {@link RECENT_LIMIT}. */
export function withRecent(list: readonly string[], id: string): string[] {
  return [id, ...list.filter((other) => other !== id)].slice(0, RECENT_LIMIT);
}

const storage = typeof localStorage === 'undefined' ? undefined : localStorage;
let current = loadRecent(storage);
const listeners = new Set<() => void>();

function publish(next: string[]): void {
  current = next;
  for (const listener of listeners) listener();
}

export function rememberRecent(id: string): void {
  const next = withRecent(current, id);
  try {
    storage?.setItem(KEY, JSON.stringify(next));
  } catch {
    // Storage full or blocked: the list is a convenience.
  }
  publish(next);
}

// The other window ran something.
if (typeof window !== 'undefined') {
  window.addEventListener('storage', (event) => {
    if (event.key === KEY) publish(loadRecent(storage));
  });
}

export function useRecent(): readonly string[] {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => current,
  );
}
