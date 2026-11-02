// Choosing the key a host moves to from its saved password.

import type { KeyView } from '@/bindings/KeyView';

/** Keys that can sign in and be installed: a private key with a known public key. */
export function usableKeys(keys: readonly KeyView[]): KeyView[] {
  return keys.filter((key) => key.privatePath && key.publicKey && key.format !== 'publicOnly');
}

/**
 * The key to offer first for the host `hostId`: one its `IdentityFile`
 * already names, then one unlocked in the agent, then software keys over
 * security keys (which need a touch every time), Ed25519 over the rest, and
 * the newest of equals. `null` if there is no usable key.
 */
export function preselectKey(keys: readonly KeyView[], hostId: number): KeyView | null {
  const rank = (key: KeyView) => [
    key.usedBy.some((usage) => usage.hostId === hostId) ? 0 : 1,
    key.inAgent ? 0 : 1,
    key.hardware ? 1 : 0,
    key.algorithm === 'ed25519' ? 0 : 1,
  ];
  let best: KeyView | null = null;
  for (const key of usableKeys(keys)) {
    if (!best || compare(key, best, rank) < 0) best = key;
  }
  return best;
}

function compare(a: KeyView, b: KeyView, rank: (key: KeyView) => number[]): number {
  const ra = rank(a);
  const rb = rank(b);
  for (let i = 0; i < ra.length; i++) {
    const diff = (ra[i] ?? 0) - (rb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  // Newer first; ISO timestamps sort as text.
  return (b.modified ?? '').localeCompare(a.modified ?? '');
}

/**
 * The key has a passphrase `ssh` cannot get: not unlocked in the agent and
 * not saved in the vault, so a key-only login cannot use it.
 */
export function needsUnlock(key: KeyView, passphraseSaved: boolean): boolean {
  return key.encrypted === true && !key.hardware && !key.inAgent && !passphraseSaved;
}
