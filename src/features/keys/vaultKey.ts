// Which keys have their passphrase saved in the password vault.
//
// While the vault is unlocked its entries say so. While it is locked nothing
// can be read, so the fingerprints seen at the last unlock are remembered
// (fingerprints are public; the passphrases themselves never reach the UI).

import type { QueryClient } from '@tanstack/react-query';
import { keys as queryKeys, useVaultEntries, useVaultStatus } from '@/api/queries';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntrySummary } from '@/bindings/EntrySummary';

type KeyEntry = EntrySummary & { keyFingerprint: string };

/** A key entry outside the recycle bin that has a passphrase. */
function holdsPassphrase(entry: EntrySummary): entry is KeyEntry {
  return entry.kind === 'key' && !entry.inTrash && entry.hasPassword && !!entry.keyFingerprint;
}

/**
 * The entry holding the passphrase of the key with this fingerprint; the most
 * recently changed one if there are several, the last of equals, as the
 * backend picks it (`Iterator::max_by` over the same list).
 */
export function findKeyEntry(
  entries: readonly EntrySummary[] | undefined,
  fingerprint: string | null | undefined,
): EntrySummary | undefined {
  let found: EntrySummary | undefined;
  for (const entry of entries ?? []) {
    if (!holdsPassphrase(entry) || entry.keyFingerprint !== fingerprint) continue;
    if (!found || (entry.modified ?? '') >= (found.modified ?? '')) found = entry;
  }
  return found;
}

/** Fingerprints of all keys with a saved passphrase. */
export function savedFingerprints(entries: readonly EntrySummary[]): Set<string> {
  return new Set(entries.filter(holdsPassphrase).map((entry) => entry.keyFingerprint));
}

/**
 * The entry for a key's passphrase: named after the key file, or, when
 * `current` is given, keeping its title and other fields.
 */
export function keyEntryInput(
  key: { name: string; fingerprint: string },
  passphrase: string,
  current?: EntryDetail,
): EntryInput {
  return {
    title: current?.title || key.name,
    username: current?.username ?? '',
    url: current?.url ?? '',
    notes: current?.notes ?? '',
    password: passphrase,
    otp: null,
    kind: 'key',
    host: null,
    keyFingerprint: key.fingerprint,
  };
}

const STORAGE_KEY = 'sshkm.vaultKeys';

function load(): Set<string> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    const list: unknown = raw ? JSON.parse(raw) : [];
    return new Set(Array.isArray(list) ? list.filter((x) => typeof x === 'string') : []);
  } catch {
    return new Set();
  }
}

let remembered = load();

function remember(next: Set<string>): void {
  const same = next.size === remembered.size && [...next].every((fp) => remembered.has(fp));
  if (same) return;
  remembered = next;
  try {
    if (next.size) localStorage.setItem(STORAGE_KEY, JSON.stringify([...next]));
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Without storage it is remembered until the app quits.
  }
}

/** Whether the passphrase was in the vault when it was last unlocked. */
export function rememberedSaved(fingerprint: string | null | undefined): boolean {
  return Boolean(fingerprint && remembered.has(fingerprint));
}

/**
 * Keeps the remembered fingerprints in step with every load of the vault's
 * entries, whichever screen loads them. Returns the unsubscribe function.
 */
export function watchKeyEntries(client: QueryClient): () => void {
  return client.getQueryCache().subscribe((event) => {
    if (event.type !== 'updated' || event.action.type !== 'success') return;
    const key = event.query.queryKey;
    if (key[0] === queryKeys.vaultEntries[0] && key[1] === queryKeys.vaultEntries[1]) {
      remember(savedFingerprints(event.query.state.data as EntrySummary[]));
    } else if (key[0] === queryKeys.vaultStatus[0] && key[1] === queryKeys.vaultStatus[1]) {
      const state = (event.query.state.data as { state?: string } | undefined)?.state;
      if (state === 'missing') remember(new Set());
    }
  });
}

export type VaultKey =
  /** Still loading, or the vault status is unknown. */
  | { vault: 'unknown' }
  /** There is no vault. */
  | { vault: 'missing' }
  /** `saved`: the passphrase was in the vault when it was last unlocked. */
  | { vault: 'locked'; saved: boolean }
  /** `entry`: the entry with the passphrase, if there is one. */
  | { vault: 'unlocked'; entry: EntrySummary | undefined };

/** What the vault knows about the passphrase of the key with this fingerprint. */
export function useVaultKey(fingerprint: string | null | undefined): VaultKey {
  const status = useVaultStatus();
  const entries = useVaultEntries();
  switch (status.data?.state) {
    case 'missing':
      return { vault: 'missing' };
    case 'locked':
      return { vault: 'locked', saved: rememberedSaved(fingerprint) };
    case 'unlocked':
      return entries.data
        ? { vault: 'unlocked', entry: findKeyEntry(entries.data, fingerprint) }
        : { vault: 'unknown' };
    default:
      return { vault: 'unknown' };
  }
}
