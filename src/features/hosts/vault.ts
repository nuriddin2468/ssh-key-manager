// A host's password in the vault: entries of kind `host` name the `Host`
// alias they belong to. Of the entries outside the recycle bin whose alias
// is the one `ssh` is run with, the backend (`host_entry` in
// `commands/vault_hosts.rs`) picks the one made first, one without a time
// counting as older still, then by id; and so does this. Titles don't
// decide, so an entry made later never takes the place of one made before.

import type { TFunction } from 'i18next';
import { useVaultEntries, useVaultStatus } from '@/api/queries';
import { errorMessage } from '@/api/useAppMutation';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { HostEntry } from '@/bindings/HostEntry';
import { AppError } from '@/lib/ipc';
import { type HostForm, hostEntry } from './model';

/** The names `ssh` can be run with for this block: none for patterns and `Match`. */
export function hostAliases(host: HostEntry): string[] {
  if (host.kind !== 'host' || host.isWildcard) return [];
  return host.patterns.filter((p) => p && !p.startsWith('!') && !/[*?]/.test(p));
}

/** The saved password for one of `aliases`, tried in order, and the alias it is for. */
export function findHostEntry(
  entries: readonly EntrySummary[] | undefined,
  aliases: readonly string[],
): { alias: string; entry: EntrySummary } | undefined {
  for (const alias of aliases) {
    const entry = hostEntry(entries ?? [], alias);
    if (entry) return { alias, entry };
  }
  return undefined;
}

export type HostVault =
  /** Loading, or not a host `ssh` can be run with. */
  | { vault: 'unknown' }
  | { vault: 'missing' }
  | { vault: 'locked' }
  /** `alias`: the one with a saved password, else the first. */
  | { vault: 'unlocked'; alias: string; entry: EntrySummary | undefined };

/** What the vault knows about this host's password. */
export function useHostVault(host: HostEntry): HostVault {
  const status = useVaultStatus();
  const entries = useVaultEntries();
  const aliases = hostAliases(host);
  const [first] = aliases;
  if (!first) return { vault: 'unknown' };
  switch (status.data?.state) {
    case 'missing':
      return { vault: 'missing' };
    case 'locked':
      return { vault: 'locked' };
    case 'unlocked': {
      if (!entries.data) return { vault: 'unknown' };
      const found = findHostEntry(entries.data, aliases);
      return { vault: 'unlocked', alias: found?.alias ?? first, entry: found?.entry };
    }
    default:
      return { vault: 'unknown' };
  }
}

export interface PasswordForm {
  username: string;
  /** `null` keeps the saved password. */
  password: string | null;
  /** `null` keeps the saved 2FA secret, `''` removes it. */
  otp: string | null;
}

/** The entry for a host's password, keeping the title, link and notes of `current`. */
export function hostEntryInput(
  alias: string,
  form: PasswordForm,
  current?: EntryDetail,
): EntryInput {
  return {
    title: current?.title || alias,
    username: form.username.trim(),
    password: form.password,
    url: current?.url ?? '',
    notes: current?.notes ?? '',
    otp: form.otp === null ? null : form.otp.trim(),
    kind: 'host',
    host: alias,
    keyFingerprint: null,
  };
}

/** What saving a host does to its saved password. */
export type EntryFollowUp =
  | { kind: 'none' }
  /** The host now signs in with a key alone: the password goes to the recycle bin. */
  | { kind: 'trash'; entryId: string }
  /** The entry follows the host: its `User`, and its alias when that was renamed. */
  | { kind: 'update'; entryId: string; username: string; alias: string };

/**
 * The host's `User` is the user everywhere, so the saved password follows
 * the host when it is saved: a changed `User` becomes the entry's user name,
 * a renamed alias the entry's host. Saved with the Key method, the host
 * keeps no password: it goes to the vault's recycle bin (Key and password is
 * how a host keeps one).
 *
 * `saved` is the block on disk, `found` the password for it (see
 * `findHostEntry`) while the vault is unlocked.
 */
export function entryFollowUp(
  form: HostForm,
  saved: HostEntry,
  found: { alias: string; entry: EntrySummary } | undefined,
): EntryFollowUp {
  if (!found || form.method === null) return { kind: 'none' };
  const { alias, entry } = found;
  if (form.method === 'key') return { kind: 'trash', entryId: entry.id };
  const user = form.user.trim();
  const userChanged = user !== (saved.user ?? '') && user !== entry.username;
  const aliases = form.patterns
    .split(/\s+/)
    .filter((p) => p && !p.startsWith('!') && !/[*?]/.test(p));
  const nextAlias = aliases.includes(alias) ? alias : (aliases[0] ?? alias);
  if (!userChanged && nextAlias === alias) return { kind: 'none' };
  return {
    kind: 'update',
    entryId: entry.id,
    username: userChanged ? user : entry.username,
    alias: nextAlias,
  };
}

/**
 * Whether the vault will take this as a 2FA secret: an `otpauth://` link, or
 * a base32 key of at least 16 characters (spaces and dashes allowed), as the
 * backend checks it.
 */
export function isOtpSecret(value: string): boolean {
  const input = value.trim();
  if (input.startsWith('otpauth://')) return true;
  const secret = input.replace(/[\s-]/g, '').toUpperCase().replace(/=+$/, '');
  return secret.length >= 16 && /^[A-Z2-7]+$/.test(secret);
}

/** A failed vault command as a sentence; covers the vault's own error codes. */
export function vaultErrorMessage(t: TFunction, error: unknown): string {
  const code = AppError.from(error).code;
  if (code === 'vault_locked') return t('hosts.vault.lockedError');
  if (code === 'conflict') return t('hosts.vault.conflictError');
  return errorMessage(t, error);
}
