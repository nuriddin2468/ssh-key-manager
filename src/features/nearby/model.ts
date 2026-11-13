// Small pure helpers for the Nearby page, the pairing dialog and the sync
// dialog.

import type { TFunction } from 'i18next';
import type { Conflict } from '@/bindings/Conflict';
import type { Pairing } from '@/bindings/Pairing';
import type { PairingFailure } from '@/bindings/PairingFailure';
import type { Review } from '@/bindings/Review';
import type { SyncItemKind } from '@/bindings/SyncItemKind';
import type { SyncSummary } from '@/bindings/SyncSummary';
import type { VaultChange } from '@/bindings/VaultChange';
import type { VaultConflict } from '@/bindings/VaultConflict';
import type { VaultCounts } from '@/bindings/VaultCounts';
import type { VaultOff } from '@/bindings/VaultOff';
import { cloudName } from '@/features/envs/files/model';

/** Seconds left until `until` (RFC 3339), never below zero; `null` without one. */
export function secondsLeft(until: string | null, now: number = Date.now()): number | null {
  if (!until) return null;
  const end = new Date(until).getTime();
  if (Number.isNaN(end)) return null;
  return Math.max(0, Math.round((end - now) / 1000));
}

/** `9:05` — minutes and seconds. */
export function clock(seconds: number): string {
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, '0')}`;
}

/** The pairing is still waiting for something (it can be cancelled). */
export function isActive(pairing: Pairing | null | undefined): boolean {
  if (!pairing) return false;
  const { type } = pairing.phase;
  return ACTIVE.has(type);
}

const ACTIVE = new Set([
  'connecting',
  'compare',
  'waiting',
  'nameMismatch',
  'offering',
  'offered',
  'authorize',
  'approving',
  'transfer',
  'setMaster',
  'syncing',
  'decide',
]);

/** Failures the user should try again after, as opposed to a decision. */
export function canRetry(reason: PairingFailure): boolean {
  return ![
    'declined',
    'peerDeclined',
    'cancelled',
    'refused',
    'turned',
    'otherVault',
    'notOwn',
    'unsupported',
    'peerUnsupported',
  ].includes(reason);
}

/** Whole percent of `done` out of `total`; 0 without a total. */
export function percent(done: number, total: number): number {
  if (total <= 0) return 0;
  return Math.min(100, Math.floor((done / total) * 100));
}

/** The vault's kinds of items, in the order the dialogs list them. */
export const VAULT_KINDS: (keyof VaultCounts)[] = ['logins', 'environments', 'shared', 'folders'];

/** Where an item's kind is counted in a sync's summary. */
export function kindKey(kind: SyncItemKind): keyof VaultCounts {
  const keys: Record<SyncItemKind, keyof VaultCounts> = {
    login: 'logins',
    environment: 'environments',
    shared: 'shared',
    folder: 'folders',
  };
  return keys[kind];
}

/** One line per kind of the vault's items a sync changed: "Passwords: 3 added, 1 changed". */
export function vaultLines(t: TFunction, counts: VaultCounts): string[] {
  return VAULT_KINDS.flatMap((kind) => {
    const { added, changed, removed } = counts[kind];
    const changes = [
      added ? t('nearby.sync.vault.added', { count: added }) : null,
      changed ? t('nearby.sync.vault.changed', { count: changed }) : null,
      removed ? t('nearby.sync.vault.removed', { count: removed }) : null,
    ].filter((part) => part !== null);
    return changes.length > 0
      ? [
          t('nearby.sync.vault.line', {
            kind: t(`nearby.sync.vault.kinds.${kind}`),
            changes: changes.join(', '),
          }),
        ]
      : [];
  });
}

/** The lines of what a sync changed here: hosts and server keys, then the vault by kind. */
export function summaryLines(t: TFunction, summary: SyncSummary): string[] {
  const hosts = [
    summary.added ? t('nearby.sync.added', { count: summary.added }) : null,
    summary.changed ? t('nearby.sync.changed', { count: summary.changed }) : null,
    summary.removed ? t('nearby.sync.removed', { count: summary.removed }) : null,
    summary.keysAdded ? t('nearby.sync.keysAdded', { count: summary.keysAdded }) : null,
  ].filter((part) => part !== null);
  const lines = [
    ...(hosts.length > 0 ? [hosts.join(', ')] : []),
    ...vaultLines(t, summary.vault),
    // A device made the user's through a sync is always named.
    ...(summary.devicesAdded.length > 0
      ? [t('nearby.sync.devicesAdded', { names: summary.devicesAdded.join(', ') })]
      : []),
  ];
  return lines.length > 0 ? lines : [t('nearby.sync.nothing')];
}

/** One line for what a sync changed here, e.g. "2 hosts added; Passwords: 1 changed". */
export function summaryLine(t: TFunction, summary: SyncSummary): string {
  return summaryLines(t, summary).join('; ');
}

/** Why the vault's entries didn't sync, in a sentence. */
export function vaultOffText(t: TFunction, off: VaultOff, peer: string): string {
  if (off.type === 'version') return t('nearby.sync.vault.offVersion', { peer });
  const service = cloudName(t, off.service);
  return off.here
    ? t('nearby.sync.vault.offCloudHere', { service, peer })
    : t('nearby.sync.vault.offCloudThere', { service, peer });
}

/** What each side did to an item in a conflict. */
export function conflictStory(t: TFunction, conflict: VaultConflict, peer: string): string {
  if (conflict.here === 'deleted') return t('nearby.sync.vault.deletedHere', { peer });
  if (conflict.there === 'deleted') return t('nearby.sync.vault.deletedThere', { peer });
  if (conflict.toBin) return t('nearby.sync.vault.binnedThere', { peer });
  return t('nearby.sync.vault.changedBoth', { peer });
}

/** The labels fields go under. */
type FieldKey =
  | 'title'
  | 'username'
  | 'password'
  | 'url'
  | 'notes'
  | 'otp'
  | 'link'
  | 'value'
  | 'variables'
  | 'files'
  | 'part'
  | 'folder'
  | 'tags'
  | 'look'
  | 'custom'
  | 'name';

/** KeePass's own text fields, by the label they go under. */
const STANDARD: Record<string, FieldKey> = {
  Title: 'title',
  UserName: 'username',
  Password: 'password',
  URL: 'url',
  Notes: 'notes',
  otp: 'otp',
  'Unrecognized 2FA secret': 'otp',
  'sshkm.kind': 'link',
  'sshkm.host': 'link',
  'sshkm.fingerprint': 'link',
};

/** Fields of an item's look and settings, shown as one. */
const LOOK = new Set([
  'icon',
  'fg',
  'bg',
  'overrideUrl',
  'autotype',
  'expiry',
  'qualityCheck',
  'sequence',
  'search',
]);

/** What a field of a synced item is, for people: an environment's variable by its name. */
export function fieldLabel(t: TFunction, field: string, kind: SyncItemKind): string {
  const label = (key: FieldKey) => t(`nearby.sync.vault.fields.${key}`);
  if (field.startsWith('s:')) {
    const name = field.slice(2);
    if (kind === 'shared' && name === 'Password') return label('value');
    if (kind === 'environment' && !['Title', 'Notes', 'Password'].includes(name)) {
      return name.replace(/^env\./, '');
    }
    const key = STANDARD[name];
    return key ? label(key) : name;
  }
  if (field.startsWith('a:')) return t('nearby.sync.vault.fields.file', { name: field.slice(2) });
  if (field === 'cd:sshkm.env') return label('variables');
  if (field === 'cd:sshkm.env.files') return label('files');
  if (field === 'cd:sshkm.env.part') return label('part');
  if (field.startsWith('cd:')) return label('custom');
  if (field === 'group') return label('folder');
  if (field === 'tags') return label('tags');
  if (field === 'name') return label('name');
  if (field === 'notes') return label('notes');
  if (LOOK.has(field)) return label('look');
  return field;
}

/** The labels of a conflict's fields, each once. */
export function fieldLabels(t: TFunction, fields: string[], kind: SyncItemKind): string[] {
  return [...new Set(fields.map((field) => fieldLabel(t, field, kind)))];
}

/**
 * Whether a field holds a 2FA secret, as this app, KeePassXC or KeePass's plugins write it
 * (`otp`, `TOTP Seed`, `TimeOtp-Secret-…`, `HmacOtp-Secret-…`), in any letter case: never shown.
 */
function isOtpField(field: string): boolean {
  const name = field.slice(2).toLowerCase();
  return (
    ['otp', 'unrecognized 2fa secret', 'totp seed'].includes(name) ||
    name.startsWith('timeotp-secret') ||
    name.startsWith('hmacotp-secret')
  );
}

/** Whether the user may see a field's two values: a text field, never a 2FA secret. */
export function canShow(field: string): boolean {
  return field.startsWith('s:') && !isOtpField(field);
}

/**
 * Whether the app shows `field` of `item` while `review` is open, as it decides: a field
 * {@link canShow} allows that differs in a conflict both computers changed.
 */
export function mayShow(review: Review, item: string, field: string): boolean {
  return (
    canShow(field) &&
    review.vault.conflicts.some(
      (conflict) =>
        conflict.id === item &&
        conflict.here === 'changed' &&
        conflict.there === 'changed' &&
        conflict.fields.includes(field),
    )
  );
}

/** The vault's deletions, by kind in the dialogs' order: each kind's label and names. */
export function deletionGroups(
  t: TFunction,
  deletions: VaultChange[],
): { kind: string; names: string[] }[] {
  return VAULT_KINDS.flatMap((kind) => {
    const names = deletions
      .filter((change) => kindKey(change.kind) === kind)
      .map((change) =>
        change.fromBin ? `${change.label} (${t('nearby.sync.vault.fromBin')})` : change.label,
      );
    return names.length > 0 ? [{ kind: t(`nearby.sync.vault.kinds.${kind}`), names }] : [];
  });
}

/** The fields of a conflict's two versions, key by key, with where they differ. */
export function conflictRows(
  conflict: Conflict,
): { key: string; mine: string | null; theirs: string | null; differs: boolean }[] {
  const keys: string[] = [];
  for (const field of [...(conflict.mine?.fields ?? []), ...(conflict.theirs?.fields ?? [])]) {
    if (!keys.some((key) => key.toLowerCase() === field.key.toLowerCase())) keys.push(field.key);
  }
  const value = (side: Conflict['mine'], key: string) =>
    side?.fields
      .find((field) => field.key.toLowerCase() === key.toLowerCase())
      ?.values.join(', ') ?? null;
  return keys.map((key) => {
    const mine = value(conflict.mine, key);
    const theirs = value(conflict.theirs, key);
    return { key, mine, theirs, differs: mine !== theirs };
  });
}

/** A `host:port` the backend can try: a host and a port from 1 to 65535. */
export function isAddress(text: string): boolean {
  const match = /^(\[[0-9a-fA-F:.]+\]|[^\s:[\]]+):(\d{1,5})$/.exec(text.trim());
  if (!match) return false;
  const port = Number(match[2]);
  return port >= 1 && port <= 65_535;
}
