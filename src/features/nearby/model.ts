// Small pure helpers for the Nearby page, the pairing dialog and the sync
// dialog.

import type { TFunction } from 'i18next';
import type { Conflict } from '@/bindings/Conflict';
import type { Pairing } from '@/bindings/Pairing';
import type { PairingFailure } from '@/bindings/PairingFailure';
import type { Server } from '@/bindings/Server';
import type { SyncSummary } from '@/bindings/SyncSummary';

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

/** One line for what a sync changed here, e.g. "2 added, 1 changed". */
export function summaryLine(t: TFunction, summary: SyncSummary): string {
  const parts = [
    summary.added ? t('nearby.sync.added', { count: summary.added }) : null,
    summary.changed ? t('nearby.sync.changed', { count: summary.changed }) : null,
    summary.removed ? t('nearby.sync.removed', { count: summary.removed }) : null,
    summary.keysAdded ? t('nearby.sync.keysAdded', { count: summary.keysAdded }) : null,
  ].filter((part) => part !== null);
  return parts.length > 0 ? parts.join(', ') : t('nearby.sync.nothing');
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

/** Where a server's password goes: `user@host`, with the port unless it is 22. */
export function serverAddress(server: Server): string {
  const port = server.port === 22 ? '' : `:${server.port}`;
  return `${server.user}@${server.hostName}${port}`;
}

/** A `host:port` the backend can try: a host and a port from 1 to 65535. */
export function isAddress(text: string): boolean {
  const match = /^(\[[0-9a-fA-F:.]+\]|[^\s:[\]]+):(\d{1,5})$/.exec(text.trim());
  if (!match) return false;
  const port = Number(match[2]);
  return port >= 1 && port <= 65_535;
}
