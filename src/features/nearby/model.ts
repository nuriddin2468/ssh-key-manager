// Small pure helpers for the Nearby page and the pairing dialog.

import type { Pairing } from '@/bindings/Pairing';
import type { PairingFailure } from '@/bindings/PairingFailure';

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
  return (
    type === 'connecting' ||
    type === 'compare' ||
    type === 'waiting' ||
    type === 'offering' ||
    type === 'offered'
  );
}

/** Failures the user should try again after, as opposed to a decision. */
export function canRetry(reason: PairingFailure): boolean {
  return !['declined', 'peerDeclined', 'cancelled', 'refused', 'turned'].includes(reason);
}

/** A `host:port` the backend can try: a host and a port from 1 to 65535. */
export function isAddress(text: string): boolean {
  const match = /^(\[[0-9a-fA-F:.]+\]|[^\s:[\]]+):(\d{1,5})$/.exec(text.trim());
  if (!match) return false;
  const port = Number(match[2]);
  return port >= 1 && port <= 65_535;
}
