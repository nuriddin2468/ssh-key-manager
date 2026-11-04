import type { TFunction } from 'i18next';
import { describe, expect, it } from 'vitest';
import type { Pairing } from '@/bindings/Pairing';
import type { SyncSummary } from '@/bindings/SyncSummary';
import {
  canRetry,
  clock,
  conflictRows,
  isActive,
  isAddress,
  percent,
  secondsLeft,
  summaryLine,
} from './model';

describe('secondsLeft', () => {
  it('counts down to the end and stops at zero', () => {
    const now = Date.parse('2026-11-04T12:00:00Z');
    expect(secondsLeft('2026-11-04T12:09:30Z', now)).toBe(570);
    expect(secondsLeft('2026-11-04T11:59:00Z', now)).toBe(0);
    expect(secondsLeft(null, now)).toBeNull();
    expect(secondsLeft('soon', now)).toBeNull();
  });
});

describe('clock', () => {
  it('shows minutes and seconds', () => {
    expect(clock(570)).toBe('9:30');
    expect(clock(65)).toBe('1:05');
    expect(clock(0)).toBe('0:00');
  });
});

describe('isActive', () => {
  const pairing = (phase: Pairing['phase']): Pairing => ({
    id: 1,
    peer: null,
    outgoing: true,
    kind: 'pair',
    phase,
  });

  it('is true until the pairing ends', () => {
    expect(isActive(pairing({ type: 'connecting' }))).toBe(true);
    expect(isActive(pairing({ type: 'compare', code: '123456' }))).toBe(true);
    expect(isActive(pairing({ type: 'waiting', code: '123456' }))).toBe(true);
    expect(isActive(pairing({ type: 'authorize', vault: true }))).toBe(true);
    expect(isActive(pairing({ type: 'setMaster' }))).toBe(true);
    expect(isActive(pairing({ type: 'syncing' }))).toBe(true);
    expect(isActive(pairing({ type: 'paired' }))).toBe(false);
    expect(isActive(pairing({ type: 'joined' }))).toBe(false);
    expect(isActive(pairing({ type: 'failed', reason: 'unreachable' }))).toBe(false);
    expect(isActive(null)).toBe(false);
  });
});

describe('canRetry', () => {
  it('offers another try after a failure, not after a decision', () => {
    expect(canRetry('unreachable')).toBe(true);
    expect(canRetry('peerLeft')).toBe(true);
    expect(canRetry('declined')).toBe(false);
    expect(canRetry('peerDeclined')).toBe(false);
    expect(canRetry('cancelled')).toBe(false);
    expect(canRetry('otherVault')).toBe(false);
  });
});

describe('percent', () => {
  it('rounds down and never passes 100', () => {
    expect(percent(0, 0)).toBe(0);
    expect(percent(1, 3)).toBe(33);
    expect(percent(5, 4)).toBe(100);
  });
});

describe('summaryLine', () => {
  const t = ((key: string, options?: { count?: number }) =>
    options?.count === undefined ? key : `${key}:${options.count}`) as unknown as TFunction;
  const summary: SyncSummary = {
    added: 2,
    changed: 0,
    removed: 1,
    keysAdded: 0,
    keysDiffer: [],
    deferred: 0,
    deferredThere: 0,
    conflicts: 0,
    failed: 0,
  };

  it('names what changed, and says when nothing did', () => {
    expect(summaryLine(t, summary)).toBe('nearby.sync.added:2, nearby.sync.removed:1');
    expect(summaryLine(t, { ...summary, added: 0, removed: 0 })).toBe('nearby.sync.nothing');
  });
});

describe('conflictRows', () => {
  it('lines both versions up by key, without case', () => {
    const rows = conflictRows({
      id: 'prod',
      mine: { id: 'prod', fields: [{ key: 'HostName', values: ['10.0.0.1'] }] },
      theirs: {
        id: 'prod',
        fields: [
          { key: 'hostname', values: ['10.0.0.2'] },
          { key: 'User', values: ['deploy'] },
        ],
      },
    });
    expect(rows).toEqual([
      { key: 'HostName', mine: '10.0.0.1', theirs: '10.0.0.2', differs: true },
      { key: 'User', mine: null, theirs: 'deploy', differs: true },
    ]);
    const deleted = conflictRows({ id: 'x', mine: null, theirs: { id: 'x', fields: [] } });
    expect(deleted).toEqual([]);
  });
});

describe('isAddress', () => {
  it('takes host:port', () => {
    expect(isAddress('192.168.1.24:48213')).toBe(true);
    expect(isAddress(' laptop.local:5000 ')).toBe(true);
    expect(isAddress('[fe80::1]:22')).toBe(true);
    expect(isAddress('192.168.1.24')).toBe(false);
    expect(isAddress('host:0')).toBe(false);
    expect(isAddress('host:70000')).toBe(false);
    expect(isAddress('a b:22')).toBe(false);
  });
});
