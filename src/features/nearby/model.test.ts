import type { TFunction } from 'i18next';
import { describe, expect, it } from 'vitest';
import type { Pairing } from '@/bindings/Pairing';
import type { Review } from '@/bindings/Review';
import type { SyncSummary } from '@/bindings/SyncSummary';
import type { VaultConflict } from '@/bindings/VaultConflict';
import {
  canRetry,
  canShow,
  clock,
  conflictRows,
  conflictStory,
  fieldLabel,
  fieldLabels,
  isActive,
  isAddress,
  mayShow,
  percent,
  secondsLeft,
  summaryLine,
  summaryLines,
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
    expect(isActive(pairing({ type: 'nameMismatch', announced: 'MacBook' }))).toBe(true);
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
    devicesAdded: [],
    keysDiffer: [],
    deferred: 0,
    deferredThere: 0,
    conflicts: 0,
    failed: 0,
    vault: {
      logins: { added: 0, changed: 0, removed: 0 },
      environments: { added: 0, changed: 0, removed: 0 },
      shared: { added: 0, changed: 0, removed: 0 },
      folders: { added: 0, changed: 0, removed: 0 },
    },
    vaultOff: null,
  };

  it('names what changed, and says when nothing did', () => {
    expect(summaryLine(t, summary)).toBe('nearby.sync.added:2, nearby.sync.removed:1');
    expect(summaryLine(t, { ...summary, added: 0, removed: 0 })).toBe('nearby.sync.nothing');
  });

  it('adds a line per kind of the vault’s items', () => {
    const vault = { ...summary.vault, environments: { added: 1, changed: 2, removed: 0 } };
    expect(summaryLines(t, { ...summary, added: 0, removed: 0, vault })).toEqual([
      'nearby.sync.vault.line',
    ]);
    expect(summaryLines(t, { ...summary, vault })).toHaveLength(2);
  });

  it('always names a device a sync made one of the user’s', () => {
    const named = ((key: string, options?: { names?: string }) =>
      options?.names ? `${key}:${options.names}` : key) as unknown as TFunction;
    expect(
      summaryLines(named, { ...summary, added: 0, removed: 0, devicesAdded: ['Phone', 'Tablet'] }),
    ).toEqual(['nearby.sync.devicesAdded:Phone, Tablet']);
  });
});

describe('conflictStory', () => {
  const t = ((key: string) => key) as unknown as TFunction;
  const conflict: VaultConflict = {
    id: 'x',
    kind: 'login',
    label: 'Mail',
    here: 'changed',
    there: 'changed',
    fields: ['s:Password'],
    risky: [],
    toBin: false,
  };

  it('says when taking the other version moves the item to the recycle bin', () => {
    expect(conflictStory(t, conflict, 'iMac')).toBe('nearby.sync.vault.changedBoth');
    expect(conflictStory(t, { ...conflict, toBin: true }, 'iMac')).toBe(
      'nearby.sync.vault.binnedThere',
    );
    expect(conflictStory(t, { ...conflict, there: 'deleted' }, 'iMac')).toBe(
      'nearby.sync.vault.deletedThere',
    );
  });
});

describe('fieldLabel', () => {
  const t = ((key: string, options?: { name?: string }) =>
    options?.name ? `${key}:${options.name}` : key) as unknown as TFunction;

  it('names KeePass fields, variables by their names and the rest by what they are', () => {
    expect(fieldLabel(t, 's:Password', 'login')).toBe('nearby.sync.vault.fields.password');
    expect(fieldLabel(t, 's:Password', 'shared')).toBe('nearby.sync.vault.fields.value');
    expect(fieldLabel(t, 's:DB_URL', 'environment')).toBe('DB_URL');
    expect(fieldLabel(t, 's:env.URL', 'environment')).toBe('URL');
    expect(fieldLabel(t, 's:Title', 'environment')).toBe('nearby.sync.vault.fields.title');
    expect(fieldLabel(t, 'a:key.pem', 'login')).toBe('nearby.sync.vault.fields.file:key.pem');
    expect(fieldLabel(t, 'cd:sshkm.env.files', 'environment')).toBe(
      'nearby.sync.vault.fields.files',
    );
    expect(fieldLabels(t, ['fg', 'bg', 'icon'], 'login')).toEqual([
      'nearby.sync.vault.fields.look',
    ]);
  });

  it('never offers a 2FA secret or a non-text field to show', () => {
    expect(canShow('s:Password')).toBe(true);
    expect(canShow('s:otp')).toBe(false);
    expect(canShow('s:Unrecognized 2FA secret')).toBe(false);
    expect(canShow('s:TOTP Seed')).toBe(false);
    expect(canShow('s:TimeOtp-Secret-Base32')).toBe(false);
    expect(canShow('s:HmacOtp-Secret')).toBe(false);
    expect(canShow('s:OTP')).toBe(false);
    expect(canShow('s:totp seed')).toBe(false);
    expect(canShow('a:key.pem')).toBe(false);
    expect(canShow('group')).toBe(false);
  });
});

describe('mayShow', () => {
  const conflict = (id: string, there: 'changed' | 'deleted'): VaultConflict => ({
    id,
    kind: 'login',
    label: 'Mail',
    here: 'changed',
    there,
    fields: ['s:Password', 's:TOTP Seed'],
    risky: [],
    toBin: false,
  });
  const review: Review = {
    conflicts: [],
    risky: [],
    deletions: [],
    vault: {
      conflicts: [conflict('both', 'changed'), conflict('gone', 'deleted')],
      risky: [],
      deletions: [],
    },
  };

  it('shows only a text field of a conflict both computers changed', () => {
    expect(mayShow(review, 'both', 's:Password')).toBe(true);
    expect(mayShow(review, 'both', 's:TOTP Seed')).toBe(false);
    expect(mayShow(review, 'both', 's:Notes')).toBe(false);
    expect(mayShow(review, 'gone', 's:Password')).toBe(false);
    expect(mayShow(review, 'elsewhere', 's:Password')).toBe(false);
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
