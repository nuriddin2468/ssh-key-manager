import { describe, expect, it } from 'vitest';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { HostEntry } from '@/bindings/HostEntry';
import { findHostEntry, hostAliases, hostEntryInput, isOtpSecret } from './vault';

function entry(partial: Partial<EntrySummary>): EntrySummary {
  return {
    id: 'id',
    title: 'prod',
    username: '',
    url: '',
    kind: 'host',
    host: 'prod',
    keyFingerprint: null,
    hasPassword: true,
    hasOtp: false,
    group: null,
    inTrash: false,
    created: null,
    modified: null,
    ...partial,
  };
}

function host(partial: Partial<HostEntry>): HostEntry {
  return {
    id: 0,
    kind: 'host',
    patterns: ['prod'],
    criteria: null,
    options: [],
    hostName: null,
    user: null,
    port: null,
    identityFiles: [],
    proxyJump: null,
    isWildcard: false,
    lineStart: 1,
    lineEnd: 1,
    ...partial,
  };
}

describe('hostAliases', () => {
  it('keeps the names ssh can be run with', () => {
    expect(hostAliases(host({ patterns: ['prod', 'prod.example.com', '!old'] }))).toEqual([
      'prod',
      'prod.example.com',
    ]);
    expect(hostAliases(host({ patterns: ['*.corp'], isWildcard: true }))).toEqual([]);
    expect(hostAliases(host({ kind: 'match', patterns: [] }))).toEqual([]);
  });
});

describe('findHostEntry', () => {
  it('takes the first host entry for the alias outside the recycle bin', () => {
    const entries = [
      entry({ id: 'login', kind: 'login', host: null, title: 'prod' }),
      entry({ id: 'trashed', inTrash: true }),
      entry({ id: 'first' }),
      entry({ id: 'second' }),
    ];
    expect(findHostEntry(entries, ['prod'])).toEqual({ alias: 'prod', entry: entries[2] });
  });

  it('tries the aliases in order and says which one matched', () => {
    const entries = [entry({ id: 'long', host: 'prod.example.com' })];
    expect(findHostEntry(entries, ['prod', 'prod.example.com'])?.alias).toBe('prod.example.com');
    expect(findHostEntry(entries, ['PROD.example.com'])).toBeUndefined();
    expect(findHostEntry(undefined, ['prod'])).toBeUndefined();
  });
});

describe('hostEntryInput', () => {
  it('names a new entry after the alias', () => {
    expect(
      hostEntryInput('prod', { username: ' deploy ', password: 's3cret', otp: ' JBSWY3DP ' }),
    ).toEqual({
      title: 'prod',
      username: 'deploy',
      password: 's3cret',
      url: '',
      notes: '',
      otp: 'JBSWY3DP',
      kind: 'host',
      host: 'prod',
      keyFingerprint: null,
    });
  });

  it('keeps the current title, link and notes, and passes null through to keep secrets', () => {
    const current = {
      ...entry({ title: 'Production API', url: 'https://prod.example.com' }),
      notes: 'Rotate in March',
      passwordChanged: null,
      historyLen: 0,
    } satisfies EntryDetail;
    expect(
      hostEntryInput('prod', { username: 'deploy', password: null, otp: null }, current),
    ).toMatchObject({
      title: 'Production API',
      url: 'https://prod.example.com',
      notes: 'Rotate in March',
      password: null,
      otp: null,
    });
    expect(hostEntryInput('prod', { username: '', password: null, otp: '' }).otp).toBe('');
  });
});

describe('isOtpSecret', () => {
  it.each([
    ['otpauth://totp/prod?secret=JBSWY3DPEHPK3PXP', true],
    ['JBSWY3DPEHPK3PXP', true],
    ['jbsw y3dp ehpk 3pxp', true],
    ['JBSW-Y3DP-EHPK-3PXP==', true],
    ['JBSWY3DP', false],
    ['123456', false],
    ['not a secret at all', false],
  ])('%s → %s', (value, valid) => {
    expect(isOtpSecret(value)).toBe(valid);
  });
});
