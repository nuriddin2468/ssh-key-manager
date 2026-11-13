import { describe, expect, it } from 'vitest';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { HostEntry } from '@/bindings/HostEntry';
import { formFromHost, type HostForm } from './model';
import { entryFollowUp, findHostEntry, hostAliases, hostEntryInput, isOtpSecret } from './vault';

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

  it('takes the entry made first, as the backend does, whatever the titles', () => {
    // As the vault lists them: by title.
    const entries = [
      entry({ id: 'b', title: '0 prod', created: '2026-11-13T10:00:00Z' }),
      entry({ id: 'a', title: 'Work prod', created: '2026-02-01T08:00:00Z' }),
    ];
    expect(findHostEntry(entries, ['prod'])?.entry.id).toBe('a');
    // One without a time is older still; the same time goes by id.
    const undated = entry({ id: 'z', title: 'Z', created: null });
    expect(findHostEntry([...entries, undated], ['prod'])?.entry.id).toBe('z');
    const tied = [
      entry({ id: 'y', created: '2026-01-01T00:00:00Z' }),
      entry({ id: 'x', created: '2026-01-01T00:00:00Z' }),
    ];
    expect(findHostEntry(tied, ['prod'])?.entry.id).toBe('x');
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

describe('entryFollowUp', () => {
  const saved = host({
    patterns: ['prod'],
    user: 'ubuntu',
    options: [{ key: 'User', value: 'ubuntu' }],
  });
  const found = { alias: 'prod', entry: entry({ id: 'e1', username: 'ubuntu' }) };
  const form = (patch: Partial<HostForm>): HostForm => ({
    ...formFromHost(saved, { passwordSaved: true }),
    ...patch,
  });

  it('does nothing without a saved password, for patterns, or when nothing it holds changed', () => {
    expect(entryFollowUp(form({ user: 'root' }), saved, undefined)).toEqual({ kind: 'none' });
    expect(entryFollowUp(form({ method: null }), saved, found)).toEqual({ kind: 'none' });
    expect(entryFollowUp(form({ port: '2222' }), saved, found)).toEqual({ kind: 'none' });
  });

  it('gives the entry the host’s new User, keeping the password', () => {
    expect(entryFollowUp(form({ user: ' root ' }), saved, found)).toEqual({
      kind: 'update',
      entryId: 'e1',
      username: 'root',
      alias: 'prod',
    });
    expect(entryFollowUp(form({ user: '', method: 'password' }), saved, found)).toMatchObject({
      kind: 'update',
      username: '',
    });
  });

  it('leaves an entry with another user name alone until the User changes', () => {
    const other = { alias: 'prod', entry: entry({ id: 'e1', username: 'deploy' }) };
    expect(entryFollowUp(form({ port: '2222' }), saved, other)).toEqual({ kind: 'none' });
    // Already the new user: nothing to write.
    expect(entryFollowUp(form({ user: 'deploy' }), saved, other)).toEqual({ kind: 'none' });
  });

  it('follows a renamed alias', () => {
    expect(entryFollowUp(form({ patterns: 'prod-1 *.prod' }), saved, found)).toEqual({
      kind: 'update',
      entryId: 'e1',
      username: 'ubuntu',
      alias: 'prod-1',
    });
    expect(entryFollowUp(form({ patterns: 'api prod' }), saved, found)).toEqual({ kind: 'none' });
  });

  it('moves the password to the recycle bin when the host signs in with a key alone', () => {
    expect(entryFollowUp(form({ method: 'key', user: 'root' }), saved, found)).toEqual({
      kind: 'trash',
      entryId: 'e1',
    });
  });
});
