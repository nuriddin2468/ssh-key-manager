import { QueryClient } from '@tanstack/react-query';
import { describe, expect, it } from 'vitest';
import { keys as queryKeys } from '@/api/queries';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntrySummary } from '@/bindings/EntrySummary';
import {
  findKeyEntry,
  keyEntryInput,
  rememberedSaved,
  savedFingerprints,
  watchKeyEntries,
} from './vaultKey';

function entry(partial: Partial<EntrySummary>): EntrySummary {
  return {
    id: crypto.randomUUID(),
    title: 'id_ed25519',
    username: '',
    url: '',
    kind: 'key',
    host: null,
    keyFingerprint: 'SHA256:a',
    hasPassword: true,
    hasOtp: false,
    group: null,
    inTrash: false,
    created: '2026-01-01T00:00:00Z',
    modified: '2026-01-01T00:00:00Z',
    ...partial,
  };
}

describe('findKeyEntry', () => {
  it('finds the key entry with a password for the fingerprint', () => {
    const wanted = entry({});
    const entries = [
      entry({ keyFingerprint: 'SHA256:b' }),
      entry({ kind: 'login', keyFingerprint: null }),
      entry({ inTrash: true, modified: '2026-12-01T00:00:00Z' }),
      entry({ hasPassword: false, modified: '2026-12-01T00:00:00Z' }),
      wanted,
    ];
    expect(findKeyEntry(entries, 'SHA256:a')).toBe(wanted);
    expect(findKeyEntry(entries, 'SHA256:c')).toBeUndefined();
    expect(findKeyEntry(entries, null)).toBeUndefined();
    expect(findKeyEntry(undefined, 'SHA256:a')).toBeUndefined();
  });

  it('prefers the most recently changed entry, like the backend', () => {
    const older = entry({ modified: '2026-03-01T00:00:00Z' });
    const newer = entry({ modified: '2026-09-01T00:00:00Z' });
    expect(findKeyEntry([older, newer], 'SHA256:a')).toBe(newer);
    expect(findKeyEntry([newer, older], 'SHA256:a')).toBe(newer);
  });
});

describe('savedFingerprints', () => {
  it('lists keys with a usable saved passphrase', () => {
    const entries = [
      entry({}),
      entry({ keyFingerprint: 'SHA256:b', inTrash: true }),
      entry({ keyFingerprint: 'SHA256:c', hasPassword: false }),
      entry({ kind: 'host', host: 'prod', keyFingerprint: null }),
    ];
    expect([...savedFingerprints(entries)]).toEqual(['SHA256:a']);
  });
});

describe('keyEntryInput', () => {
  const key = { name: 'id_ed25519', fingerprint: 'SHA256:a' };

  it('names a new entry after the key', () => {
    expect(keyEntryInput(key, 'Tundra-Velvet-Rocket-Mango7')).toEqual({
      title: 'id_ed25519',
      username: '',
      url: '',
      notes: '',
      password: 'Tundra-Velvet-Rocket-Mango7',
      otp: null,
      kind: 'key',
      host: null,
      keyFingerprint: 'SHA256:a',
    });
  });

  it('keeps what the user wrote in an existing entry', () => {
    const current = {
      ...entry({ title: 'Laptop key', username: 'me' }),
      notes: 'Rotated yearly',
      passwordChanged: null,
      historyLen: 1,
    } satisfies EntryDetail;
    const input = keyEntryInput(key, 'new', current);
    expect(input).toMatchObject({ title: 'Laptop key', username: 'me', notes: 'Rotated yearly' });
    expect(input.password).toBe('new');
    expect(input.otp).toBeNull();
  });
});

describe('watchKeyEntries', () => {
  it('remembers saved keys from every load of the entries until the vault is gone', () => {
    const client = new QueryClient();
    const stop = watchKeyEntries(client);
    client.setQueryData(queryKeys.vaultEntries, [entry({ keyFingerprint: 'SHA256:z' })]);
    expect(rememberedSaved('SHA256:z')).toBe(true);
    expect(rememberedSaved('SHA256:y')).toBe(false);
    expect(localStorage.getItem('sshkm.vaultKeys')).toContain('SHA256:z');

    client.setQueryData(queryKeys.vaultStatus, { state: 'missing' });
    expect(rememberedSaved('SHA256:z')).toBe(false);
    expect(localStorage.getItem('sshkm.vaultKeys')).toBeNull();
    stop();
  });
});
