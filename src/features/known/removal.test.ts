import { describe, expect, it } from 'vitest';
import type { KnownHostEntry } from '@/bindings/KnownHostEntry';
import { removalOf } from './removal';

const entry = (line: number, fingerprint: string, more: Partial<KnownHostEntry> = {}) =>
  ({
    line,
    marker: 'none',
    hosts: ['example.com'],
    hashed: false,
    keyType: 'ssh-ed25519',
    fingerprint,
    comment: null,
    ...more,
  }) satisfies KnownHostEntry;

describe('removalOf', () => {
  const view = {
    entries: [entry(1, 'SHA256:a'), entry(2, 'SHA256:b', { marker: 'revoked' })],
    invalid: [],
    revision: 'r1',
  };

  it('names the revision when every entry is still on its line', () => {
    expect(removalOf(view, [entry(1, 'SHA256:a')])).toEqual({ lines: [1], revision: 'r1' });
  });

  it('refuses when a line now holds something else', () => {
    // The check saw `a` on line 2, but line 2 is a revoked key now.
    expect(removalOf(view, [entry(2, 'SHA256:b')])).toBeNull();
    expect(removalOf(view, [entry(3, 'SHA256:a')])).toBeNull();
    expect(removalOf(view, [entry(1, 'SHA256:a', { hosts: ['other.example'] })])).toBeNull();
    expect(removalOf(view, [])).toBeNull();
  });
});
