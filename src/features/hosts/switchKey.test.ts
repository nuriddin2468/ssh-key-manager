import { describe, expect, it } from 'vitest';
import type { KeyView } from '@/bindings/KeyView';
import { needsUnlock, preselectKey, usableKeys } from './switchKey';

function key(name: string, partial: Partial<KeyView> = {}): KeyView {
  return {
    id: `fp#${name}`,
    name,
    privatePath: `/home/dev/.ssh/${name}`,
    publicPath: `/home/dev/.ssh/${name}.pub`,
    algorithm: 'ed25519',
    keyType: 'ssh-ed25519',
    bits: 256,
    fingerprint: `SHA256:${name}`,
    comment: '',
    encrypted: true,
    hardware: false,
    format: 'openssh',
    publicKey: `ssh-ed25519 AAAA ${name}`,
    modified: '2026-01-01T00:00:00Z',
    pairMismatch: false,
    permissions: { ok: true, mode: '600', problem: null },
    inAgent: false,
    usedBy: [],
    ...partial,
  };
}

describe('usableKeys', () => {
  it('needs a private key and its public key', () => {
    const keys = [
      key('ok'),
      key('public_only', { privatePath: null, format: 'publicOnly' }),
      key('no_public', { publicKey: null }),
    ];
    expect(usableKeys(keys).map((k) => k.name)).toEqual(['ok']);
  });
});

describe('preselectKey', () => {
  it('prefers the key the host already names', () => {
    const keys = [
      key('in_agent', { inAgent: true }),
      key('named', { algorithm: 'rsa', usedBy: [{ hostId: 3, patterns: ['prod'] }] }),
    ];
    expect(preselectKey(keys, 3)?.name).toBe('named');
    expect(preselectKey(keys, 4)?.name).toBe('in_agent');
  });

  it('then prefers software Ed25519 keys and the newest', () => {
    const keys = [
      key('yubikey', { hardware: true, modified: '2026-09-01T00:00:00Z' }),
      key('rsa', { algorithm: 'rsa', modified: '2026-08-01T00:00:00Z' }),
      key('old', { modified: '2024-01-01T00:00:00Z' }),
      key('new', { modified: '2026-05-01T00:00:00Z' }),
    ];
    expect(preselectKey(keys, 0)?.name).toBe('new');
    expect(preselectKey(keys.slice(0, 2), 0)?.name).toBe('rsa');
  });

  it('skips keys that cannot sign in', () => {
    expect(preselectKey([key('pub', { privatePath: null, format: 'publicOnly' })], 0)).toBeNull();
    expect(preselectKey([], 0)).toBeNull();
  });
});

describe('needsUnlock', () => {
  it('is true only for a locked key ssh cannot unlock by itself', () => {
    expect(needsUnlock(key('k'), false)).toBe(true);
    expect(needsUnlock(key('k'), true)).toBe(false);
    expect(needsUnlock(key('k', { inAgent: true }), false)).toBe(false);
    expect(needsUnlock(key('k', { encrypted: false }), false)).toBe(false);
    expect(needsUnlock(key('k', { hardware: true }), false)).toBe(false);
  });
});
