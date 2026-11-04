import { describe, expect, it } from 'vitest';
import type { AgentIdentityView } from '@/bindings/AgentIdentityView';
import type { AuthorizedKey } from '@/bindings/AuthorizedKey';
import type { KeyView } from '@/bindings/KeyView';
import {
  addableKeys,
  entryName,
  entryTone,
  expiry,
  letsIn,
  type OwnKeys,
  ownKeyName,
  removalLocksOut,
} from './serverKeys';

function entry(name: string, partial: Partial<AuthorizedKey> = {}): AuthorizedKey {
  return {
    line: 1,
    algorithm: 'ed25519',
    keyType: 'ssh-ed25519',
    bits: 256,
    fingerprint: `SHA256:${name}`,
    comment: name,
    publicKey: `ssh-ed25519 AAAA${name}`,
    expires: null,
    certAuthority: false,
    options: [],
    ...partial,
  };
}

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
    encrypted: false,
    hardware: false,
    format: 'openssh',
    publicKey: `ssh-ed25519 AAAA${name}`,
    modified: null,
    pairMismatch: false,
    permissions: { ok: true, mode: '600', problem: null },
    inAgent: false,
    usedBy: [],
    ...partial,
  };
}

function loaded(name: string, comment = ''): AgentIdentityView {
  return {
    keyId: null,
    expiresAt: null,
    fingerprint: `SHA256:${name}`,
    algorithm: 'ed25519',
    keyType: 'ssh-ed25519',
    bits: 256,
    comment,
    publicKey: `ssh-ed25519 AAAA${name}`,
    certificate: false,
  };
}

const NOW = new Date('2026-11-04T12:00:00');

describe('ownKeyName', () => {
  it('names a key in ~/.ssh, then one in the agent', () => {
    const own: OwnKeys = {
      keys: [key('id_ed25519'), key('public_only', { privatePath: null, format: 'publicOnly' })],
      agent: [loaded('yubikey', 'YubiKey 5C'), loaded('nameless')],
    };
    expect(ownKeyName(entry('id_ed25519'), own)).toBe('id_ed25519');
    expect(ownKeyName(entry('yubikey'), own)).toBe('YubiKey 5C');
    expect(ownKeyName(entry('nameless'), own)).toBe('SHA256:nameless');
    // Only a public key here: it cannot sign in from this computer.
    expect(ownKeyName(entry('public_only'), own)).toBeNull();
    expect(ownKeyName(entry('colleague'), own)).toBeNull();
  });
});

describe('entryName', () => {
  it('is the comment, else a short fingerprint', () => {
    expect(entryName(entry('alice@laptop'))).toBe('alice@laptop');
    const nameless = entry('x', {
      comment: '',
      fingerprint: 'SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw',
    });
    expect(entryName(nameless)).toBe('SHA256:k3XbV9qL2…KjBnHw');
  });
});

describe('expiry', () => {
  it('reads local and UTC times and says whether they have passed', () => {
    expect(expiry(entry('a'), NOW)).toBeNull();
    const later = expiry(entry('a', { expires: '2026-12-01T00:00:00' }), NOW);
    expect(later?.expired).toBe(false);
    expect(later?.date.getMonth()).toBe(11);
    expect(expiry(entry('a', { expires: '2026-11-01T00:00:00Z' }), NOW)?.expired).toBe(true);
    expect(expiry(entry('a', { expires: 'soon' }), NOW)).toBeNull();
  });

  it('keeps expired keys and certificate authorities from counting as a way in', () => {
    expect(letsIn(entry('a'), NOW)).toBe(true);
    expect(letsIn(entry('a', { expires: '2026-11-01T00:00:00' }), NOW)).toBe(false);
    expect(letsIn(entry('a', { certAuthority: true }), NOW)).toBe(false);
  });
});

describe('removalLocksOut', () => {
  const own: OwnKeys = { keys: [key('laptop'), key('spare')], agent: [] };

  it('never stops removing someone else’s key', () => {
    expect(removalLocksOut(entry('colleague'), [entry('colleague')], own, false, NOW)).toBe(false);
  });

  it('stops removing this computer’s last way in', () => {
    const entries = [entry('laptop'), entry('colleague')];
    expect(removalLocksOut(entry('laptop'), entries, own, false, NOW)).toBe(true);
    // A saved password still lets it in.
    expect(removalLocksOut(entry('laptop'), entries, own, true, NOW)).toBe(false);
  });

  it('allows it while another key of this computer’s still lets it in', () => {
    const entries = [entry('laptop'), entry('spare')];
    expect(removalLocksOut(entry('laptop'), entries, own, false, NOW)).toBe(false);
    const expired = [entry('laptop'), entry('spare', { expires: '2026-11-01T00:00:00' })];
    expect(removalLocksOut(entry('laptop'), expired, own, false, NOW)).toBe(true);
    // The same key on another line goes too.
    const twice = [entry('laptop'), entry('laptop', { line: 2, options: ['no-pty'] })];
    expect(removalLocksOut(entry('laptop'), twice, own, false, NOW)).toBe(true);
  });
});

describe('addableKeys', () => {
  it('offers usable keys that are not on the server yet', () => {
    const keys = [key('laptop'), key('spare'), key('public_only', { privatePath: null })];
    expect(addableKeys(keys, [entry('laptop')]).map((k) => k.name)).toEqual(['spare']);
  });
});

describe('entryTone', () => {
  it('colours keys as the key list does', () => {
    expect(entryTone(entry('a'))).toBe('teal');
    expect(entryTone(entry('a', { algorithm: 'rsa', bits: 2048 }))).toBe('amber');
    expect(entryTone(entry('a', { algorithm: 'rsa', bits: 4096 }))).toBe('slate');
    expect(entryTone(entry('a', { algorithm: 'skEd25519' }))).toBe('violet');
    expect(entryTone(entry('a', { algorithm: 'ecdsaP256' }))).toBe('blue');
  });
});
