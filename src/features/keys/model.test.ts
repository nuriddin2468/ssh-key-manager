import { describe, expect, it } from 'vitest';
import type { KeyInfo } from '@/bindings/KeyInfo';
import {
  algorithmBadge,
  FILE_NAME_PATTERN,
  isPlain,
  isWeak,
  keyTone,
  keyTypeBadge,
  passphraseLabel,
  passphraseStrength,
  suggestFileName,
} from './model';

function key(partial: Partial<KeyInfo>): KeyInfo {
  return {
    id: 'SHA256:x#id_ed25519',
    name: 'id_ed25519',
    privatePath: '/home/dev/.ssh/id_ed25519',
    publicPath: '/home/dev/.ssh/id_ed25519.pub',
    algorithm: 'ed25519',
    keyType: 'ssh-ed25519',
    bits: 256,
    fingerprint: 'SHA256:x',
    comment: '',
    encrypted: true,
    hardware: false,
    format: 'openssh',
    publicKey: null,
    modified: null,
    pairMismatch: false,
    permissions: { ok: true, mode: '600', problem: null },
    ...partial,
  };
}

describe('key classification', () => {
  it('flags short RSA and DSA as weak', () => {
    expect(isWeak(key({ algorithm: 'rsa', bits: 2048 }))).toBe(true);
    expect(isWeak(key({ algorithm: 'rsa', bits: 4096 }))).toBe(false);
    expect(isWeak(key({ algorithm: 'dsa', bits: 1024 }))).toBe(true);
    expect(isWeak(key({}))).toBe(false);
  });

  it('treats hardware and public-only keys as not plain', () => {
    expect(isPlain(key({ encrypted: false }))).toBe(true);
    expect(isPlain(key({ encrypted: false, hardware: true }))).toBe(false);
    expect(isPlain(key({ privatePath: null, encrypted: null }))).toBe(false);
  });

  it('labels and colours keys by algorithm', () => {
    expect(algorithmBadge(key({ algorithm: 'rsa', bits: 3072 }))).toBe('RSA 3072');
    expect(algorithmBadge(key({ algorithm: 'skEcdsaP256' }))).toBe('ECDSA-SK');
    expect(keyTypeBadge('ssh-ed25519')).toBe('ED25519');
    expect(keyTypeBadge('ssh-rsa')).toBe('RSA');
    expect(keyTypeBadge('sk-ssh-ed25519@openssh.com')).toBe('ED25519-SK');
    expect(keyTypeBadge('ssh-xyz')).toBe('ssh-xyz');
    expect(keyTone(key({ algorithm: 'rsa', bits: 2048 }))).toBe('amber');
    expect(keyTone(key({ hardware: true, algorithm: 'skEd25519' }))).toBe('violet');
    expect(keyTone(key({ privatePath: null }))).toBe('slate');
  });
});

describe('suggestFileName', () => {
  it('appends the first free number', () => {
    expect(suggestFileName('id_ed25519', new Set())).toBe('id_ed25519');
    expect(suggestFileName('id_ed25519', new Set(['id_ed25519', 'id_ed25519_2']))).toBe(
      'id_ed25519_3',
    );
  });
});

describe('FILE_NAME_PATTERN', () => {
  it.each(['id_ed25519', 'work.key', 'deploy-ci'])('accepts %s', (name) => {
    expect(FILE_NAME_PATTERN.test(name)).toBe(true);
  });
  it.each(['.hidden', 'a/b', 'with space', ''])('rejects %j', (name) => {
    expect(FILE_NAME_PATTERN.test(name)).toBe(false);
  });
});

describe('passphraseStrength', () => {
  it('grows with length and variety', () => {
    expect(passphraseStrength('short')).toBe(0);
    expect(passphraseStrength('abcdefgh')).toBe(1);
    expect(passphraseStrength('tandem-orbit-cactus-violet')).toBeGreaterThanOrEqual(3);
    expect(passphraseStrength('Tandem-Orbit-Cactus-7')).toBe(4);
  });
});

describe('passphraseLabel', () => {
  it('names how the private half is protected', () => {
    expect(passphraseLabel(key({}))).toBe('keys.passProtected');
    expect(passphraseLabel(key({ encrypted: false }))).toBe('keys.passNone');
    expect(passphraseLabel(key({ hardware: true, encrypted: false }))).toBe('keys.passHardware');
    expect(passphraseLabel(key({ privatePath: null }))).toBeNull();
  });
});
