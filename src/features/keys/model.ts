import type { KeyAlgorithm } from '@/bindings/KeyAlgorithm';
import type { KeyInfo } from '@/bindings/KeyInfo';
import type { Tone } from '@/components/ui/Tile';

export const hasPrivate = (key: KeyInfo) => key.privatePath !== null;

/** A private key anyone with a copy of the file can use. */
export const isPlain = (key: KeyInfo) =>
  hasPrivate(key) && key.encrypted === false && !key.hardware;

export const isProtected = (key: KeyInfo) =>
  hasPrivate(key) && (key.encrypted === true || key.hardware);

/** DSA, or RSA below the 3072-bit recommendation. */
export const isWeak = (key: Pick<KeyInfo, 'algorithm' | 'bits'>) =>
  key.algorithm === 'dsa' || (key.algorithm === 'rsa' && (key.bits ?? 0) < 3072);

/** Short label for the type badge: `ED25519`, `RSA 2048`, `ECDSA-SK`. */
export function algorithmBadge(key: Pick<KeyInfo, 'algorithm' | 'bits' | 'keyType'>): string {
  switch (key.algorithm) {
    case 'ed25519':
      return 'ED25519';
    case 'rsa':
      return key.bits ? `RSA ${key.bits}` : 'RSA';
    case 'ecdsaP256':
      return 'ECDSA P-256';
    case 'ecdsaP384':
      return 'ECDSA P-384';
    case 'ecdsaP521':
      return 'ECDSA P-521';
    case 'skEd25519':
      return 'ED25519-SK';
    case 'skEcdsaP256':
      return 'ECDSA-SK';
    case 'dsa':
      return 'DSA';
    case 'other':
      return key.keyType || '?';
  }
}

const ALGORITHMS: Record<string, KeyAlgorithm> = {
  'ssh-ed25519': 'ed25519',
  'ssh-rsa': 'rsa',
  'ecdsa-sha2-nistp256': 'ecdsaP256',
  'ecdsa-sha2-nistp384': 'ecdsaP384',
  'ecdsa-sha2-nistp521': 'ecdsaP521',
  'sk-ssh-ed25519@openssh.com': 'skEd25519',
  'sk-ecdsa-sha2-nistp256@openssh.com': 'skEcdsaP256',
  'ssh-dss': 'dsa',
};

/** The type badge for an OpenSSH key type such as `ssh-ed25519`, without a size. */
export function keyTypeBadge(keyType: string): string {
  return algorithmBadge({ algorithm: ALGORITHMS[keyType] ?? 'other', bits: null, keyType });
}

/** `Ed25519 · 256-bit` style description for the details panel. */
export function algorithmDescription(key: KeyInfo, bitsLabel: (bits: number) => string): string {
  const names: Record<KeyInfo['algorithm'], string> = {
    ed25519: 'Ed25519',
    rsa: 'RSA',
    ecdsaP256: 'ECDSA P-256',
    ecdsaP384: 'ECDSA P-384',
    ecdsaP521: 'ECDSA P-521',
    skEd25519: 'Ed25519 · FIDO2',
    skEcdsaP256: 'ECDSA P-256 · FIDO2',
    dsa: 'DSA',
    other: key.keyType,
  };
  const name = names[key.algorithm];
  return key.bits && !key.hardware ? `${name} · ${bitsLabel(key.bits)}` : name;
}

export function keyTone(key: KeyInfo): Tone {
  if (!hasPrivate(key)) return 'slate';
  if (key.hardware) return 'violet';
  if (key.algorithm === 'dsa') return 'rose';
  if (key.algorithm === 'rsa') return isWeak(key) ? 'amber' : 'slate';
  if (key.algorithm.startsWith('ecdsa')) return 'blue';
  return 'teal';
}

/** The file name of a key, used in messages. */
export const keyFileName = (key: KeyInfo) => key.name;

/** Suggests a free file name like `id_ed25519_2` for a new key. */
export function suggestFileName(base: string, taken: ReadonlySet<string>): string {
  if (!taken.has(base)) return base;
  for (let i = 2; ; i += 1) {
    const candidate = `${base}_${i}`;
    if (!taken.has(candidate)) return candidate;
  }
}

export const FILE_NAME_PATTERN = /^[A-Za-z0-9_-][A-Za-z0-9._-]*$/;

/**
 * A rough passphrase strength from 0 (too short) to 4 (strong): length plus
 * character variety. Good enough to nudge people away from short phrases.
 */
export function passphraseStrength(value: string): 0 | 1 | 2 | 3 | 4 {
  if (value.length < 8) return 0;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length;
  const score =
    (value.length >= 12 ? 1 : 0) + (value.length >= 20 ? 1 : 0) + Math.min(classes, 3) - 1;
  return Math.max(1, Math.min(4, score)) as 1 | 2 | 3 | 4;
}
