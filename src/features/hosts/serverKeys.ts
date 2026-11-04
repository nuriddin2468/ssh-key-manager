// The keys in a server's `authorized_keys` as the "Keys on the server" dialog
// shows them: which are this computer's, when they stop working, and whether
// removing one would lock this computer out.

import type { AgentIdentityView } from '@/bindings/AgentIdentityView';
import type { AuthorizedKey } from '@/bindings/AuthorizedKey';
import type { KeyView } from '@/bindings/KeyView';
import type { Tone } from '@/components/ui/Tile';
import { isWeak } from '@/features/keys/model';
import { shortFingerprint } from '@/lib/format';
import { usableKeys } from './switchKey';

/** Keys this computer signs in with: in `~/.ssh` with a private key, or in the agent. */
export interface OwnKeys {
  keys: readonly KeyView[];
  agent: readonly AgentIdentityView[];
}

/** The name of this computer's key that `entry` lets in, or `null` if it is someone else's. */
export function ownKeyName(entry: AuthorizedKey, own: OwnKeys): string | null {
  const file = usableKeys(own.keys).find((key) => key.fingerprint === entry.fingerprint);
  if (file) return file.name;
  const loaded = own.agent.find((identity) => identity.fingerprint === entry.fingerprint);
  if (loaded) return loaded.comment || shortFingerprint(loaded.fingerprint);
  return null;
}

/** How the entry is named in messages: its comment, else its fingerprint. */
export function entryName(entry: AuthorizedKey): string {
  return entry.comment || shortFingerprint(entry.fingerprint);
}

/** When `entry` stops letting anyone in, and whether that has happened. */
export function expiry(
  entry: AuthorizedKey,
  now = new Date(),
): { date: Date; expired: boolean } | null {
  if (!entry.expires) return null;
  // Without a `Z` it is the server's local time; the viewer's is close enough.
  const date = new Date(entry.expires);
  if (Number.isNaN(date.getTime())) return null;
  return { date, expired: date.getTime() <= now.getTime() };
}

/** The entry signs in by itself: not a certificate authority, and not expired. */
export function letsIn(entry: AuthorizedKey, now = new Date()): boolean {
  return !entry.certAuthority && !expiry(entry, now)?.expired;
}

/**
 * Removing `entry` would leave this computer no way in: it is this
 * computer's key, no other key of this computer's is on the server, and no
 * password for the host is saved.
 */
export function removalLocksOut(
  entry: AuthorizedKey,
  entries: readonly AuthorizedKey[],
  own: OwnKeys,
  passwordSaved: boolean,
  now = new Date(),
): boolean {
  if (passwordSaved || ownKeyName(entry, own) === null) return false;
  return !entries.some(
    (other) =>
      other.publicKey !== entry.publicKey && letsIn(other, now) && ownKeyName(other, own) !== null,
  );
}

/** Keys this computer could add: usable here, and not on the server yet. */
export function addableKeys(
  keys: readonly KeyView[],
  entries: readonly AuthorizedKey[],
): KeyView[] {
  const present = new Set(entries.map((entry) => entry.fingerprint));
  return usableKeys(keys).filter((key) => key.fingerprint && !present.has(key.fingerprint));
}

/** The icon tile tone, as the key list colours the same family. */
export function entryTone(entry: AuthorizedKey): Tone {
  if (entry.algorithm === 'skEd25519' || entry.algorithm === 'skEcdsaP256') return 'violet';
  if (entry.algorithm === 'dsa') return 'rose';
  if (entry.algorithm === 'rsa') return isWeak(entry) ? 'amber' : 'slate';
  if (entry.algorithm.startsWith('ecdsa')) return 'blue';
  if (entry.algorithm === 'other') return 'slate';
  return 'teal';
}
