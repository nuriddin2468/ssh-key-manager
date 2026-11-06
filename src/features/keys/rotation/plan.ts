// Planning a key rotation: which hosts use the old key, the order to move
// them in, how each host's block changes, and when the old key may go from a
// server and from this computer. Pure functions; the wizard runs the steps.

import type { ConfigFile } from '@/bindings/ConfigFile';
import type { ConnectionEvent } from '@/bindings/ConnectionEvent';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import { formFromHost, isConcrete, pointHostAtKey } from '@/features/hosts/model';
import { displayPath } from '@/lib/format';

/** Why a host is thought to sign in with the old key. */
export type UseReason =
  /** Its own block names the key in `IdentityFile`. */
  | 'config'
  /** A pattern block (`Host *.corp`) or the global section names it. */
  | 'pattern'
  /**
   * No `IdentityFile` applies to it, so `ssh` offers its default key files,
   * this one among them, and the history says it has signed in.
   */
  | 'default';

export interface Candidate {
  hostId: number;
  /** The name `ssh` is run with: the block's first pattern. */
  alias: string;
  reason: UseReason;
  /** `PubkeyAuthentication no`: it signs in with a password, and offers no key. */
  passwordOnly: boolean;
  /** Ticked at first: the key is sure to be offered, and keys are used. */
  suggested: boolean;
  /** The host it is reached through (`ProxyJump`), as written. */
  via: string | null;
  /** When a check or session last signed in, from the connection history. */
  lastSignedIn: string | null;
}

/** The key files `ssh` tries when no `IdentityFile` applies (OpenSSH 9). */
const DEFAULT_KEY_FILES = [
  'id_rsa',
  'id_ecdsa',
  'id_ecdsa_sk',
  'id_ed25519',
  'id_ed25519_sk',
  'id_xmss',
  'id_dsa',
];

/** Whether `ssh` tries `path` on its own: one of the default files in `~/.ssh`. */
export function isDefaultKeyFile(path: string | null, sshDir: string): boolean {
  if (!path) return false;
  const dir = sshDir.replace(/[\\/]+$/, '');
  const rest = path.startsWith(dir) ? path.slice(dir.length) : '';
  return /^[\\/]/.test(rest) && DEFAULT_KEY_FILES.includes(rest.slice(1));
}

/**
 * Whether a `Host` line's patterns take `alias`, as `ssh` matches them: one
 * pattern (`*` and `?` as wildcards, case-insensitive) matches and no negated
 * one (`!pattern`) does.
 */
export function hostMatches(patterns: readonly string[], alias: string): boolean {
  const name = alias.toLowerCase();
  let matched = false;
  for (const pattern of patterns) {
    const negated = pattern.startsWith('!');
    if (!wildcardMatch(negated ? pattern.slice(1) : pattern, name)) continue;
    if (negated) return false;
    matched = true;
  }
  return matched;
}

function wildcardMatch(pattern: string, name: string): boolean {
  const source = [...pattern.toLowerCase()]
    .map((c) => (c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[.+^${}()|[\]\\]/g, '\\$&')))
    .join('');
  return new RegExp(`^${source}$`).test(name);
}

/** The newest event that signed in, if any. */
function lastSignedIn(events: readonly ConnectionEvent[] | undefined): string | null {
  return events?.find((event) => event.outcome === 'signedIn')?.at ?? null;
}

export interface CandidateInput {
  key: Pick<KeyView, 'privatePath'>;
  config: Pick<ConfigFile, 'view' | 'usage'>;
  history: Readonly<Record<string, readonly ConnectionEvent[]>>;
  /** `~/.ssh`, where the default key files are. */
  sshDir: string;
}

/**
 * Every concrete host (a `Host` without wildcards) that signs in with the
 * key, in config order:
 * - its own block names the key, or a pattern block or the global section
 *   that applies to it does; both are suggested unless the host signs in with
 *   a password alone;
 * - or the key is one of `ssh`'s default files, no `IdentityFile` applies to
 *   the host, and it has signed in before: likely, but not certain, so it is
 *   not suggested.
 */
export function findCandidates({ key, config, history, sshDir }: CandidateInput): Candidate[] {
  const path = key.privatePath;
  if (!path) return [];
  const blocks = config.view.hosts;
  const byId = new Map(blocks.map((block) => [block.id, block]));
  // Pattern blocks and the global section apply to every host they match.
  const applies = (hostId: number | null, alias: string) => {
    if (hostId === null) return true;
    const block = byId.get(hostId);
    return block?.kind === 'host' && block.isWildcard && hostMatches(block.patterns, alias);
  };
  const isDefault = isDefaultKeyFile(path, sshDir);
  const result: Candidate[] = [];
  for (const host of blocks) {
    if (!isConcrete(host)) continue;
    const alias = host.patterns[0];
    if (!alias) continue;
    const own = config.usage.filter((usage) => usage.hostId === host.id);
    const shared = config.usage.filter(
      (usage) => usage.hostId !== host.id && applies(usage.hostId, alias),
    );
    const signedIn = lastSignedIn(history[alias]);
    let reason: UseReason | null = null;
    if (own.some((usage) => usage.path === path)) reason = 'config';
    else if (shared.some((usage) => usage.path === path)) reason = 'pattern';
    else if (isDefault && own.length === 0 && shared.length === 0 && signedIn) reason = 'default';
    if (reason === null) continue;
    const passwordOnly = formFromHost(host).method === 'password';
    result.push({
      hostId: host.id,
      alias,
      reason,
      passwordOnly,
      suggested: reason !== 'default' && !passwordOnly,
      via: host.proxyJump,
      lastSignedIn: signedIn,
    });
  }
  return result;
}

/** The first host a `ProxyJump` value goes through: `user@bastion:2222,next` → `bastion`. */
export function jumpHost(proxyJump: string | null): string | null {
  if (!proxyJump || proxyJump.toLowerCase() === 'none') return null;
  const last = proxyJump.split(',').pop()?.trim() ?? '';
  const host = last.replace(/^ssh:\/\//, '').replace(/^.*@/, '');
  const name = host.startsWith('[') ? host.slice(1, host.indexOf(']')) : host.split(':')[0];
  return name || null;
}

/**
 * The order to move hosts in: a host after the host it jumps through, when
 * both are moving, so a jump host that cannot be reached fails first and the
 * hosts behind it are seen to fail with it. Otherwise the given order.
 */
export function rotationOrder<T extends { alias: string; via: string | null }>(hosts: T[]): T[] {
  const byAlias = new Map(hosts.map((host) => [host.alias, host]));
  const depth = (host: T): number => {
    let count = 0;
    const seen = new Set([host.alias]);
    let next = byAlias.get(jumpHost(host.via) ?? '');
    while (next && !seen.has(next.alias)) {
      seen.add(next.alias);
      count += 1;
      next = byAlias.get(jumpHost(next.via) ?? '');
    }
    return count;
  };
  return hosts
    .map((host, index) => ({ host, index, depth: depth(host) }))
    .sort((a, b) => a.depth - b.depth || a.index - b.index)
    .map(({ host }) => host);
}

/**
 * The edit that moves `host` from the old key to `newFile`:
 * - each `IdentityFile` that names the old key (`isOld` knows its
 *   spellings) gives way: the first becomes `newFile` where it stands, the
 *   others go, and all of them go if the block lists the new key already;
 * - a block that names neither gets `newFile` as its first `IdentityFile`,
 *   as the host editor would write it.
 *
 * Every other line stays as it is, `IdentitiesOnly` included.
 */
export function replaceKeyEdit(
  host: HostEntry,
  { isOld, isNew }: { isOld: (raw: string) => boolean; isNew: (raw: string) => boolean },
  newFile: string,
): { edit: HostEdit; changed: boolean } {
  const isIdentity = (key: string) => key.toLowerCase() === 'identityfile';
  const named = host.options.filter((option) => isIdentity(option.key));
  const hasNew = named.some((option) => isNew(option.value));
  if (!named.some((option) => isOld(option.value))) {
    if (hasNew) {
      return {
        edit: { id: host.id, patterns: host.patterns, options: host.options },
        changed: false,
      };
    }
    return pointHostAtKey(host, newFile, { identitiesOnly: false, isKey: isNew });
  }
  let placed = hasNew;
  const options = host.options.flatMap((option) => {
    if (!isIdentity(option.key) || !isOld(option.value)) return [option];
    if (placed) return [];
    placed = true;
    return [{ key: option.key, value: newFile }];
  });
  return { edit: { id: host.id, patterns: host.patterns, options }, changed: true };
}

/**
 * Whether an `IdentityFile` value of the block `hostId` names the key file
 * at `path`: as the config's usage resolved it, or written as the path
 * itself or as `~/…`.
 */
export function namesKeyFile(
  config: Pick<ConfigFile, 'usage'>,
  hostId: number,
  path: string | null,
  home: string | undefined,
): (raw: string) => boolean {
  if (!path) return () => false;
  const written = new Set(
    config.usage
      .filter((usage) => usage.hostId === hostId && usage.path === path)
      .map((usage) => usage.raw),
  );
  const shown = displayPath(path, home);
  return (raw) => written.has(raw) || raw === path || raw === shown;
}

/** Where a host's `authorized_keys` lives, as far as the config says. */
export interface ServerAccount {
  /** `HostName`, else the alias; lower case. */
  host: string;
  port: number;
  /** `User`; `null` signs in as the local user. */
  user: string | null;
}

export function serverAccount(host: HostEntry): ServerAccount {
  return {
    host: (host.hostName ?? host.patterns[0] ?? '').toLowerCase(),
    port: host.port ?? 22,
    user: host.user,
  };
}

/**
 * Two aliases may reach one `authorized_keys`: the same server and port,
 * and the same account, or one whose account is not written (it could be
 * the same).
 */
export function sameAccount(a: ServerAccount, b: ServerAccount): boolean {
  return a.host === b.host && a.port === b.port && (a.user === b.user || !a.user || !b.user);
}

/** How far a host has come; persisted, so a rotation can go on later. */
export type StepState = 'pending' | 'done' | 'failed' | 'skipped';

export interface HostProgress {
  alias: string;
  /** Adding the new key; `skipped`: the user added it themselves (a git service's website). */
  install: StepState;
  /** Signing in with the new key alone. */
  verify: StepState;
  /** Pointing the host's block at the new key. */
  config: StepState;
  /** Taking the old key off the server; `skipped`: the user kept it there. */
  removeOld: StepState;
  /** The server's `authorized_keys` had the old key when it was read; `null`: not read. */
  oldOnServer: boolean | null;
}

export const newProgress = (alias: string): HostProgress => ({
  alias,
  install: 'pending',
  verify: 'pending',
  config: 'pending',
  removeOld: 'pending',
  oldOnServer: null,
});

/** The new key works on the host and its block names it: the host no longer needs the old key. */
export const moved = (progress: HostProgress) =>
  progress.verify === 'done' && progress.config === 'done';

/** What is left to do for a host, in order; `null` once it has moved. */
export function nextStep(progress: HostProgress): 'install' | 'verify' | 'config' | null {
  if (progress.install !== 'done' && progress.install !== 'skipped') return 'install';
  if (progress.verify !== 'done') return 'verify';
  if (progress.config !== 'done') return 'config';
  return null;
}

/** Something that still signs in with the old key. */
export type OldKeyNeed =
  /** A host in the rotation that has not moved yet. */
  | { kind: 'notMoved'; alias: string }
  /** A block that names the old key (a host left out, a pattern, the global section). */
  | { kind: 'config'; hostId: number | null; patterns: string[] };

export interface NeedsInput {
  progress: readonly HostProgress[];
  /** The old key, as the key list sees it now: `usedBy` is every block that names it. */
  oldKey: Pick<KeyView, 'usedBy'>;
}

/** Everything that still needs the old key; it may go to the trash once there is nothing. */
export function oldKeyNeeds({ progress, oldKey }: NeedsInput): OldKeyNeed[] {
  const needs: OldKeyNeed[] = progress
    .filter((host) => !moved(host))
    .map((host) => ({ kind: 'notMoved', alias: host.alias }));
  const waiting = new Set(needs.map((need) => (need.kind === 'notMoved' ? need.alias : '')));
  for (const usage of oldKey.usedBy) {
    // A host not moved yet is listed once, as such.
    if (usage.patterns.length === 1 && waiting.has(usage.patterns[0] ?? '')) continue;
    needs.push({ kind: 'config', hostId: usage.hostId, patterns: usage.patterns });
  }
  return needs;
}

/** Why the old key cannot be taken off a host's server now. */
export type RemovalBlock =
  /** The new key has not signed in there, or the block still names the old key. */
  | { kind: 'notMoved' }
  /** The key was added by hand (a git service): it is removed the same way. */
  | { kind: 'manual' }
  /** The old key was not in the server's `authorized_keys`. */
  | { kind: 'notOnServer' }
  /** Another alias reaches the same account and still needs the old key. */
  | { kind: 'sharedAccount'; alias: string };

export interface RemovalInput {
  progress: readonly HostProgress[];
  /** Every block of the config as it is now. */
  hosts: readonly HostEntry[];
  /**
   * Aliases of the hosts that sign in with the old key as the config is
   * now (`findCandidates`); hosts in `progress` go by their progress.
   */
  stillUsing: ReadonlySet<string>;
}

/**
 * Whether the old key may come off `alias`'s server: only once the new key
 * has signed in there and the block names it, and only when no other alias
 * that reaches the same account still signs in with the old key (one not
 * moved yet, or one left out).
 */
export function removalBlock(alias: string, input: RemovalInput): RemovalBlock | null {
  const progress = input.progress.find((host) => host.alias === alias);
  if (!progress || !moved(progress)) return { kind: 'notMoved' };
  if (progress.install === 'skipped') return { kind: 'manual' };
  if (progress.oldOnServer === false) return { kind: 'notOnServer' };
  const block = input.hosts.find((host) => isConcrete(host) && host.patterns[0] === alias);
  if (!block) return { kind: 'notMoved' };
  const account = serverAccount(block);
  for (const other of input.hosts) {
    const otherAlias = other.patterns[0];
    if (!isConcrete(other) || !otherAlias || otherAlias === alias) continue;
    if (!sameAccount(account, serverAccount(other))) continue;
    const otherProgress = input.progress.find((host) => host.alias === otherAlias);
    const needs = otherProgress ? !moved(otherProgress) : input.stillUsing.has(otherAlias);
    if (needs) return { kind: 'sharedAccount', alias: otherAlias };
  }
  return null;
}
