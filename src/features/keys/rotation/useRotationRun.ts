// Runs a rotation's steps against its hosts, one host and one step at a
// time, saving each outcome as it comes, so a closed app or a failed host
// leaves the rotation where it was.

import { useRef, useState } from 'react';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { KeyLoginCheck } from '@/bindings/KeyLoginCheck';
import type { ServerKeys } from '@/bindings/ServerKeys';
import type { ServerKeysAction } from '@/bindings/ServerKeysAction';
import { explain } from '@/features/hosts/login';
import { isConcrete } from '@/features/hosts/model';
import { displayPath } from '@/lib/format';
import { AppError } from '@/lib/ipc';
import { type HostProgress, namesKeyFile, nextStep, removalBlock, replaceKeyEdit } from './plan';
import { rotationOf, updateRotation, withHost } from './store';

export type HostStep = 'install' | 'verify' | 'config' | 'remove';

/** Why a host's last step failed; kept in memory until the next try. */
export type Failure =
  /** Signing in failed (installing or removing a key). */
  | { step: 'install' | 'remove'; kind: 'login'; run: ServerKeys }
  /** Signed in, but the server's shell could not change `authorized_keys`. */
  | { step: 'install' | 'remove'; kind: 'server'; output: string }
  /** The new key did not sign in. */
  | { step: 'verify'; kind: 'login'; run: KeyLoginCheck }
  /** Another key signed in: the server did not take the new one. */
  | { step: 'verify'; kind: 'otherKey'; run: KeyLoginCheck }
  /** The host's block is gone from the config. */
  | { step: 'config'; kind: 'hostGone' }
  /** A command failed outright. */
  | { step: HostStep; kind: 'error'; message: string };

interface RunOptions {
  oldKeyId: string;
  newKey: { id: string; privatePath: string | null } | undefined;
  home: string | undefined;
  /** Sign in with what the vault saved (host passwords, key passphrases). */
  withVault: boolean;
  /** The hosts that sign in with the old key in `file` (see `findCandidates`). */
  stillUsing: (file: ConfigFile) => ReadonlySet<string>;
  /** A failed command, in words. */
  describe: (cause: unknown) => string;
}

export function useRotationRun({
  oldKeyId,
  newKey,
  home,
  withVault,
  stillUsing,
  describe,
}: RunOptions) {
  const [active, setActive] = useState<{ alias: string; step: HostStep } | null>(null);
  const [failures, setFailures] = useState<Record<string, Failure>>({});
  const busy = useRef(false);

  const progressOf = (alias: string) =>
    rotationOf(oldKeyId)?.hosts.find((host) => host.alias === alias);
  const save = (alias: string, change: Partial<HostProgress>) =>
    updateRotation(oldKeyId, (rotation) => withHost(rotation, alias, change));
  const fail = (alias: string, failure: Failure, change: Partial<HostProgress>) => {
    setFailures((all) => ({ ...all, [alias]: failure }));
    save(alias, change);
    return false;
  };
  const serverKeys = (alias: string, action: ServerKeysAction) =>
    withVault ? api.vaultServerKeys(alias, action) : api.serverKeys(alias, action);

  /** Adds the new key, signing in as the host does now: with the old key. */
  async function install(alias: string, keyId: string): Promise<boolean> {
    try {
      const result = await serverKeys(alias, { type: 'add', keyId });
      if (!result.read)
        return fail(alias, { step: 'install', kind: 'login', run: result }, { install: 'failed' });
      if (!result.ok) {
        return fail(
          alias,
          { step: 'install', kind: 'server', output: result.output },
          { install: 'failed' },
        );
      }
      const fingerprint = rotationOf(oldKeyId)?.oldFingerprint;
      save(alias, {
        install: 'done',
        oldOnServer: fingerprint
          ? result.file.keys.some((k) => k.fingerprint === fingerprint)
          : null,
      });
      return true;
    } catch (cause) {
      return fail(
        alias,
        { step: 'install', kind: 'error', message: describe(cause) },
        { install: 'failed' },
      );
    }
  }

  /** Signs in offering the new key, and counts only a sign-in with it. */
  async function verify(alias: string, keyId: string): Promise<boolean> {
    try {
      const result = withVault
        ? await api.vaultCheckKeyLogin(alias, keyId)
        : await api.checkKeyLogin(alias, keyId);
      if (result.ok) {
        save(alias, { verify: 'done' });
        return true;
      }
      // A new key `ssh` could not open lets the old one in after it: say so,
      // with the fix, rather than that the server turned the new key down.
      const kind =
        result.otherKey && explain(result).kind !== 'passphraseMissing' ? 'otherKey' : 'login';
      return fail(alias, { step: 'verify', kind, run: result }, { verify: 'failed' });
    } catch (cause) {
      return fail(
        alias,
        { step: 'verify', kind: 'error', message: describe(cause) },
        { verify: 'failed' },
      );
    }
  }

  /**
   * Points the host's block at the new key, against the config as it is on
   * disk; a file changed in between is read again once.
   */
  async function config(alias: string, path: string | null): Promise<boolean> {
    const oldPath = rotationOf(oldKeyId)?.oldPath ?? null;
    for (let attempt = 0; ; attempt++) {
      try {
        const file = await api.config();
        const host = file.view.hosts.find((h) => isConcrete(h) && h.patterns[0] === alias);
        if (!host) return fail(alias, { step: 'config', kind: 'hostGone' }, { config: 'failed' });
        const { edit, changed } = replaceKeyEdit(
          host,
          {
            isOld: namesKeyFile(file, host.id, oldPath, home),
            isNew: namesKeyFile(file, host.id, path, home),
          },
          displayPath(path ?? '', home),
        );
        if (changed) await api.saveHost(edit, file.view.revision);
        save(alias, { config: 'done' });
        return true;
      } catch (cause) {
        if (AppError.from(cause).code === 'conflict' && attempt === 0) continue;
        return fail(
          alias,
          { step: 'config', kind: 'error', message: describe(cause) },
          { config: 'failed' },
        );
      }
    }
  }

  async function exclusive(work: () => Promise<void>) {
    if (busy.current) return;
    busy.current = true;
    try {
      await work();
    } finally {
      busy.current = false;
      setActive(null);
      void invalidateAll();
    }
  }

  /** Takes each host in turn as far as it goes: add the key, sign in with it, update the block. */
  const move = (aliases: readonly string[]) =>
    exclusive(async () => {
      if (!newKey) return;
      for (const alias of aliases) {
        setFailures(({ [alias]: _cleared, ...rest }) => rest);
        for (;;) {
          const progress = progressOf(alias);
          const step = progress ? nextStep(progress) : null;
          if (!step) break;
          setActive({ alias, step });
          const ok =
            step === 'install'
              ? await install(alias, newKey.id)
              : step === 'verify'
                ? await verify(alias, newKey.id)
                : await config(alias, newKey.privatePath);
          if (!ok) break;
        }
      }
    });

  /**
   * Takes the old key off each host's server, checking again first that
   * the new key signed in there and no alias of the same account still
   * needs the old one.
   */
  const removeOld = (aliases: readonly string[]) =>
    exclusive(async () => {
      for (const alias of aliases) {
        const rotation = rotationOf(oldKeyId);
        if (!rotation?.oldPublicKey) return;
        setFailures(({ [alias]: _cleared, ...rest }) => rest);
        setActive({ alias, step: 'remove' });
        try {
          const file = await api.config();
          const blocked = removalBlock(alias, {
            progress: rotation.hosts,
            hosts: file.view.hosts,
            stillUsing: stillUsing(file),
          });
          if (blocked) continue;
          const result = await serverKeys(alias, {
            type: 'remove',
            publicKey: rotation.oldPublicKey,
          });
          if (!result.read) {
            fail(alias, { step: 'remove', kind: 'login', run: result }, { removeOld: 'failed' });
          } else if (
            !result.ok ||
            // Read back after the change: a line that is still there counts as not removed.
            result.file.keys.some((key) => key.fingerprint === rotation.oldFingerprint)
          ) {
            fail(
              alias,
              { step: 'remove', kind: 'server', output: result.output },
              { removeOld: 'failed' },
            );
          } else {
            save(alias, { removeOld: 'done', oldOnServer: false });
          }
        } catch (cause) {
          fail(
            alias,
            { step: 'remove', kind: 'error', message: describe(cause) },
            { removeOld: 'failed' },
          );
        }
      }
    });

  /** The user added the key themselves (a git service's website): check it signs in. */
  const addedByHand = (alias: string) => {
    save(alias, { install: 'skipped' });
    return move([alias]);
  };

  /** Adds the key again, then checks it, after another key signed in. */
  const installAgain = (alias: string) => {
    save(alias, { install: 'pending', verify: 'pending' });
    return move([alias]);
  };

  return { active, failures, move, removeOld, addedByHand, installAgain };
}
