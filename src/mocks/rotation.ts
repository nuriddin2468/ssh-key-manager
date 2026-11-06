// Mock key rotation for `pnpm dev` (see backend.ts): three servers that still
// let the user in with the old `~/.ssh/id_rsa`, each with its own
// `authorized_keys` in memory, and `check_key_login`, which signs in with a
// key only where the server takes it.
//
// - `backup` takes the new key;
// - `media` adds it to `~/.ssh/authorized_keys`, but its sshd reads keys
//   from elsewhere, so the check gets in with the old key instead;
// - `router` names no key, so ssh offers `id_rsa` by default, and the
//   history says it signed in.
//
// Every other host goes to the `server_keys` mock as before.

import type { AskedPrompt } from '@/bindings/AskedPrompt';
import type { AuthorizedKey } from '@/bindings/AuthorizedKey';
import type { HostOption } from '@/bindings/HostOption';
import type { KeyLoginCheck } from '@/bindings/KeyLoginCheck';
import type { KeyView } from '@/bindings/KeyView';
import type { ServerKeys } from '@/bindings/ServerKeys';
import type { ServerKeysAction } from '@/bindings/ServerKeysAction';
import { recordCheck } from './history';
import { serverKeysHandlers } from './serverKeys';
import { vaultKeyTest } from './vault';

const opt = (key: string, value: string): HostOption => ({ key, value });

/** Host blocks of the demo servers, for the mock config. */
export const ROTATION_HOSTS: { patterns: string[]; options: HostOption[] }[] = [
  {
    patterns: ['backup'],
    options: [
      opt('HostName', 'backup.example.net'),
      opt('User', 'backup'),
      opt('IdentityFile', '~/.ssh/id_rsa'),
    ],
  },
  {
    patterns: ['media'],
    options: [
      opt('HostName', '192.168.1.40'),
      opt('User', 'pi'),
      opt('IdentityFile', '~/.ssh/id_rsa'),
    ],
  },
  { patterns: ['router'], options: [opt('HostName', '192.168.1.1'), opt('User', 'admin')] },
];

/** `id_rsa` in the mock key list. */
const OLD_KEY = 'SHA256:u9Fh2KdL7pQ3zX8mV1bN6rT4wY0sGcJ5aE2iOkHjUyB';
const SOMEONE_ELSE = 'SHA256:Ty7Ui1Op5As9Df3Gh7Jk1Lz5Xc9Vb3Nm7Qw1Er5Ty9Ui3';

interface Server {
  user: string;
  fingerprints: string[];
  /** sshd reads `authorized_keys` from another place: what is added there never signs in. */
  readsElsewhere?: boolean;
}

type Login = (alias: string) => { ok: boolean; output: string; prompts: AskedPrompt[] };
type Handlers = Record<string, (args: Record<string, unknown>) => unknown>;

const fail = (code: string, message: string) => Promise.reject({ code, message });

export function rotationHandlers({
  keys,
  batchLogin,
  vaultLogin,
}: {
  /** The key list as `list_keys` returns it (with `inAgent`). */
  keys: () => KeyView[];
  batchLogin: Login;
  vaultLogin: Login;
}): Handlers {
  const others = serverKeysHandlers({ keys, batchLogin, vaultLogin });
  const servers = new Map<string, Server>([
    ['backup', { user: 'backup', fingerprints: [SOMEONE_ELSE, OLD_KEY] }],
    ['media', { user: 'pi', fingerprints: [OLD_KEY], readsElsewhere: true }],
    ['router', { user: 'admin', fingerprints: [OLD_KEY] }],
  ]);
  recordCheck('router', { ok: true, output: '', prompts: [], diagnosis: null });

  function line(index: number, fingerprint: string): AuthorizedKey {
    const key = keys().find((k) => k.fingerprint === fingerprint);
    return {
      line: index + 1,
      algorithm: key?.algorithm ?? 'ed25519',
      keyType: key?.keyType ?? 'ssh-ed25519',
      bits: key?.bits ?? 256,
      fingerprint,
      comment: key?.comment ?? 'ci@build-01',
      publicKey:
        key?.publicKey?.split(' ').slice(0, 2).join(' ') ??
        `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${fingerprint.slice(7, 30)}`,
      expires: null,
      certAuthority: false,
      options: [],
    };
  }

  function serverKeys(
    alias: string,
    server: Server,
    action: ServerKeysAction,
  ): ServerKeys | Promise<never> {
    let changed = false;
    if (action.type === 'add') {
      const key = keys().find((k) => k.id === action.keyId);
      if (!key?.fingerprint) return fail('not_found', `key ${action.keyId}`);
      if (!server.fingerprints.includes(key.fingerprint)) {
        server.fingerprints.push(key.fingerprint);
        changed = true;
      }
    }
    if (action.type === 'remove') {
      // The backend goes by the key's base64, whatever the comment.
      const removed = action.publicKey.split(' ').slice(0, 2).join(' ');
      const before = server.fingerprints.length;
      server.fingerprints = server.fingerprints.filter(
        (fingerprint, index) => line(index, fingerprint).publicKey !== removed,
      );
      changed = server.fingerprints.length < before;
    }
    return {
      ok: true,
      changed,
      read: true,
      file: { keys: server.fingerprints.map((fp, index) => line(index, fp)), invalid: [] },
      output: alias === 'router' ? 'Welcome to RouterOS' : '',
      prompts: [],
    };
  }

  function checkKeyLogin(args: Record<string, unknown>, withVault: boolean) {
    const alias = String(args.alias);
    const key = keys().find((k) => k.id === args.keyId);
    if (!key) return fail('not_found', `key ${String(args.keyId)}`);
    const server = servers.get(alias);
    const check = (opens: (fingerprint: string | null) => boolean): KeyLoginCheck => {
      if (!server) {
        const login = batchLogin(alias);
        return { ...login, otherKey: false };
      }
      const denied = `${server.user}@${alias}: Permission denied (publickey).`;
      if (key.encrypted && !key.inAgent && !opens(key.fingerprint)) {
        return {
          ok: false,
          otherKey: server.fingerprints.includes(OLD_KEY),
          output: server.fingerprints.includes(OLD_KEY) ? '' : denied,
          prompts: [
            {
              text: `Enter passphrase for key '${key.privatePath}': `,
              kind: { type: 'passphrase', key: key.privatePath ?? '' },
              account: null,
              outcome: 'missing',
            },
          ],
        };
      }
      const takes = !server.readsElsewhere && server.fingerprints.includes(key.fingerprint ?? '');
      if (takes) return { ok: true, otherKey: false, output: '', prompts: [] };
      // ssh moves on to the old key, still named in the config.
      if (server.fingerprints.includes(OLD_KEY)) {
        return { ok: false, otherKey: true, output: '', prompts: [] };
      }
      return { ok: false, otherKey: false, output: denied, prompts: [] };
    };
    if (!withVault) return check(() => false);
    return vaultKeyTest(alias, check) ?? check(() => false);
  }

  return {
    server_keys: ({ alias, action }) => {
      const server = servers.get(String(alias));
      return server
        ? serverKeys(String(alias), server, action as ServerKeysAction)
        : others.server_keys?.({ alias, action });
    },
    vault_server_keys: ({ alias, action }) => {
      const server = servers.get(String(alias));
      return server
        ? serverKeys(String(alias), server, action as ServerKeysAction)
        : others.vault_server_keys?.({ alias, action });
    },
    check_key_login: (args) => checkKeyLogin(args, false),
    vault_check_key_login: (args) => checkKeyLogin(args, true),
  };
}
