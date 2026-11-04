// Mock `server_keys` and `vault_server_keys`: each server's
// `~/.ssh/authorized_keys`, in memory. A server is read only after signing
// in, the way the real commands do: with keys alone as `test_connection` does,
// with the vault as `vault_test_connection` does.

import type { AskedPrompt } from '@/bindings/AskedPrompt';
import type { AuthorizedKey } from '@/bindings/AuthorizedKey';
import type { KeyView } from '@/bindings/KeyView';
import type { ServerKeys } from '@/bindings/ServerKeys';
import type { ServerKeysAction } from '@/bindings/ServerKeysAction';

interface SignIn {
  ok: boolean;
  output: string;
  prompts: AskedPrompt[];
}

type Login = (alias: string) => SignIn | Promise<SignIn>;

const IN_A_WEEK = new Date(Date.now() + 7 * 24 * 3600 * 1000);
const LAST_MONTH = new Date(Date.now() - 30 * 24 * 3600 * 1000);

/** `YYYY-MM-DDT00:00:00`, as the core reads `expiry-time="YYYYMMDD"`. */
const day = (date: Date) =>
  `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}T00:00:00`;

function entry(
  line: number,
  partial: Partial<AuthorizedKey> & Pick<AuthorizedKey, 'fingerprint'>,
): AuthorizedKey {
  return {
    line,
    algorithm: 'ed25519',
    keyType: 'ssh-ed25519',
    bits: 256,
    comment: '',
    publicKey: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${partial.fingerprint.slice(7, 30)}`,
    expires: null,
    certAuthority: false,
    options: [],
    ...partial,
  };
}

/** What is on each server; a missing alias has no file. */
function seed(): Map<string, { keys: AuthorizedKey[]; invalid: number[] }> {
  return new Map([
    [
      'prod-api',
      {
        keys: [
          entry(1, {
            comment: 'dev@macbook-pro',
            fingerprint: 'SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw',
          }),
          entry(2, {
            comment: 'aziz@thinkpad',
            fingerprint: 'SHA256:Pq3Lm8Xc1Vb6Nr9Tz2Hs5Dj7Fg0Ay4Up8Io3Ke1Wq6R',
            expires: day(IN_A_WEEK),
          }),
          entry(3, {
            comment: 'github-actions deploy',
            fingerprint: 'SHA256:Ze4Wq8Tn1Lm6Xc3Vb9Rk2Hs7Dj5Fg0Ay8Up4Io1Ke6W',
            options: ['restrict', 'from="140.82.112.0/20"'],
          }),
          entry(4, {
            comment: 'admin@old-laptop',
            algorithm: 'rsa',
            keyType: 'ssh-rsa',
            bits: 2048,
            fingerprint: 'SHA256:Jw5Ty0Ui3Op7As1Df4Gh8Jk2Lz6Xc9Vb0Nm3Qw7Er1T',
            publicKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQJw5Ty0Ui3Op7As1Df4',
          }),
          entry(6, {
            comment: 'contractor 2026',
            fingerprint: 'SHA256:Mn8Bv2Cx5Za9Sd3Fg6Hj1Kl4Qw7Er0Ty3Ui6Op9As2D',
            expires: day(LAST_MONTH),
          }),
        ],
        invalid: [5],
      },
    ],
    [
      'staging-api',
      {
        keys: [
          entry(1, {
            comment: 'dev@macbook-pro',
            fingerprint: 'SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw',
          }),
        ],
        invalid: [],
      },
    ],
  ]);
}

export function serverKeysHandlers({
  keys,
  batchLogin,
  vaultLogin,
}: {
  keys: () => KeyView[];
  batchLogin: Login;
  vaultLogin: Login;
}): Record<string, (args: Record<string, unknown>) => unknown> {
  const files = seed();

  async function run(alias: string, action: ServerKeysAction, login: Login): Promise<ServerKeys> {
    const signedIn = await login(alias);
    if (!signedIn.ok) {
      return {
        ok: false,
        changed: false,
        read: false,
        file: { keys: [], invalid: [] },
        output: signedIn.output,
        prompts: signedIn.prompts,
      };
    }
    let file = files.get(alias);
    let changed = false;
    let ok = true;
    let output = '';
    if (action.type === 'add') {
      const key = keys().find((k) => k.id === action.keyId);
      if (!key?.fingerprint) {
        return Promise.reject({ code: 'not_found', message: `key ${action.keyId}` });
      }
      if (alias === 'old-vpn') {
        ok = false;
        output = 'sh: 1: cannot create .ssh/authorized_keys: Read-only file system';
      } else if (!file?.keys.some((k) => k.fingerprint === key.fingerprint)) {
        file ??= { keys: [], invalid: [] };
        const line = Math.max(0, ...file.keys.map((k) => k.line), ...file.invalid) + 1;
        file.keys.push(
          entry(line, {
            comment: key.comment,
            fingerprint: key.fingerprint,
            algorithm: key.algorithm,
            keyType: key.keyType,
            bits: key.bits,
            publicKey: key.publicKey?.split(' ').slice(0, 2).join(' ') ?? '',
          }),
        );
        files.set(alias, file);
        changed = true;
      }
    }
    if (action.type === 'remove' && file) {
      const before = file.keys.length;
      file.keys = file.keys.filter((k) => k.publicKey !== action.publicKey);
      changed = file.keys.length < before;
    }
    return {
      ok,
      changed,
      read: true,
      file: file ? { keys: [...file.keys], invalid: [...file.invalid] } : { keys: [], invalid: [] },
      output,
      prompts: signedIn.prompts,
    };
  }

  return {
    server_keys: ({ alias, action }) => run(String(alias), action as ServerKeysAction, batchLogin),
    vault_server_keys: ({ alias, action }) =>
      run(String(alias), action as ServerKeysAction, vaultLogin),
  };
}
