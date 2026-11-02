// In-memory password vault for `pnpm dev` (see backend.ts). It starts locked;
// the master password is `master`. Open `?vault=missing` to start without one.

import type { CopyResult } from '@/bindings/CopyResult';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { GenerateOptions } from '@/bindings/GenerateOptions';
import type { OtpCode } from '@/bindings/OtpCode';
import type { SecretField } from '@/bindings/SecretField';
import type { Strength } from '@/bindings/Strength';
import type { VaultSettings } from '@/bindings/VaultSettings';
import type { VaultStatus } from '@/bindings/VaultStatus';

const DATA = '/Users/dev/Library/Application Support/uz.sshkm.app';
const RECOVERY_KEY = '7K3M-Q9TB-X2HD-4WNF-8RJC-ZP6V-1GYS-5MAE-0QK7-T3XB-N9HD-2WFR-8JCZ';

interface MockEntry {
  detail: EntryDetail;
  password: string;
  otp: string;
}

let exists = new URLSearchParams(window.location.search).get('vault') !== 'missing';
let master = 'master';
let unlocked = false;
let deviceEnabled = false;
let settings: VaultSettings = {
  database: null,
  autoLockMinutes: 5,
  clipboardSeconds: 30,
  lockOnSleep: true,
  lockOnScreenLock: true,
  lockOnMinimize: false,
  unlockKeysOnOpen: false,
};

function entry(
  summary: Partial<EntrySummary> & Pick<EntrySummary, 'title'>,
  password: string,
  extra: { otp?: string; notes?: string } = {},
): MockEntry {
  return {
    detail: {
      id: crypto.randomUUID(),
      username: '',
      url: '',
      kind: 'login',
      host: null,
      keyFingerprint: null,
      hasPassword: password !== '',
      hasOtp: Boolean(extra.otp),
      group: null,
      inTrash: false,
      created: '2026-02-03T10:00:00Z',
      modified: '2026-09-14T16:20:00Z',
      notes: extra.notes ?? '',
      passwordChanged: '2026-09-14T16:20:00Z',
      historyLen: 2,
      ...summary,
    },
    password,
    otp: extra.otp ?? '',
  };
}

const entries: MockEntry[] = [
  entry(
    { title: 'GitHub', username: 'dev@example.com', url: 'https://github.com/login' },
    'kV9#pL2!mZ7qR4xT',
    {
      otp: 'otpauth://totp/GitHub?secret=JBSWY3DPEHPK3PXP',
      notes: 'Recovery codes are in the safe.',
    },
  ),
  entry(
    { title: 'AWS console', username: 'admin', url: 'https://console.aws.amazon.com' },
    'password123',
  ),
  entry(
    { title: 'prod-api', username: 'deploy', kind: 'host', host: 'prod-api' },
    'correct-horse-battery-staple',
  ),
  entry(
    {
      title: 'id_ed25519',
      kind: 'key',
      keyFingerprint: 'SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw',
    },
    'Tundra-Velvet-Rocket-Mango7',
  ),
  entry({ title: 'Router admin', username: 'admin', url: 'http://192.168.1.1' }, 'password123'),
  entry({ title: 'Old forum', username: 'dev', inTrash: true, group: 'Recycle Bin' }, 'hunter2'),
];

const fail = (code: string, message: string) => Promise.reject({ code, message });

function requireUnlocked(): Promise<never> | undefined {
  if (!unlocked) return fail('vault_locked', 'the vault is locked');
  return undefined;
}

function find(id: unknown): MockEntry | undefined {
  return entries.find((e) => e.detail.id === id);
}

function summary({ detail }: MockEntry): EntrySummary {
  const { notes: _n, passwordChanged: _p, historyLen: _h, ...rest } = detail;
  return rest;
}

function apply(target: MockEntry, input: EntryInput) {
  if (!input.title.trim()) throw { code: 'invalid_input', message: 'an entry needs a title' };
  if (input.password !== null) {
    target.password = input.password;
    target.detail.passwordChanged = new Date().toISOString();
  }
  if (input.otp !== null) target.otp = input.otp.trim();
  Object.assign(target.detail, {
    title: input.title.trim(),
    username: input.username.trim(),
    url: input.url.trim(),
    notes: input.notes,
    kind: input.kind,
    host: input.kind === 'host' ? input.host : null,
    keyFingerprint: input.kind === 'key' ? input.keyFingerprint : null,
    hasPassword: target.password !== '',
    hasOtp: target.otp !== '',
    modified: new Date().toISOString(),
  });
}

function status(): VaultStatus {
  return {
    state: unlocked ? 'unlocked' : exists ? 'locked' : 'missing',
    files: {
      exists,
      hasMasterPassword: exists,
      hasDeviceUnlock: exists && deviceEnabled,
      deviceSlots: exists && deviceEnabled ? ['9b2e4c1a-7f3d-4e8a-b6c5-1d0f2a3e4b5c'] : [],
      vaultId: exists ? '3f0c7a52-0d5e-4c1b-9a51-7b0f4e2a8c11' : null,
    },
    paths: { database: `${DATA}/vault.kdbx`, keys: `${DATA}/vault.keys` },
    settings,
    device: { kind: 'touchId', unavailableReason: null, enabled: exists && deviceEnabled },
  };
}

const WORDS = ['tundra', 'velvet', 'rocket', 'mango', 'harbor', 'pixel', 'quartz', 'lantern'];

function randomIndex(n: number): number {
  return (crypto.getRandomValues(new Uint32Array(1))[0] ?? 0) % n;
}

function generate(options: GenerateOptions): string {
  if (options.mode === 'passphrase') {
    const words = Array.from({ length: options.words }, () => {
      const word = WORDS[randomIndex(WORDS.length)] ?? 'word';
      return options.capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word;
    });
    if (options.number) {
      const i = randomIndex(words.length);
      words[i] = `${words[i]}${randomIndex(10)}`;
    }
    return words.join(options.separator);
  }
  let set = '';
  if (options.lowercase) set += 'abcdefghijkmnpqrstuvwxyz';
  if (options.uppercase) set += 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  if (options.digits) set += '23456789';
  if (options.symbols) set += '!#$%&*+-=?@^_';
  if (!set) throw { code: 'invalid_input', message: 'choose at least one kind of character' };
  return Array.from({ length: options.length }, () => set[randomIndex(set.length)]).join('');
}

/** A rough stand-in for zxcvbn: length and variety. */
function strength(password: string): Strength {
  if (!password || /^(password|123456|qwerty)/i.test(password)) {
    return { score: 0, guessesLog10: 1 };
  }
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(password)).length;
  const guessesLog10 = Math.min(password.length * Math.log10(10 + classes * 20), 40);
  const score =
    guessesLog10 < 3 ? 0 : guessesLog10 < 6 ? 1 : guessesLog10 < 8 ? 2 : guessesLog10 < 10 ? 3 : 4;
  return { score, guessesLog10 };
}

export const vaultHandlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  vault_status: status,
  vault_create: ({ master: next }) => {
    if (exists) return fail('already_exists', 'vault.kdbx');
    if (!next) return fail('invalid_input', 'the master password is empty');
    exists = true;
    unlocked = true;
    master = next as string;
    return RECOVERY_KEY;
  },
  vault_unlock: ({ master: typed }) => {
    if (typed !== master) return fail('wrong_passphrase', 'wrong passphrase');
    unlocked = true;
  },
  vault_recover: ({ recoveryKey, newMaster }) => {
    const normalized = String(recoveryKey).toUpperCase().replace(/[\s-]/g, '');
    if (normalized !== RECOVERY_KEY.replace(/-/g, '')) {
      return fail('wrong_passphrase', 'wrong passphrase');
    }
    master = newMaster as string;
    unlocked = true;
  },
  vault_unlock_device: () => {
    if (!deviceEnabled) return fail('not_found', 'device unlock is not set up here');
    unlocked = true;
  },
  vault_enable_device: ({ master: typed }) => {
    if (typed !== master) return fail('wrong_passphrase', 'wrong passphrase');
    deviceEnabled = true;
  },
  vault_disable_device: () => {
    deviceEnabled = false;
  },
  vault_lock: () => {
    unlocked = false;
  },
  vault_activity: () => undefined,
  vault_entries: () =>
    requireUnlocked() ?? entries.map(summary).sort((a, b) => a.title.localeCompare(b.title)),
  vault_entry: ({ id }) =>
    requireUnlocked() ?? find(id)?.detail ?? fail('not_found', `entry ${id}`),
  vault_reveal: ({ id, field }) => {
    const target = find(id);
    if (!target) return requireUnlocked() ?? fail('not_found', `entry ${id}`);
    return requireUnlocked() ?? ((field as SecretField) === 'otp' ? target.otp : target.password);
  },
  vault_copy: async ({ id, field }): Promise<CopyResult> => {
    await requireUnlocked();
    const target = find(id);
    if (!target) return fail('not_found', `entry ${id}`);
    const text =
      field === 'username'
        ? target.detail.username
        : field === 'url'
          ? target.detail.url
          : field === 'otp'
            ? '492039'
            : target.password;
    await navigator.clipboard.writeText(text).catch(() => undefined);
    const secret = field === 'password' || field === 'otp';
    return { clearsInSecs: secret && settings.clipboardSeconds ? settings.clipboardSeconds : null };
  },
  vault_otp: ({ id }): OtpCode | Promise<never> => {
    const target = find(id);
    if (!target?.otp) return fail('not_found', '2FA secret');
    const seconds = Math.floor(Date.now() / 1000);
    const code = String((Math.floor(seconds / 30) * 7919) % 1_000_000).padStart(6, '0');
    return { code, validFor: 30 - (seconds % 30) };
  },
  vault_add: ({ input }) => {
    const locked = requireUnlocked();
    if (locked) return locked;
    const created = entry({ title: 'new' }, '');
    created.detail.historyLen = 0;
    apply(created, input as EntryInput);
    entries.push(created);
    return created.detail;
  },
  vault_update: ({ id, input }) => {
    const target = find(id);
    if (!target) return requireUnlocked() ?? fail('not_found', `entry ${id}`);
    apply(target, input as EntryInput);
    target.detail.historyLen += 1;
    return target.detail;
  },
  vault_trash: ({ id }) => {
    const target = find(id);
    if (target) Object.assign(target.detail, { inTrash: true, group: 'Recycle Bin' });
  },
  vault_restore: ({ id }) => {
    const target = find(id);
    if (target) Object.assign(target.detail, { inTrash: false, group: null });
  },
  vault_delete: ({ id }) => {
    const index = entries.findIndex((e) => e.detail.id === id);
    if (index < 0 || !entries[index]?.detail.inTrash) {
      return fail('invalid_input', 'only entries in the recycle bin can be deleted');
    }
    entries.splice(index, 1);
  },
  vault_empty_trash: () => {
    const kept = entries.filter((e) => !e.detail.inTrash);
    const removed = entries.length - kept.length;
    entries.splice(0, entries.length, ...kept);
    return removed;
  },
  vault_generate: ({ options }) => generate(options as GenerateOptions),
  vault_strength: ({ password }) => strength(String(password)),
  vault_change_master: ({ current, new: next }) => {
    if (current !== master) return fail('wrong_passphrase', 'wrong passphrase');
    master = next as string;
  },
  vault_new_recovery_key: ({ master: typed }) => {
    if (typed !== master) return fail('wrong_passphrase', 'wrong passphrase');
    deviceEnabled = false;
    return RECOVERY_KEY;
  },
  vault_test_connection: ({ alias }) => {
    const host = entries.find((e) => e.detail.kind === 'host' && e.detail.host === alias);
    return (
      requireUnlocked() ?? {
        ok: Boolean(host),
        output: host ? '' : `${alias}: Permission denied (publickey,password).`,
        prompts: host
          ? [
              {
                text: `${host.detail.username}@${alias}'s password: `,
                kind: { type: 'password' },
                account: { user: host.detail.username, host: alias },
                outcome: 'answered',
              },
            ]
          : [],
      }
    );
  },
  vault_install_public_key: ({ alias }) =>
    requireUnlocked() ?? { ok: true, added: true, output: `Key added on ${alias}.`, prompts: [] },
  vault_set_settings: ({ settings: next }) => {
    settings = { ...(next as VaultSettings), database: settings.database };
    return settings;
  },
};
