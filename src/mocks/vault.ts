// In-memory password vault for `pnpm dev` (see backend.ts). It starts locked;
// the master password is `master`. `?vault=` changes the start:
// - `missing`: no vault yet;
// - `keepass`: a KeePass file without a master password on this computer
//   (opens with the recovery key or the file's password, `keepass`);
// - `unlocked`: already open.
// Like the backend, it locks itself after the auto-lock time without activity
// and announces every lock (see `MOCK_LOCKED_EVENT` in features/passwords).

import type { AskedPrompt } from '@/bindings/AskedPrompt';
import type { CopyResult } from '@/bindings/CopyResult';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { GenerateOptions } from '@/bindings/GenerateOptions';
import type { OtpCode } from '@/bindings/OtpCode';
import type { PromptOutcome } from '@/bindings/PromptOutcome';
import type { SecretField } from '@/bindings/SecretField';
import type { Strength } from '@/bindings/Strength';
import type { VaultSettings } from '@/bindings/VaultSettings';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { hostEntry as pickHostEntry } from '@/features/hosts/model';

const DATA = '/Users/dev/Library/Application Support/uz.sshkm.app';
const RECOVERY_KEY = '7K3M-Q9TB-X2HD-4WNF-8RJC-ZP6V-1GYS-5MAE-0QK7-T3XB-N9HD-2WFR-8JCZ';

interface MockEntry {
  detail: EntryDetail;
  password: string;
  otp: string;
}

const START = new URLSearchParams(window.location.search).get('vault');
const LOCKED_EVENT = 'sshkm:mock-vault-locked';
const KEEPASS_PASSWORD = 'keepass';

let exists = START !== 'missing';
let hasMaster = START !== 'keepass';
let master = 'master';
let unlocked = START === 'unlocked';
/** A recovery key made and not yet confirmed as saved. */
let recoveryKeyUnsaved = false;
let lastActivity = Date.now();
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
    { otp: 'otpauth://totp/prod-api?secret=KRSXG5CTMVRXEZLU' },
  ),
  entry(
    { title: 'legacy-nas', username: 'admin', kind: 'host', host: 'legacy-nas' },
    'nas-admin-2019',
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

/** Whether the mock vault is open: projects show their logins only then. */
export const isMockVaultUnlocked = () => unlocked;

/** The id of the entry titled `title` (not in the recycle bin), for other mocks. */
export const mockEntryId = (title: string) =>
  entries.find((e) => e.detail.title === title && !e.detail.inTrash)?.detail.id;

/** Whether `id` is an entry of the mock vault. */
export const isMockEntry = (id: string) => entries.some((e) => e.detail.id === id);

function requireUnlocked(): Promise<never> | undefined {
  if (!unlocked) return fail('vault_locked', 'the vault is locked');
  lastActivity = Date.now();
  return undefined;
}

function open() {
  unlocked = true;
  lastActivity = Date.now();
}

function lock(reason: 'manual' | 'idle') {
  if (!unlocked) return;
  unlocked = false;
  window.dispatchEvent(new CustomEvent(LOCKED_EVENT, { detail: reason }));
}

window.setInterval(() => {
  const minutes = settings.autoLockMinutes;
  if (unlocked && minutes !== null && Date.now() - lastActivity >= minutes * 60_000) {
    lock('idle');
  }
}, 5_000);

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
      hasMasterPassword: exists && hasMaster,
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

/** `alias#keyId` of the keys installed on mock servers this session. */
const installed = new Set<string>();

/** The entry for `alias`'s password, as the backend picks it: the one made first. */
function hostEntry(alias: string): MockEntry | undefined {
  const first = pickHostEntry(
    entries.map((e) => e.detail),
    alias,
  );
  return first && entries.find((e) => e.detail === first);
}

/**
 * The vault test of a host with no saved password: it signs in with keys,
 * opening those whose passphrases are saved. Locked vault: `vault_locked`.
 */
export function vaultKeyTest<T>(
  alias: string,
  test: (opens: (fingerprint: string | null) => boolean) => T,
): T | Promise<never> | undefined {
  if (hostEntry(alias)?.detail.hasPassword) return undefined;
  return (
    requireUnlocked() ??
    test((fingerprint) =>
      entries.some(
        (e) =>
          !e.detail.inTrash &&
          e.detail.kind === 'key' &&
          e.detail.keyFingerprint === fingerprint &&
          e.password !== '',
      ),
    )
  );
}

function hostUser(alias: string): string {
  return hostEntry(alias)?.detail.username || 'dev';
}

/**
 * Signing in to a mock server with its saved password. Most let you in;
 * `staging-api` turns the password down, `legacy-nas` has a host key that
 * isn't trusted yet, and `bastion` wants a 2FA code as well.
 */
function passwordLogin(alias: string): { ok: boolean; output: string; prompts: AskedPrompt[] } {
  const host = hostEntry(alias);
  const user = hostUser(alias);
  const account = { user, host: alias };
  const denied = `${user}@${alias}: Permission denied (publickey,password).`;
  const password = (outcome: PromptOutcome): AskedPrompt => ({
    text: `${user}@${alias}'s password: `,
    kind: { type: 'password' },
    account,
    outcome,
  });
  const code = (outcome: PromptOutcome): AskedPrompt => ({
    text: 'Verification code: ',
    kind: { type: 'oneTimeCode' },
    account: null,
    outcome,
  });
  if (alias === 'legacy-nas') {
    return {
      ok: false,
      output: 'Host key verification failed.',
      prompts: [
        {
          text: `The authenticity of host '${alias}' can't be established.\nAre you sure you want to continue connecting (yes/no/[fingerprint])? `,
          kind: { type: 'hostKeyConfirm' },
          account: null,
          outcome: 'declined',
        },
      ],
    };
  }
  if (!host?.password) {
    return { ok: false, output: denied, prompts: host ? [password('missing')] : [] };
  }
  if (alias === 'staging-api') {
    return { ok: false, output: denied, prompts: [password('answered'), password('repeated')] };
  }
  if (alias === 'bastion') {
    return host.otp
      ? { ok: true, output: '', prompts: [password('answered'), code('answered')] }
      : { ok: false, output: denied, prompts: [password('answered'), code('missing')] };
  }
  return { ok: true, output: '', prompts: [password('answered')] };
}

export const vaultHandlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  vault_status: status,
  vault_create: ({ master: next }) => {
    if (exists) return fail('already_exists', 'vault.kdbx');
    if (!next) return fail('invalid_input', 'the master password is empty');
    exists = true;
    hasMaster = true;
    master = next as string;
    open();
    recoveryKeyUnsaved = true;
    return RECOVERY_KEY;
  },
  vault_unlock: ({ master: typed }) => {
    if (!hasMaster) return fail('not_found', 'vault.keys');
    if (typed !== master) return fail('wrong_passphrase', 'wrong passphrase');
    open();
  },
  vault_recover: ({ recoveryKey, newMaster }) => {
    const normalized = String(recoveryKey).toUpperCase().replace(/[\s-]/g, '');
    const isKeepassPassword = !hasMaster && recoveryKey === KEEPASS_PASSWORD;
    if (normalized !== RECOVERY_KEY.replace(/-/g, '') && !isKeepassPassword) {
      return fail('wrong_passphrase', 'wrong passphrase');
    }
    master = newMaster as string;
    hasMaster = true;
    open();
  },
  vault_unlock_device: () => {
    if (!deviceEnabled) return fail('not_found', 'device unlock is not set up here');
    unlocked = true;
    lastActivity = Date.now();
  },
  vault_enable_device: ({ master: typed }) => {
    if (typed !== master) return fail('wrong_passphrase', 'wrong passphrase');
    deviceEnabled = true;
  },
  vault_disable_device: () => {
    deviceEnabled = false;
  },
  vault_lock: () => lock('manual'),
  vault_activity: () => {
    if (unlocked) lastActivity = Date.now();
  },
  vault_entries: () =>
    requireUnlocked() ?? entries.map(summary).sort((a, b) => a.title.localeCompare(b.title)),
  vault_entry: ({ id }) =>
    requireUnlocked() ?? find(id)?.detail ?? fail('not_found', `entry ${id}`),
  vault_reveal: ({ id, field }) => {
    const target = find(id);
    if (!target) return requireUnlocked() ?? fail('not_found', `entry ${id}`);
    // As the backend: a 2FA secret is never shown.
    if ((field as SecretField) !== 'password') {
      return requireUnlocked() ?? fail('invalid_input', 'not a secret the interface may show');
    }
    return requireUnlocked() ?? target.password;
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
  vault_copy_recovery_key: async ({ key }): Promise<CopyResult> => {
    await navigator.clipboard.writeText(String(key)).catch(() => undefined);
    return { clearsInSecs: settings.clipboardSeconds || 30 };
  },
  vault_otp: ({ id }): OtpCode | Promise<never> => {
    const locked = requireUnlocked();
    if (locked) return locked;
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
    recoveryKeyUnsaved = true;
    return RECOVERY_KEY;
  },
  vault_recovery_key_pending: () => requireUnlocked() ?? (recoveryKeyUnsaved && hasMaster),
  // The app asks in a native dialog first; the mock takes the yes.
  vault_unsaved_recovery_key: () =>
    requireUnlocked() ?? (recoveryKeyUnsaved && hasMaster ? RECOVERY_KEY : null),
  vault_recovery_key_saved: () => {
    recoveryKeyUnsaved = false;
  },
  vault_test_connection: ({ alias }) => requireUnlocked() ?? passwordLogin(String(alias)),
  vault_test_key_login: ({ alias }) => {
    const locked = requireUnlocked();
    if (locked) return locked;
    const ok = [...installed].some((item) => item.startsWith(`${alias}#`));
    return {
      ok,
      output: ok ? '' : `${hostUser(String(alias))}@${alias}: Permission denied (publickey).`,
      prompts: [],
    };
  },
  vault_install_public_key: ({ alias, keyId }) => {
    const locked = requireUnlocked();
    if (locked) return locked;
    const login = passwordLogin(String(alias));
    if (!login.ok) return { ...login, added: false };
    if (alias === 'old-vpn') {
      return {
        ...login,
        ok: false,
        added: false,
        output: 'sh: 1: cannot create .ssh/authorized_keys: Read-only file system',
      };
    }
    const item = `${alias}#${keyId}`;
    const added = !installed.has(item);
    installed.add(item);
    return { ...login, added };
  },
  vault_set_settings: ({ settings: next }) => {
    settings = { ...(next as VaultSettings), database: settings.database };
    return settings;
  },
};
