// The vault's files for `pnpm dev` (see backend.ts): CSV import and export,
// and moving or switching the vault file. It builds on the in-memory vault
// in vault.ts through its handlers. The made-up paths come from
// src/features/passwords/files/pickers.ts.

import type { CsvFormat } from '@/bindings/CsvFormat';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { ImportPreview } from '@/bindings/ImportPreview';
import type { ImportRow } from '@/bindings/ImportRow';
import type { VaultLocation } from '@/bindings/VaultLocation';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { vaultHandlers } from './vault';

type Handler = (args: Record<string, unknown>) => unknown;

interface SampleRow {
  title: string;
  username: string;
  url: string;
  group: string | null;
  password: string;
  otp: string;
}

const SAMPLE: SampleRow[] = [
  {
    title: 'GitHub',
    username: 'dev@example.com',
    url: 'https://github.com/',
    group: 'Work',
    password: 'gh-imported',
    otp: '',
  },
  {
    title: 'GitLab',
    username: 'dev',
    url: 'https://gitlab.com/users/sign_in',
    group: 'Work',
    password: 'gl-imported',
    otp: 'JBSWY3DPEHPK3PXP',
  },
  {
    title: 'Hetzner Cloud',
    username: 'ops@example.com',
    url: 'https://console.hetzner.cloud',
    group: 'Work/Servers',
    password: 'hz-imported',
    otp: 'JBSWY3DPEHPK3PXP',
  },
  {
    title: 'Router admin',
    username: 'admin',
    url: 'http://192.168.1.1',
    group: null,
    password: 'router-imported',
    otp: '',
  },
  {
    title: 'Netflix',
    username: 'family@example.com',
    url: 'https://www.netflix.com/login',
    group: 'Personal',
    password: 'nf-imported',
    otp: '',
  },
  {
    title: 'Wi-Fi at home',
    username: '',
    url: '',
    group: 'Personal',
    password: '',
    otp: '',
  },
];

const FORMATS: [RegExp, CsvFormat][] = [
  [/bitwarden/i, 'bitwarden'],
  [/1password/i, 'onePassword'],
  [/chrome|edge/i, 'chrome'],
  [/firefox|logins/i, 'firefox'],
  [/apple|passwords\.csv/i, 'apple'],
  [/keepass/i, 'keepassxc'],
];

const fail = (code: string, message: string) => Promise.reject({ code, message });

let current: string | null = null;
/** The current file came from elsewhere and has no keys file next to it. */
let foreign = false;
/** The default vault was moved away, so nothing is left at the default place. */
let defaultMoved = false;
let lastImport: string | null = null;

const keysOf = (database: string) => database.replace(/\.kdbx$/i, '.keys');
const folderOf = (path: string) => path.slice(0, Math.max(path.lastIndexOf('/'), 0));

function host(url: string): string {
  return (
    url
      .replace(/^[a-z][a-z0-9+.-]*:\/\//i, '')
      .split(/[/?#]/)[0]
      ?.replace(/^www\./, '')
      .toLowerCase() ?? ''
  );
}

async function baseStatus(): Promise<VaultStatus> {
  return (await vaultHandlers.vault_status?.({})) as VaultStatus;
}

async function location(): Promise<VaultLocation> {
  const status = await baseStatus();
  const defaultPaths = status.paths;
  const database = current ?? defaultPaths.database;
  return {
    paths: { database, keys: keysOf(database) },
    exists: current ? true : status.files.exists,
    isDefault: current === null,
    defaultPaths,
    defaultExists: status.files.exists && !defaultMoved,
  };
}

async function entries(): Promise<EntrySummary[]> {
  return (await vaultHandlers.vault_entries?.({})) as EntrySummary[];
}

function rowsFor(existing: EntrySummary[]): ImportRow[] {
  return SAMPLE.map((row, index) => {
    const duplicate = existing.find(
      (e) =>
        !e.inTrash &&
        e.username.toLowerCase() === row.username.toLowerCase() &&
        (row.url
          ? host(e.url) !== '' && host(e.url) === host(row.url)
          : e.title.toLowerCase() === row.title.toLowerCase()),
    );
    return {
      index,
      title: row.title,
      username: row.username,
      url: row.url,
      group: row.group,
      hasPassword: row.password !== '',
      hasOtp: row.otp !== '',
      duplicateOf: duplicate?.id ?? null,
    };
  });
}

export const vaultFilesHandlers: Record<string, Handler> = {
  // Shows the switched-to file and, for a file from elsewhere, the recovery form.
  vault_status: async () => {
    const status = await baseStatus();
    if (status.state === 'unlocked') foreign = false;
    if (current === null) return status;
    return {
      ...status,
      state: status.state === 'missing' ? 'locked' : status.state,
      paths: { database: current, keys: keysOf(current) },
      files: foreign
        ? {
            exists: true,
            hasMasterPassword: false,
            hasDeviceUnlock: false,
            deviceSlots: [],
            vaultId: null,
          }
        : { ...status.files, exists: true },
      settings: { ...status.settings, database: current },
    } satisfies VaultStatus;
  },
  vault_import_preview: async ({ path }): Promise<ImportPreview> => {
    const existing = await entries();
    if (/contacts/i.test(String(path))) return fail('unsupported', 'no password column');
    const format = FORMATS.find(([pattern]) => pattern.test(String(path)))?.[1] ?? 'generic';
    return { format, rows: rowsFor(existing), skipped: 1 };
  },
  vault_import: async ({ path, indices }) => {
    await entries();
    let count = 0;
    for (const index of indices as number[]) {
      const row = SAMPLE[index];
      if (!row) return fail('invalid_input', 'the file changed since it was previewed');
      const input: EntryInput = {
        title: row.title,
        username: row.username,
        password: row.password,
        url: row.url,
        notes: '',
        otp: row.otp ? `otpauth://totp/${row.title}?secret=${row.otp}` : null,
        kind: 'login',
        host: null,
        keyFingerprint: null,
      };
      await vaultHandlers.vault_add?.({ input });
      count += 1;
    }
    lastImport = String(path);
    return count;
  },
  vault_trash_import_file: ({ path }) => {
    if (path !== lastImport) {
      return fail('invalid_input', 'only the CSV file just imported can be moved to the Trash');
    }
    lastImport = null;
  },
  vault_export_csv: async ({ path, master }) => {
    const all = await entries();
    // Checks the master password without changing anything in the mock.
    await vaultHandlers.vault_new_recovery_key?.({ master });
    if (String(path).includes('/.ssh/')) {
      return fail('invalid_input', 'an export is never written into the SSH folder');
    }
    return all.filter((e) => !e.inTrash).length;
  },
  vault_export_kdbx: async ({ path }) => {
    const { paths } = await location();
    if (path === paths.database || path === paths.keys || String(path).includes('/.ssh/')) {
      return fail('invalid_input', "an export never replaces the vault's own files");
    }
  },
  vault_location: location,
  vault_move: async ({ folder }) => {
    const before = await location();
    const name = before.paths.database.split('/').pop() ?? 'vault.kdbx';
    const target = `${folder}/${name}`;
    if (target === before.paths.database)
      return fail('invalid_input', 'the vault is already there');
    if (before.isDefault) defaultMoved = true;
    current = target === before.defaultPaths.database ? null : target;
    if (current === null) defaultMoved = false;
    return location();
  },
  vault_use_file: async ({ path }) => {
    if (!String(path).endsWith('.kdbx')) return fail('parse', 'not a KeePass database');
    const before = await location();
    if (path === before.paths.database) return before;
    await vaultHandlers.vault_lock?.({});
    current = path === before.defaultPaths.database ? null : String(path);
    foreign = current !== null && folderOf(String(path)) !== folderOf(before.paths.database);
    return location();
  },
  vault_use_default: async ({ moveFiles }) => {
    const before = await location();
    if (moveFiles && before.defaultExists && !before.isDefault) {
      return fail('already_exists', before.defaultPaths.database);
    }
    if (moveFiles) defaultMoved = false;
    else await vaultHandlers.vault_lock?.({});
    current = null;
    foreign = false;
    return location();
  },
};
