// The generator's presets, the ways to copy a secret and the connection
// string builder. The secrets themselves come from Rust (`tools_generate_secret`).

import type { SecretPreset } from '@/bindings/SecretPreset';
import type { TokenEncoding } from '@/bindings/TokenEncoding';
import type { UuidVersion } from '@/bindings/UuidVersion';
import { parsePort } from '../network/model';

export type PresetId = SecretPreset['kind'];

/** The presets as the list shows them, under three headings. */
export const PRESET_GROUPS = [
  {
    id: 'passwords',
    presets: [
      'databasePassword',
      'shellPassword',
      'envPassword',
      'wifiPassword',
      'passphrase',
      'pin',
    ],
  },
  { id: 'tokens', presets: ['apiToken', 'jwtSecret', 'uuid'] },
  { id: 'frameworks', presets: ['laravelAppKey', 'djangoSecretKey', 'railsSecretKeyBase'] },
] as const satisfies readonly { id: string; presets: readonly PresetId[] }[];

export type PresetGroup = (typeof PRESET_GROUPS)[number]['id'];

/** The limits the backend checks. */
export const RANGES = {
  length: { min: 16, max: 64 },
  groups: { min: 3, max: 8 },
  words: { min: 3, max: 12 },
  digits: { min: 4, max: 12 },
} as const;

/** What the user can change about each preset. */
export interface Choices {
  length: { databasePassword: number; shellPassword: number; envPassword: number };
  encoding: { apiToken: TokenEncoding; jwtSecret: TokenEncoding };
  version: UuidVersion;
  groups: number;
  words: number;
  digits: number;
}

export const DEFAULT_CHOICES: Choices = {
  length: { databasePassword: 32, shellPassword: 24, envPassword: 32 },
  encoding: { apiToken: 'base64url', jwtSecret: 'base64url' },
  version: 'v4',
  groups: 5,
  words: 6,
  digits: 6,
};

export function presetOf(id: PresetId, choices: Choices): SecretPreset {
  switch (id) {
    case 'databasePassword':
    case 'shellPassword':
    case 'envPassword':
      return { kind: id, length: choices.length[id] };
    case 'apiToken':
    case 'jwtSecret':
      return { kind: id, encoding: choices.encoding[id] };
    case 'uuid':
      return { kind: id, version: choices.version };
    case 'wifiPassword':
      return { kind: id, groups: choices.groups };
    case 'passphrase':
      return { kind: id, words: choices.words };
    case 'pin':
      return { kind: id, digits: choices.digits };
    case 'laravelAppKey':
    case 'djangoSecretKey':
    case 'railsSecretKeyBase':
      return { kind: id };
  }
}

/** The variable each secret usually goes into, for "copy as". */
export const VARIABLE: Record<PresetId, string> = {
  databasePassword: 'DB_PASSWORD',
  shellPassword: 'PASSWORD',
  envPassword: 'SECRET',
  wifiPassword: 'WIFI_PASSWORD',
  passphrase: 'PASSPHRASE',
  pin: 'PIN',
  apiToken: 'API_TOKEN',
  jwtSecret: 'JWT_SECRET',
  uuid: 'ID',
  laravelAppKey: 'APP_KEY',
  djangoSecretKey: 'SECRET_KEY',
  railsSecretKeyBase: 'SECRET_KEY_BASE',
};

export const COPY_FORMATS = ['raw', 'env', 'export', 'json'] as const;
export type CopyFormat = (typeof COPY_FORMATS)[number];

/** A name a shell and `.env` files take: letters, digits, `_`; no digit first. */
export function isVariableName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

/** Safe unquoted after `NAME=` in a `.env` file. */
const ENV_PLAIN = /^[A-Za-z0-9%+,\-./:=@_]*$/;

/** What "copy as `format`" puts on the clipboard. */
export function formatForCopy(format: CopyFormat, name: string, value: string): string {
  switch (format) {
    case 'raw':
      return value;
    case 'env':
      return `${name}=${envValue(value)}`;
    case 'export':
      return `export ${name}=${shellQuote(value)}`;
    case 'json':
      return JSON.stringify({ [name]: value });
  }
}

/**
 * A `.env` value: as it is when nothing in it needs quoting, else in single
 * quotes (no `$` expansion in dotenv parsers), else in escaped double quotes.
 */
function envValue(value: string): string {
  if (ENV_PLAIN.test(value)) return value;
  if (!value.includes("'") && !value.includes('\n')) return `'${value}'`;
  return `"${value.replace(/[\\"$`]/g, (c) => `\\${c}`).replace(/\n/g, '\\n')}"`;
}

/** Single quotes for POSIX shells; a `'` inside becomes `'\''`. */
function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export const DATABASES = {
  postgres: { label: 'PostgreSQL', scheme: 'postgres', port: 5432 },
  mysql: { label: 'MySQL', scheme: 'mysql', port: 3306 },
  mongodb: { label: 'MongoDB', scheme: 'mongodb', port: 27017 },
  redis: { label: 'Redis', scheme: 'redis', port: 6379 },
} as const;
export type DatabaseKind = keyof typeof DATABASES;

export interface Connection {
  kind: DatabaseKind;
  user: string;
  host: string;
  /** As typed; empty means the database's usual port. */
  port: string;
  /** A database name, or for Redis its number. */
  database: string;
}

export const EMPTY_CONNECTION: Connection = {
  kind: 'postgres',
  user: '',
  host: '',
  port: '',
  database: '',
};

/**
 * `scheme://user:password@host:port/database`, the user, password and
 * database percent-encoded, an IPv6 host in brackets. Without `password`
 * (for a note next to a saved password) the URL has none.
 */
export function connectionString(connection: Connection, password: string | null): string {
  const db = DATABASES[connection.kind];
  const user = encodeURIComponent(connection.user.trim());
  const secret = password === null ? '' : `:${encodeURIComponent(password)}`;
  const userinfo = user || secret ? `${user}${secret}@` : '';
  let host = connection.host.trim() || 'localhost';
  if (host.includes(':') && !host.startsWith('[')) host = `[${host}]`;
  const port = parsePort(connection.port) ?? db.port;
  const database = connection.database.trim();
  const path = database ? `/${encodeURIComponent(database)}` : '';
  return `${db.scheme}://${userinfo}${host}:${port}${path}`;
}
