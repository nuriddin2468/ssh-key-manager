// Pure logic of the Passwords page: filtering, the editor's form, 2FA timing
// and small formatting helpers. Kept free of React so it is easy to test.

import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryInput } from '@/bindings/EntryInput';
import type { EntryKind } from '@/bindings/EntryKind';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { GenerateOptions } from '@/bindings/GenerateOptions';
import type { LockReason } from '@/bindings/LockReason';
import type { Tone } from '@/components/ui/Tile';

// ── List ────────────────────────────────────────────────────────────────────

export type EntryFilter = 'all' | 'login' | 'host' | 'key' | 'otp' | 'trash';

export const FILTERS: readonly EntryFilter[] = ['all', 'login', 'host', 'key', 'otp', 'trash'];

/** Entries in the recycle bin show only under its own filter. */
export function matchesFilter(entry: EntrySummary, filter: EntryFilter): boolean {
  if (filter === 'trash') return entry.inTrash;
  if (entry.inTrash) return false;
  if (filter === 'all') return true;
  if (filter === 'otp') return entry.hasOtp;
  return entry.kind === filter;
}

/** Case-insensitive match on everything the list shows (never on secrets). */
export function matchesQuery(entry: EntrySummary, query: string): boolean {
  const needle = query.trim().toLocaleLowerCase();
  if (!needle) return true;
  return [entry.title, entry.username, entry.url, entry.host, entry.keyFingerprint, entry.group]
    .filter((value): value is string => Boolean(value))
    .some((value) => value.toLocaleLowerCase().includes(needle));
}

export function filterEntries(
  entries: readonly EntrySummary[],
  filter: EntryFilter,
  query: string,
): EntrySummary[] {
  return entries.filter((entry) => matchesFilter(entry, filter) && matchesQuery(entry, query));
}

export function filterCounts(entries: readonly EntrySummary[]): Record<EntryFilter, number> {
  const counts = { all: 0, login: 0, host: 0, key: 0, otp: 0, trash: 0 };
  for (const entry of entries) {
    for (const filter of FILTERS) if (matchesFilter(entry, filter)) counts[filter] += 1;
  }
  return counts;
}

/** The filter to switch to so that `entry` is listed, keeping `current` if it already is. */
export function filterShowing(entry: EntrySummary, current: EntryFilter): EntryFilter {
  if (matchesFilter(entry, current)) return current;
  return entry.inTrash ? 'trash' : 'all';
}

const AVATAR_TONES: Tone[] = [
  'indigo',
  'teal',
  'pink',
  'orange',
  'blue',
  'violet',
  'amber',
  'rose',
];

/** A letter avatar: the title's first letter or digit, coloured by the title. */
export function avatar(title: string): { letter: string; tone: Tone } {
  const first = Array.from(title.trim()).find((char) => /[\p{L}\p{N}]/u.test(char));
  let hash = 0;
  for (const char of title.trim().toLocaleLowerCase()) {
    hash = (hash * 31 + (char.codePointAt(0) ?? 0)) >>> 0;
  }
  return {
    letter: first ? first.toLocaleUpperCase() : '#',
    tone: AVATAR_TONES[hash % AVATAR_TONES.length] ?? 'slate',
  };
}

/**
 * A link the opener can show in the browser: http(s) as typed, or a bare
 * domain like `github.com/login` with https added. Anything else is `null`.
 */
export function openableUrl(url: string): string | null {
  const value = url.trim();
  if (!value) return null;
  const candidate = /^https?:\/\//i.test(value)
    ? value
    : /^[\p{L}\p{N}-]+(\.[\p{L}\p{N}-]+)*\.\p{L}{2,}(:\d+)?([/?#].*)?$/u.test(value)
      ? `https://${value}`
      : null;
  if (!candidate) return null;
  try {
    const parsed = new URL(candidate);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.href : null;
  } catch {
    return null;
  }
}

/** `github.com` for `https://github.com/login`; the text itself if it is no URL. */
export function urlLabel(url: string): string {
  const href = openableUrl(url);
  if (!href) return url.trim();
  return new URL(href).host;
}

// ── Strength ────────────────────────────────────────────────────────────────

export type StrengthScore = 0 | 1 | 2 | 3 | 4;

/** zxcvbn's score, clamped to 0–4. */
export function strengthScore(score: number | undefined | null): StrengthScore {
  if (score === undefined || score === null || Number.isNaN(score)) return 0;
  return Math.max(0, Math.min(4, Math.round(score))) as StrengthScore;
}

export const strengthLabelKey = (score: number) =>
  `passwords.strength${strengthScore(score)}` as const;

// ── 2FA ─────────────────────────────────────────────────────────────────────

/**
 * The period a code belongs to. The backend reports only how long the current
 * code stays valid, so assume the common 30 s unless that is longer.
 */
export function otpPeriod(validFor: number): number {
  return validFor > 30 ? 60 : 30;
}

/** Seconds left of a code that was `validFor` seconds from expiry at `fetchedAt`. */
export function otpRemaining(validFor: number, fetchedAt: number, now: number): number {
  const elapsed = Math.floor(Math.max(0, now - fetchedAt) / 1000);
  return Math.max(0, validFor - elapsed);
}

/** 0–1, how much of the code's period is left; drives the countdown ring. */
export function otpFraction(remaining: number, period: number): number {
  if (period <= 0) return 0;
  return Math.max(0, Math.min(1, remaining / period));
}

/** `492 039`, `1234 5678`: codes are easier to read and type in halves. */
export function formatOtp(code: string): string {
  if (code.length < 6) return code;
  const half = Math.ceil(code.length / 2);
  return `${code.slice(0, half)} ${code.slice(half)}`;
}

/**
 * Whether `text` looks like what a site shows for 2FA: an `otpauth://` URI, or
 * a base32 key of at least 16 characters (spaces and dashes allowed).
 */
export function isOtpSecret(text: string): boolean {
  const value = text.trim();
  if (/^otpauth:\/\//i.test(value)) return true;
  const key = value.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
  return key.length >= 16 && /^[A-Z2-7]+$/.test(key);
}

// ── Recovery key ────────────────────────────────────────────────────────────

/** `7K3M-Q9TB-…` as groups; a key without dashes is cut into fours. */
export function recoveryKeyGroups(key: string): string[] {
  const trimmed = key.trim();
  if (trimmed.includes('-')) return trimmed.split('-').filter(Boolean);
  const compact = trimmed.replace(/\s+/g, '');
  return compact.match(/.{1,4}/g) ?? [];
}

// ── Editor ──────────────────────────────────────────────────────────────────

export type OtpMode = 'keep' | 'replace' | 'remove';

export interface EntryForm {
  kind: EntryKind;
  title: string;
  username: string;
  /** A new password; empty keeps the current one. */
  password: string;
  url: string;
  notes: string;
  /** For an entry that has a 2FA secret: what to do with it. */
  otpMode: OtpMode;
  /** A new 2FA secret, when there is none yet or it is being replaced. */
  otp: string;
  host: string;
  keyFingerprint: string;
}

export const EMPTY_FORM: EntryForm = {
  kind: 'login',
  title: '',
  username: '',
  password: '',
  url: '',
  notes: '',
  otpMode: 'keep',
  otp: '',
  host: '',
  keyFingerprint: '',
};

/** The editor's starting state for an entry; secrets are never prefilled. */
export function formFromEntry(entry: EntryDetail): EntryForm {
  return {
    kind: entry.kind,
    title: entry.title,
    username: entry.username,
    password: '',
    url: entry.url,
    notes: entry.notes,
    otpMode: 'keep',
    otp: '',
    host: entry.host ?? '',
    keyFingerprint: entry.keyFingerprint ?? '',
  };
}

export interface FormErrors {
  title?: 'required';
  host?: 'required';
  key?: 'required';
  otp?: 'invalid' | 'required';
}

/** `hadOtp`: the entry being edited already has a 2FA secret. */
export function validateForm(form: EntryForm, hadOtp: boolean): FormErrors {
  const errors: FormErrors = {};
  if (!form.title.trim()) errors.title = 'required';
  if (form.kind === 'host' && !form.host.trim()) errors.host = 'required';
  if (form.kind === 'key' && !form.keyFingerprint.trim()) errors.key = 'required';
  const enteringOtp = !hadOtp || form.otpMode === 'replace';
  if (enteringOtp && form.otp.trim() && !isOtpSecret(form.otp)) errors.otp = 'invalid';
  if (hadOtp && form.otpMode === 'replace' && !form.otp.trim()) errors.otp = 'required';
  return errors;
}

export const hasErrors = (errors: FormErrors) => Object.keys(errors).length > 0;

/**
 * The editor's state as the backend's `EntryInput`: `password: null` keeps the
 * current password, `otp: null` keeps the 2FA secret and `''` removes it.
 * `hadOtp`: the entry being edited already has a 2FA secret.
 */
export function inputFromForm(form: EntryForm, hadOtp: boolean): EntryInput {
  let otp: string | null = null;
  if (hadOtp) {
    if (form.otpMode === 'remove') otp = '';
    else if (form.otpMode === 'replace' && form.otp.trim()) otp = form.otp.trim();
  } else if (form.otp.trim()) {
    otp = form.otp.trim();
  }
  return {
    title: form.title.trim(),
    username: form.username.trim(),
    password: form.password === '' ? null : form.password,
    url: form.url.trim(),
    notes: form.notes,
    otp,
    kind: form.kind,
    host: form.kind === 'host' ? form.host.trim() || null : null,
    keyFingerprint: form.kind === 'key' ? form.keyFingerprint.trim() || null : null,
  };
}

/** Words an attacker would try first when guessing an entry's password. */
export function strengthContext(form: Pick<EntryForm, 'title' | 'username' | 'url'>): string[] {
  return [form.title, form.username, urlLabel(form.url)].map((word) => word.trim()).filter(Boolean);
}

// ── Generator ───────────────────────────────────────────────────────────────

export type PasswordOptions = Extract<GenerateOptions, { mode: 'password' }>;
export type PassphraseOptions = Extract<GenerateOptions, { mode: 'passphrase' }>;

export const DEFAULT_PASSWORD: PasswordOptions = {
  mode: 'password',
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

export const DEFAULT_PASSPHRASE: PassphraseOptions = {
  mode: 'passphrase',
  words: 5,
  separator: '-',
  capitalize: true,
  number: true,
};

export const PASSWORD_LENGTH = { min: 8, max: 128, slider: 64 } as const;
export const PASSPHRASE_WORDS = { min: 3, max: 12 } as const;

export function clamp(value: number, min: number, max: number): number {
  if (Number.isNaN(value)) return min;
  return Math.max(min, Math.min(max, Math.round(value)));
}

type CharacterClass = 'lowercase' | 'uppercase' | 'digits' | 'symbols';
export const CHARACTER_CLASSES: readonly CharacterClass[] = [
  'lowercase',
  'uppercase',
  'digits',
  'symbols',
];

/** Turning off the last character class would leave nothing to generate from. */
export function canToggleClass(options: PasswordOptions, which: CharacterClass): boolean {
  if (!options[which]) return true;
  return CHARACTER_CLASSES.filter((name) => options[name]).length > 1;
}

// ── Settings and locking ────────────────────────────────────────────────────

/** Auto-lock choices in minutes; `null` never. */
export const AUTO_LOCK_MINUTES = [1, 5, 15, 60, null] as const;
/** Clipboard clearing choices in seconds; 0 never. */
export const CLIPBOARD_SECONDS = [10, 30, 90, 0] as const;

/** Toast for a lock the user didn't ask for; none for a manual lock. */
export function lockToastKey(reason: LockReason) {
  switch (reason) {
    case 'manual':
      return null;
    case 'idle':
      return 'passwords.lockedIdle' as const;
    case 'sleep':
      return 'passwords.lockedSleep' as const;
    case 'screenLock':
      return 'passwords.lockedScreen' as const;
    case 'minimize':
      return 'passwords.lockedMinimize' as const;
    case 'changed':
      return 'passwords.lockedChanged' as const;
  }
}

/** The conflict copy's path from a `conflict` error's message. */
export function conflictCopyPath(message: string): string | null {
  const match = /changed on disk:\s*(.+)$/s.exec(message);
  return match?.[1]?.trim() || null;
}

/** Whole days between an RFC 3339 time and `now`, or `null` if unknown. */
export function daysSince(iso: string | null | undefined, now: Date = new Date()): number | null {
  if (!iso) return null;
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return null;
  return Math.max(0, Math.floor((now.getTime() - time) / 86_400_000));
}
