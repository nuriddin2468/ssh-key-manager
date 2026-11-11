// The Terminal section's model: tabs and how events change them, what each
// state says, and the hosts connected to recently. No React here, so it can
// be tested on its own.

import type { TFunction } from 'i18next';
import type { Diagnosis } from '@/bindings/Diagnosis';
import type { FailReason } from '@/bindings/FailReason';
import type { Failure } from '@/bindings/Failure';
import type { HostEntry } from '@/bindings/HostEntry';
import type { PromptAsk } from '@/bindings/PromptAsk';
import type { PromptRequest } from '@/bindings/PromptRequest';
import type { SessionState } from '@/bindings/SessionState';
import type { SignIn } from '@/bindings/SignIn';
import type { TerminalEvent } from '@/bindings/TerminalEvent';
import type { TerminalInfo } from '@/bindings/TerminalInfo';
import { causeTitle } from '@/features/diagnose/model';

/** The UI's own failure, for a session `ssh` never started in. */
export type OpenFailure = { reason: 'openFailed'; message: string };

export type TabState =
  | Exclude<SessionState, { phase: 'failed' }>
  | { phase: 'failed'; failure: Failure | OpenFailure };

/** A shell on this computer, in a tab instead of `ssh`. */
export interface LocalShell {
  /** The shell's id from `terminal_shells`; `null` for the default one. */
  shell: string | null;
  /** The secret environment whose variables it gets; the tab's `alias` then names it. */
  env?: string;
  /** A project's folder it starts in, with the project's `local` environment. */
  folder?: { project: string; path: string };
}

export interface Tab {
  /** Stable for the tab's life, across reconnects. */
  key: string;
  /** The host, or for a local shell its name (or its environment's). */
  alias: string;
  local?: LocalShell;
  /** The backend session; `null` while it opens or after it ended. */
  id: number | null;
  info: TerminalInfo | null;
  state: TabState;
  /** The prompt waiting for the user, if any. */
  prompt: PromptRequest | null;
  /** Whether its dialog shows (it may wait behind "Show prompt"). */
  promptOpen: boolean;
  /** The "Signed in: …" banner; hides itself after a while. */
  banner: SignIn | null;
  /** The "key has changed" alert waits to be seen. */
  keyChanged: boolean;
  cols: number;
  rows: number;
}

let nextKey = 0;

export function newTab(alias: string, local?: LocalShell): Tab {
  nextKey += 1;
  return {
    key: `tab-${nextKey}`,
    alias,
    local,
    id: null,
    info: null,
    state: { phase: 'connecting' },
    prompt: null,
    promptOpen: false,
    banner: null,
    keyChanged: false,
    cols: 100,
    rows: 30,
  };
}

/** A session running (or starting) behind the tab: closing it disconnects. */
export function isLive(tab: Tab): boolean {
  return tab.state.phase === 'connecting' || tab.state.phase === 'connected';
}

/**
 * The tab after `event`. `showPrompt` says whether a new prompt's dialog
 * opens at once (its tab is in front) or waits behind "Show prompt".
 */
export function applyEvent(tab: Tab, event: TerminalEvent, showPrompt: boolean): Tab {
  switch (event.type) {
    case 'state': {
      const state = event.state;
      return {
        ...tab,
        state,
        info: tab.info ? { ...tab.info, phase: state.phase } : null,
        prompt: state.phase === 'connecting' ? tab.prompt : null,
        promptOpen: state.phase === 'connecting' && tab.promptOpen,
        // A local shell signs in nowhere.
        banner: state.phase === 'connected' && !tab.local ? state.signIn : null,
        keyChanged: state.phase === 'failed' && state.failure.reason === 'hostKeyChanged',
        id: state.phase === 'ended' || state.phase === 'failed' ? null : tab.id,
      };
    }
    case 'prompt':
      return { ...tab, prompt: event.prompt, promptOpen: showPrompt };
    case 'promptClosed':
      return tab.prompt?.id === event.id ? { ...tab, prompt: null, promptOpen: false } : tab;
    case 'saved':
      return tab;
  }
}

/** The tabs in order after the one at `index` closes, and which to show next. */
export function afterClose(tabs: Tab[], key: string, active: string | null) {
  const index = tabs.findIndex((tab) => tab.key === key);
  const rest = tabs.filter((tab) => tab.key !== key);
  if (active !== key) return { tabs: rest, active };
  const next = rest[Math.min(index, rest.length - 1)];
  return { tabs: rest, active: next?.key ?? null };
}

/** The tab `step` places after the active one, wrapping around. */
export function cycle(tabs: Tab[], active: string | null, step: 1 | -1): string | null {
  if (tabs.length === 0) return null;
  const index = Math.max(
    0,
    tabs.findIndex((tab) => tab.key === active),
  );
  return tabs[(index + step + tabs.length) % tabs.length]?.key ?? null;
}

/**
 * Names the app runs `ssh` with: letters, digits and `. _ - @ : [ ]`, not an
 * option. Patterns and anything a shell treats specially are left out; the
 * backend refuses them too (`check_alias`).
 */
export function isConnectable(alias: string): boolean {
  return /^[A-Za-z0-9._@:[\]-]+$/.test(alias) && !alias.startsWith('-');
}

/** The aliases of the config's host blocks that `ssh` can be run with. */
export function connectableAliases(hosts: readonly HostEntry[]): string[] {
  const seen = new Set<string>();
  for (const host of hosts) {
    if (host.kind !== 'host' || host.isWildcard) continue;
    for (const pattern of host.patterns) {
      if (isConnectable(pattern)) seen.add(pattern);
    }
  }
  return [...seen];
}

/** The host block an alias belongs to, for "Open host". */
export function hostIdOf(hosts: readonly HostEntry[] | undefined, alias: string) {
  return hosts?.find((host) => host.kind === 'host' && host.patterns.includes(alias))?.id;
}

/** The last path segment: `id_ed25519` for `/Users/dev/.ssh/id_ed25519`. */
export function fileName(path: string): string {
  return path.split(/[\\/]/).pop() || path;
}

/** "Signed in: key id_ed25519_work, password and 2FA code from the vault". */
export function signInText(t: TFunction, signIn: SignIn, language: string): string {
  const fromVault: string[] = [];
  if (signIn.password === 'vault') fromVault.push(t('terminal.banner.password'));
  if (signIn.oneTimeCode === 'vault') fromVault.push(t('terminal.banner.code'));
  if (signIn.passphrase === 'vault') fromVault.push(t('terminal.banner.passphrase'));
  const parts: string[] = [];
  if (signIn.key) parts.push(t('terminal.banner.key', { key: fileName(signIn.key) }));
  if (fromVault.length > 0) {
    const list = new Intl.ListFormat(language, { type: 'conjunction' }).format(fromVault);
    parts.push(t('terminal.banner.fromVault', { list }));
  }
  if (parts.length > 0) return t('terminal.banner.signedIn', { what: parts.join(', ') });
  const typed = signIn.password === 'user' || signIn.oneTimeCode === 'user';
  return typed ? t('terminal.banner.signedInTyped') : t('terminal.banner.signedInKey');
}

/** `ubuntu@10.0.4.12 · via bastion · connected`, or `Zsh · running` for a local shell. */
export function statusLine(t: TFunction, tab: Tab): string {
  const info = tab.info;
  if (tab.local) return [info?.shell ?? tab.alias, phaseLabel(t, tab)].join(' · ');
  const account = info?.user && info.host ? `${info.user}@${info.host}` : tab.alias;
  const parts = [account];
  if (info?.proxyJump) parts.push(t('terminal.status.via', { jump: info.proxyJump }));
  parts.push(phaseLabel(t, tab));
  return parts.join(' · ');
}

export function phaseLabel(t: TFunction, tab: Tab): string {
  if (tab.local) return t(`terminal.local.status.${tab.state.phase}`);
  if (tab.state.phase === 'connecting' && tab.prompt) return t('terminal.status.waiting');
  return t(`terminal.status.${tab.state.phase}`);
}

/** A prompt that may name the account it is for. */
export type AccountAsk = Extract<PromptAsk, { type: 'password' | 'oneTimeCode' | 'other' }>;

/**
 * The account a prompt's dialog names: `ubuntu@prod-api`, or another host's
 * own account (`bob@bastion.example.net`) when the prompt is for that host.
 */
export function promptAccount(tab: Tab, ask: AccountAsk): string {
  if (ask.foreign && ask.account) return `${ask.account.user}@${ask.account.host}`;
  const user = ask.account?.user ?? tab.info?.user;
  return user ? `${user}@${tab.alias}` : tab.alias;
}

/**
 * The host a host-key question is about, without the address in brackets:
 * `bastion.example.net` for `bastion.example.net (203.0.113.7)`. It may be a
 * jump host rather than the tab's.
 */
export function hostKeyHost(host: string): string {
  return host.replace(/\s+\(.*\)$/, '') || host;
}

/** What "Waiting for your answer: …" goes on to say. */
export function waitingText(t: TFunction, tab: Tab, ask: PromptAsk): string {
  switch (ask.type) {
    case 'password':
      return t('terminal.waiting.password', { account: promptAccount(tab, ask) });
    case 'passphrase':
      return t('terminal.waiting.passphrase', { key: fileName(ask.key) });
    case 'oneTimeCode':
      return t('terminal.waiting.code');
    case 'hostKey':
      return t('terminal.waiting.hostKey');
    case 'other':
      return t('terminal.waiting.other');
  }
}

export type Fix = 'enterPassword' | 'retry' | 'compare' | 'output';

export interface FailureView {
  title: string;
  detail: string;
  /** The first is the primary action. */
  fixes: Fix[];
}

const FIXES: Record<FailReason | 'openFailed', Fix[]> = {
  passwordRejected: ['enterPassword', 'retry', 'output'],
  oneTimeCodeRejected: ['retry', 'output'],
  oneTimeCodeMissing: ['retry', 'output'],
  notAccepted: ['retry', 'output'],
  hostKeyNotTrusted: ['retry', 'output'],
  hostKeyChanged: ['compare', 'output'],
  unreachable: ['retry', 'output'],
  cancelled: ['retry', 'output'],
  other: ['retry', 'output'],
  openFailed: ['retry'],
};

/** A failed session in plain words, and what can be done about it. */
export function failureView(t: TFunction, tab: Tab, failure: Failure | OpenFailure): FailureView {
  const values = {
    alias: tab.alias,
    user: tab.info?.user ?? tab.alias,
    code: 'exitCode' in failure ? (failure.exitCode ?? '—') : '—',
  };
  if (failure.reason === 'openFailed') {
    return {
      title: t(tab.local ? 'terminal.local.openFailed' : 'terminal.failed.openFailed'),
      detail: failure.message,
      fixes: FIXES.openFailed,
    };
  }
  const detailKey =
    failure.reason === 'passwordRejected' && failure.saved
      ? ('terminal.failed.passwordRejectedSavedDetail' as const)
      : (`terminal.failed.${failure.reason}Detail` as const);
  const fixes = FIXES[failure.reason].filter((fix) => fix !== 'output' || failure.output !== '');
  return {
    title: t(`terminal.failed.${failure.reason}` as const, values),
    detail: t(detailKey, values),
    fixes,
  };
}

/**
 * The diagnosis a failed session shows, where the prompts said nothing more
 * precise (a password or code turned down, a prompt cancelled).
 */
export function sessionDiagnosis(failure: Failure | OpenFailure): Diagnosis | null {
  if (failure.reason === 'openFailed' || !failure.diagnosis) return null;
  const { kind } = failure.diagnosis.cause;
  switch (failure.reason) {
    case 'notAccepted':
    case 'unreachable':
    case 'hostKeyChanged':
      return kind === 'unknown' ? null : failure.diagnosis;
    case 'other':
      return failure.diagnosis;
    default:
      return null;
  }
}

/** One line for the live region when a session changes state. */
export function announcement(t: TFunction, tab: Tab, state: TabState): string | null {
  switch (state.phase) {
    case 'connected':
      return t(tab.local ? 'terminal.local.announce.started' : 'terminal.announce.connected', {
        alias: tab.alias,
      });
    case 'ended':
      return t(tab.local ? 'terminal.local.announce.ended' : 'terminal.announce.ended', {
        alias: tab.alias,
      });
    case 'failed': {
      const diagnosis = sessionDiagnosis(state.failure);
      return t('terminal.announce.failed', {
        alias: tab.alias,
        reason: diagnosis
          ? causeTitle(t, diagnosis, tab.alias)
          : failureView(t, tab, state.failure).title,
      });
    }
    default:
      return null;
  }
}

// Hosts connected to recently, newest first, kept in this browser's storage.

const RECENT_KEY = 'sshkm.terminal.recent';
const RECENT_LIMIT = 10;

export interface RecentHost {
  alias: string;
  /** Milliseconds since the epoch. */
  at: number;
}

export function loadRecent(storage: Pick<Storage, 'getItem'> | undefined): RecentHost[] {
  try {
    const raw = storage?.getItem(RECENT_KEY);
    const list: unknown = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(list)) return [];
    return list.filter(
      (item): item is RecentHost =>
        typeof item === 'object' &&
        item !== null &&
        typeof (item as RecentHost).alias === 'string' &&
        typeof (item as RecentHost).at === 'number',
    );
  } catch {
    return [];
  }
}

/** Puts `alias` first, without duplicates, keeping at most ten. */
export function rememberRecent(list: RecentHost[], alias: string, at: number): RecentHost[] {
  return [{ alias, at }, ...list.filter((item) => item.alias !== alias)].slice(0, RECENT_LIMIT);
}

export function saveRecent(storage: Pick<Storage, 'setItem'> | undefined, list: RecentHost[]) {
  try {
    storage?.setItem(RECENT_KEY, JSON.stringify(list));
  } catch {
    // Storage full or blocked: recent hosts are a convenience.
  }
}
