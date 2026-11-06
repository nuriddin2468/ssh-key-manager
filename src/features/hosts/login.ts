// What a run of `ssh` against a host means, in plain words: read from the
// prompts `ssh` showed the app (and what became of them) and from the few
// messages `ssh` always prints in English.

import type { AskedPrompt } from '@/bindings/AskedPrompt';
import type { Diagnosis } from '@/bindings/Diagnosis';
import type { PromptKind } from '@/bindings/PromptKind';
import type { PromptOutcome } from '@/bindings/PromptOutcome';
import type en from '@/i18n/locales/en';

/** A connection test, a key install or a key-only login. */
export interface SshRun {
  ok: boolean;
  output: string;
  prompts: readonly AskedPrompt[];
  /** Key installs: the key was added (`false`: it was there already). */
  added?: boolean;
  /** Checks: why it failed, read from what ssh printed. */
  diagnosis?: Diagnosis | null;
}

export type Explanation =
  /** Signed in; `password` when the saved password was given, `code` a 2FA code too. */
  | { kind: 'signedIn'; password: boolean; code: boolean }
  | { kind: 'hostKeyUnknown' }
  | { kind: 'hostKeyChanged' }
  /** `code`: a 2FA code was given as well, so either may be wrong. */
  | { kind: 'passwordRejected'; code: boolean }
  | { kind: 'passwordMissing' }
  | { kind: 'otpMissing' }
  | { kind: 'otpRejected' }
  /** `ssh` wanted a key's passphrase and none is saved; `key` as `ssh` named it. */
  | { kind: 'passphraseMissing'; key: string }
  /** A prompt for another account (a jump host's) went unanswered. */
  | { kind: 'otherAccount'; account: string }
  /** The server turned down every key and no password was given. */
  | { kind: 'keysRejected' }
  /** Signed in, but the command run afterwards failed. */
  | { kind: 'commandFailed' }
  /** Anything else: no connection, a timeout, a configuration error. */
  | { kind: 'failed' };

/** `alice@host: Permission denied (publickey,password).` */
const AUTH_FAILED = /Permission denied \([\w-]+(?:,[\w-]+)*\)/;
const HOST_KEY_CHANGED = /REMOTE HOST IDENTIFICATION HAS CHANGED/;
/** An unknown host key `ssh` was not asked about (`StrictHostKeyChecking yes`), or a changed one. */
const HOST_KEY_FAILED = /Host key verification failed/;
const TIMED_OUT = /\(timed out\)$/;

export function explain(run: SshRun): Explanation {
  const find = (type: PromptKind['type'], outcome: PromptOutcome) =>
    run.prompts.find((p) => p.kind.type === type && p.outcome === outcome);
  const gave = (type: PromptKind['type']) => Boolean(find(type, 'answered'));
  const password = gave('password');
  const code = gave('oneTimeCode');

  if (run.ok) return { kind: 'signedIn', password, code };
  if (HOST_KEY_CHANGED.test(run.output)) return { kind: 'hostKeyChanged' };
  if (find('hostKeyConfirm', 'declined') || HOST_KEY_FAILED.test(run.output)) {
    return { kind: 'hostKeyUnknown' };
  }
  if (find('password', 'repeated')) return { kind: 'passwordRejected', code };
  if (find('oneTimeCode', 'missing')) return { kind: 'otpMissing' };
  if (find('oneTimeCode', 'repeated')) return { kind: 'otpRejected' };
  if (find('password', 'missing')) return { kind: 'passwordMissing' };
  const foreign = run.prompts.find((p) => p.outcome === 'refused' && p.account);
  if (foreign?.account) {
    return { kind: 'otherAccount', account: `${foreign.account.user}@${foreign.account.host}` };
  }

  const denied = AUTH_FAILED.test(run.output);
  if (password) {
    // The password went in once (ssh asks only once) and the server said no;
    // or it let us in and what ran afterwards failed.
    if (denied) return { kind: 'passwordRejected', code };
    return TIMED_OUT.test(run.output) ? { kind: 'failed' } : { kind: 'commandFailed' };
  }
  const passphrase = find('passphrase', 'missing');
  if (passphrase?.kind.type === 'passphrase') {
    return { kind: 'passphraseMissing', key: passphrase.kind.key };
  }
  return denied ? { kind: 'keysRejected' } : { kind: 'failed' };
}

/**
 * The diagnosis a failed check shows as "Why it failed", or null where the
 * prompts already tell more: a password, code or passphrase asked for, a
 * host key declined.
 */
export function shownDiagnosis(run: SshRun, context: RunContext): Diagnosis | null {
  const { diagnosis } = run;
  if (run.ok || !diagnosis || (context !== 'test' && context !== 'vaultTest')) return null;
  const kind = explain(run).kind;
  return kind === 'failed' || kind === 'keysRejected' || kind === 'hostKeyChanged'
    ? diagnosis
    : null;
}

/** What the run was for; the same outcome reads differently in each. */
export type RunContext =
  /** "Test connection" with no saved password: only keys can get in. */
  | 'test'
  /** "Test connection" with the saved password and 2FA code. */
  | 'vaultTest'
  /** Adding a public key, signed in with the saved password. */
  | 'install'
  /** Signing in with a key alone. */
  | 'keyLogin';

export type MessageAction = 'checkHostKey' | 'editPassword' | 'addOtp' | 'unlockKey';

type ResultKey = keyof (typeof en)['hosts']['vault']['result'];

/**
 * A result as the UI shows it: translation keys under `hosts.vault.result`,
 * except `signedIn` and `failed`, the plain test's `hosts.testOk` and
 * `hosts.testFailed`.
 */
export interface LoginMessage {
  tone: 'ok' | 'error';
  title: ResultKey | 'signedIn' | 'failed';
  detail?: ResultKey;
  values?: Record<string, string>;
  action?: MessageAction;
}

/**
 * The message for a run. `vaultLocked`: the vault holds a password for the
 * host but is locked (only matters for `test`).
 */
export function loginMessage(
  run: SshRun,
  context: RunContext,
  options: { vaultLocked?: boolean } = {},
): LoginMessage {
  const explanation = explain(run);
  switch (explanation.kind) {
    case 'signedIn':
      if (context === 'install') {
        return { tone: 'ok', title: run.added === false ? 'keyPresent' : 'keyAdded' };
      }
      if (context === 'keyLogin') return { tone: 'ok', title: 'signedInKeyOnly' };
      if (explanation.password) {
        return {
          tone: 'ok',
          title: explanation.code ? 'signedInPasswordCode' : 'signedInPassword',
        };
      }
      return { tone: 'ok', title: context === 'vaultTest' ? 'signedInKey' : 'signedIn' };
    case 'hostKeyUnknown':
      return {
        tone: 'error',
        title: 'hostKeyUnknown',
        detail: 'hostKeyUnknownHint',
        action: 'checkHostKey',
      };
    case 'hostKeyChanged':
      return {
        tone: 'error',
        title: 'hostKeyChanged',
        detail: 'hostKeyChangedHint',
        action: 'checkHostKey',
      };
    case 'passwordRejected':
      return explanation.code
        ? {
            tone: 'error',
            title: 'passwordOrCodeRejected',
            detail: 'passwordOrCodeRejectedHint',
            action: 'editPassword',
          }
        : {
            tone: 'error',
            title: 'passwordRejected',
            detail: 'passwordRejectedHint',
            action: 'editPassword',
          };
    case 'passwordMissing':
      return {
        tone: 'error',
        title: 'passwordMissing',
        detail: 'passwordMissingHint',
        action: 'editPassword',
      };
    case 'otpMissing':
      return { tone: 'error', title: 'otpMissing', detail: 'otpMissingHint', action: 'addOtp' };
    case 'otpRejected':
      return {
        tone: 'error',
        title: 'otpRejected',
        detail: 'otpRejectedHint',
        action: 'editPassword',
      };
    case 'passphraseMissing':
      return {
        tone: 'error',
        title: 'passphraseMissing',
        detail: 'passphraseMissingHint',
        values: { key: explanation.key },
        action: 'unlockKey',
      };
    case 'otherAccount':
      return {
        tone: 'error',
        title: 'otherAccount',
        detail: 'otherAccountHint',
        values: { account: explanation.account },
      };
    case 'keysRejected':
      if (context === 'keyLogin') {
        return { tone: 'error', title: 'keyRejected', detail: 'keyRejectedHint' };
      }
      return {
        tone: 'error',
        title: 'keysRejected',
        detail: options.vaultLocked ? 'keysRejectedLockedHint' : 'keysRejectedHint',
      };
    case 'commandFailed':
      return context === 'install'
        ? { tone: 'error', title: 'installFailed', detail: 'installFailedHint' }
        : { tone: 'error', title: 'commandFailed' };
    case 'failed':
      return { tone: 'error', title: 'failed' };
  }
}
