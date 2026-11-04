// Mock connection history for `pnpm dev` (see backend.ts): a few past
// events, then each check and terminal session recorded as the backend does.

import type { ConnectionEvent } from '@/bindings/ConnectionEvent';
import type { ConnectionOutcome } from '@/bindings/ConnectionOutcome';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { FailReason } from '@/bindings/FailReason';
import { explain } from '@/features/hosts/login';

const KEPT = 20;

const ago = (minutes: number) =>
  new Date(Date.now() - minutes * 60_000).toISOString().replace(/\.\d+Z$/, 'Z');

const history: Record<string, ConnectionEvent[]> = {
  'github.com': [{ at: ago(130), via: 'check', outcome: 'signedIn' }],
  'prod-api': [
    { at: ago(26 * 60), via: 'terminal', outcome: 'signedIn', durationSecs: 840 },
    { at: ago(3 * 24 * 60), via: 'check', outcome: 'signedIn' },
  ],
  bastion: [
    { at: ago(20 * 60), via: 'check', outcome: 'keysRejected' },
    { at: ago(4 * 24 * 60), via: 'terminal', outcome: 'signedIn', durationSecs: 1520 },
  ],
  'legacy-nas': [{ at: ago(5), via: 'check', outcome: 'hostKeyUnknown' }],
};

function record(alias: string, event: ConnectionEvent) {
  history[alias] = [event, ...(history[alias] ?? [])].slice(0, KEPT);
}

const CHECK_OUTCOME: Record<ReturnType<typeof explain>['kind'], ConnectionOutcome> = {
  signedIn: 'signedIn',
  hostKeyUnknown: 'hostKeyUnknown',
  hostKeyChanged: 'hostKeyChanged',
  passwordRejected: 'passwordRejected',
  passwordMissing: 'passwordMissing',
  otpMissing: 'oneTimeCodeMissing',
  otpRejected: 'oneTimeCodeRejected',
  passphraseMissing: 'passphraseMissing',
  otherAccount: 'failed',
  keysRejected: 'keysRejected',
  commandFailed: 'failed',
  failed: 'failed',
};

export function recordCheck(alias: string, test: ConnectionTest) {
  const kind = explain(test).kind;
  const unreachable = kind === 'failed' && /connect to host|timed out/.test(test.output);
  record(alias, {
    at: ago(0),
    via: 'check',
    outcome: unreachable ? 'unreachable' : CHECK_OUTCOME[kind],
  });
}

const FAILURE_OUTCOME: Record<FailReason, ConnectionOutcome | null> = {
  passwordRejected: 'passwordRejected',
  oneTimeCodeRejected: 'oneTimeCodeRejected',
  oneTimeCodeMissing: 'oneTimeCodeMissing',
  notAccepted: 'keysRejected',
  hostKeyNotTrusted: 'hostKeyUnknown',
  hostKeyChanged: 'hostKeyChanged',
  unreachable: 'unreachable',
  cancelled: null,
  other: 'failed',
};

export function recordSession(
  alias: string,
  at: string,
  change: { signedIn: true } | { failed: FailReason } | { durationSecs: number },
) {
  if ('signedIn' in change) {
    record(alias, { at, via: 'terminal', outcome: 'signedIn' });
  } else if ('failed' in change) {
    const outcome = FAILURE_OUTCOME[change.failed];
    if (outcome) record(alias, { at, via: 'terminal', outcome });
  } else {
    const event = history[alias]?.find(
      (e) => e.via === 'terminal' && e.at === at && e.durationSecs === undefined,
    );
    if (event) event.durationSecs = change.durationSecs;
  }
}

export const historyHandlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  connection_history: () => structuredClone(history),
  clear_connection_history: ({ alias }) => {
    delete history[String(alias)];
    return null;
  },
};
