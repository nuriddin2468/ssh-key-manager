// Where a host stands, for the list: a session open in the terminal, a check
// running, a key file that is gone, or what the last check or session found.

import type { ConnectionEvent } from '@/bindings/ConnectionEvent';
import type { ConnectionOutcome } from '@/bindings/ConnectionOutcome';

export type HostStatus =
  /** `tab`: the terminal tab of the session. */
  | { kind: 'connected'; tab: string }
  | { kind: 'connecting'; tab: string }
  | { kind: 'checking' }
  /** The config names a key file that isn't there. */
  | { kind: 'missingKey' }
  | { kind: 'last'; event: ConnectionEvent }
  | { kind: 'never' };

export type StatusTone = 'online' | 'ok' | 'warning' | 'error' | 'busy' | 'none';

/** A terminal tab, as far as the status needs it. */
export interface LiveTab {
  key: string;
  alias: string;
  phase: string;
}

export function hostStatus({
  aliases,
  tabs,
  checking,
  missingKey,
  events,
}: {
  aliases: readonly string[];
  tabs: readonly LiveTab[];
  checking: boolean;
  missingKey: boolean;
  /** Newest first. */
  events: readonly ConnectionEvent[];
}): HostStatus {
  const mine = tabs.filter((tab) => aliases.includes(tab.alias));
  const connected = mine.find((tab) => tab.phase === 'connected');
  if (connected) return { kind: 'connected', tab: connected.key };
  const connecting = mine.find((tab) => tab.phase === 'connecting');
  if (connecting) return { kind: 'connecting', tab: connecting.key };
  if (checking) return { kind: 'checking' };
  if (missingKey) return { kind: 'missingKey' };
  const [last] = events;
  return last ? { kind: 'last', event: last } : { kind: 'never' };
}

/**
 * Something to give or approve (a password, a passphrase, a new host key) is
 * a warning; a server that refused or couldn't be reached is an error.
 */
export function outcomeTone(outcome: ConnectionOutcome): 'ok' | 'warning' | 'error' {
  switch (outcome) {
    case 'signedIn':
      return 'ok';
    case 'passwordMissing':
    case 'passphraseMissing':
    case 'oneTimeCodeMissing':
    case 'hostKeyUnknown':
      return 'warning';
    default:
      return 'error';
  }
}

export function statusTone(status: HostStatus): StatusTone {
  switch (status.kind) {
    case 'connected':
      return 'online';
    case 'connecting':
    case 'checking':
      return 'busy';
    case 'missingKey':
      return 'warning';
    case 'last':
      return outcomeTone(status.event.outcome);
    case 'never':
      return 'none';
  }
}

/** The events of a host's aliases together, newest first. */
export function hostEvents(
  history: Readonly<Record<string, readonly ConnectionEvent[]>> | undefined,
  aliases: readonly string[],
): ConnectionEvent[] {
  const events = aliases.flatMap((alias) => history?.[alias] ?? []);
  // RFC 3339 times in UTC sort as text.
  return aliases.length > 1 ? events.sort((a, b) => b.at.localeCompare(a.at)) : events;
}
