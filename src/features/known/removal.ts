// Removing lines from `known_hosts`: line numbers only mean something in the
// revision of the file they were read from, so a removal names it.

import type { KnownHostEntry } from '@/bindings/KnownHostEntry';
import type { KnownHostsView } from '@/bindings/KnownHostsView';

export interface KnownHostsRemoval {
  lines: number[];
  /** The file's revision the lines belong to. */
  revision: string;
}

/**
 * Removes `entries`, found by another read of the file (a host key check),
 * from `view`: possible if each is on its line there still, the same in every
 * way. `null` when the file changed under them.
 */
export function removalOf(
  view: KnownHostsView,
  entries: readonly KnownHostEntry[],
): KnownHostsRemoval | null {
  const same = (a: KnownHostEntry, b: KnownHostEntry) =>
    a.line === b.line &&
    a.marker === b.marker &&
    a.hashed === b.hashed &&
    a.keyType === b.keyType &&
    a.fingerprint === b.fingerprint &&
    a.hosts.join(',') === b.hosts.join(',');
  const found = entries.every((entry) => view.entries.some((current) => same(current, entry)));
  return found && entries.length > 0
    ? { lines: entries.map((entry) => entry.line), revision: view.revision }
    : null;
}
