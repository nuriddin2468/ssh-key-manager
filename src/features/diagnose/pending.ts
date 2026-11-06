// A fix asked for outside the host's editor (in the terminal) that only the
// editor can make: it runs it when it opens for the host, right after.

import type { Diagnosis } from '@/bindings/Diagnosis';
import type { DiagnoseFix } from './model';

export interface PendingFix {
  fix: DiagnoseFix;
  diagnosis: Diagnosis;
}

/** A fix the editor couldn't make by then is dropped, so it never surprises later. */
const LIFETIME_MS = 10_000;

let pending: (PendingFix & { alias: string; at: number }) | null = null;

export function requestHostFix(alias: string, fix: DiagnoseFix, diagnosis: Diagnosis) {
  pending = { alias, fix, diagnosis, at: Date.now() };
}

/** The fix waiting for one of `aliases`, once `ready` says it can be made. */
export function takeHostFix(
  aliases: readonly string[],
  ready: (fix: DiagnoseFix) => boolean,
): PendingFix | undefined {
  if (pending && Date.now() - pending.at > LIFETIME_MS) pending = null;
  if (!pending || !aliases.includes(pending.alias) || !ready(pending.fix)) return undefined;
  const { fix, diagnosis } = pending;
  pending = null;
  return { fix, diagnosis };
}
