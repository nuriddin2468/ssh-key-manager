// How a TLS check reads: its headline, and what each certificate of the
// chain is.

import type { CertProblem } from '@/bindings/CertProblem';
import type { CertSummary } from '@/bindings/CertSummary';
import type { TlsReport } from '@/bindings/TlsReport';
import type { BadgeTone } from '@/components/ui/Badge';

/** A trusted certificate this close to its end gets a warning. */
export const SOON_DAYS = 30;
/** Names of a certificate listed before "and N more". */
export const NAMES_SHOWN = 6;

const HINTS = ['unknownIssuer', 'selfSigned', 'nameMismatch', 'notYetValid'] as const;
type Hint = (typeof HINTS)[number];

export interface Headline {
  tone: BadgeTone;
  badge: 'trusted' | 'expiring' | 'notTrusted';
  /** Why it isn't trusted; a lone self-signed certificate says so. */
  problem: CertProblem | 'selfSigned' | null;
  hint: Hint | null;
  expiresSoon: boolean;
}

/** The headline of a check whose handshake finished. */
export function headline(report: TlsReport): Headline {
  const leaf = report.chain[0];
  if (report.trusted) {
    const soon = leaf !== undefined && leaf.daysLeft <= SOON_DAYS;
    return {
      tone: soon ? 'warning' : 'accent',
      badge: soon ? 'expiring' : 'trusted',
      problem: null,
      hint: null,
      expiresSoon: soon,
    };
  }
  let problem: Headline['problem'] = report.problem ?? 'other';
  if (problem === 'unknownIssuer' && report.chain.length === 1 && leaf?.selfSigned) {
    problem = 'selfSigned';
  }
  const hint = HINTS.find((h) => h === problem) ?? null;
  return { tone: 'critical', badge: 'notTrusted', problem, hint, expiresSoon: false };
}

/** The server's own certificate comes first; a self-signed one later is a root. */
export function roleOf(
  chain: readonly CertSummary[],
  index: number,
): 'server' | 'intermediate' | 'root' {
  if (index === 0) return 'server';
  return chain[index]?.selfSigned ? 'root' : 'intermediate';
}
