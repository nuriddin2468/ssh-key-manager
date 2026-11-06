import type { TFunction } from 'i18next';
import type { LineOptions } from '@/bindings/LineOptions';
import type { LineProblem } from '@/bindings/LineProblem';

/** The builder's form; text fields as typed. */
export interface LineForm {
  publicKey: string;
  restrict: boolean;
  /** Comma-separated patterns. */
  from: string;
  command: string;
  /** `YYYY-MM-DD` from the date field; empty for none. */
  expiry: string;
  noPortForwarding: boolean;
  noAgentForwarding: boolean;
  noPty: boolean;
  noX11Forwarding: boolean;
}

export type Field = 'key' | 'from' | 'command' | 'expiry';

/** What the core builds the line from. */
export function optionsOf(form: LineForm): LineOptions {
  return {
    restrict: form.restrict,
    from: form.from
      .split(',')
      .map((pattern) => pattern.trim())
      .filter(Boolean),
    command: form.command.trim() || null,
    // `expiry-time` takes YYYYMMDD; the date field gives YYYY-MM-DD.
    expiryTime: form.expiry ? form.expiry.replaceAll('-', '') : null,
    noPortForwarding: form.noPortForwarding,
    noAgentForwarding: form.noAgentForwarding,
    noPty: form.noPty,
    noX11Forwarding: form.noX11Forwarding,
  };
}

function fieldOf(problem: LineProblem): Field {
  switch (problem.kind) {
    case 'keyMissing':
    case 'keyPrivate':
    case 'keyInvalid':
      return 'key';
    case 'fromInvalid':
    case 'fromOnlyExcludes':
      return 'from';
    case 'commandInvalid':
      return 'command';
    case 'expiryInvalid':
    case 'expiryPast':
      return 'expiry';
  }
}

/** The first problem of each field, in words. */
export function problemsByField(
  t: TFunction,
  problems: readonly LineProblem[],
): Partial<Record<Field, string>> {
  const out: Partial<Record<Field, string>> = {};
  for (const problem of problems) {
    const field = fieldOf(problem);
    out[field] ??= t(`toolSsh.line.problem.${problem.kind}`, {
      pattern: problem.kind === 'fromInvalid' ? problem.pattern : '',
    });
  }
  return out;
}
