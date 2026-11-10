import type { AiTool } from '@/bindings/AiTool';
import type { LeakFinding } from '@/bindings/LeakFinding';
import type { LeakPlace } from '@/bindings/LeakPlace';
import type { LeakSecret } from '@/bindings/LeakSecret';
import type { Severity } from '@/bindings/Severity';

/** Where a secret leaked to, as the audit groups and checks it. */
export type LeakKind = 'leakAi' | 'leakRepository' | 'leakLocalFile' | 'leakHistory';

export const LEAK_KINDS: LeakKind[] = ['leakAi', 'leakRepository', 'leakLocalFile', 'leakHistory'];

/** Ids of ignored leaks are kept with this prefix, apart from the others. */
export const LEAK_IGNORE_PREFIX = 'leaks:';

/** Tools' own names, the same in every language. */
export const AI_TOOL_NAMES: Record<AiTool, string> = {
  claudeCode: 'Claude Code',
  codex: 'Codex',
  geminiCli: 'Gemini CLI',
  continue: 'Continue',
  cline: 'Cline',
  rooCode: 'Roo Code',
  aider: 'Aider',
};

export const SHELL_NAMES = {
  zsh: 'zsh',
  bash: 'bash',
  fish: 'fish',
  powerShell: 'PowerShell',
} as const;

export function leakKind(place: LeakPlace): LeakKind {
  switch (place.kind) {
    case 'aiSession':
      return 'leakAi';
    case 'shellHistory':
      return 'leakHistory';
    case 'file':
      return place.git === 'tracked' || place.git === 'untracked'
        ? 'leakRepository'
        : 'leakLocalFile';
  }
}

/** Names a secret in ids, as the backend does: `var:<env>:<NAME>` or `entry:<id>`. */
export function secretKey(secret: LeakSecret): string {
  return secret.kind === 'variable'
    ? `var:${secret.envId}:${secret.name}`
    : `entry:${secret.entryId}`;
}

/** `project / env / NAME`, or the entry's title. */
export function secretLabel(secret: LeakSecret): string {
  return secret.kind === 'variable'
    ? [secret.project, secret.environment, secret.name].filter(Boolean).join(' / ')
    : secret.title;
}

/** One secret found in one kind of place, with every file it is in. */
export interface LeakGroup {
  ignoreId: string;
  kind: LeakKind;
  severity: Severity;
  secret: LeakSecret;
  /** Most severe first, then by path, as the backend sorts them. */
  findings: LeakFinding[];
}

const RANK: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };

/** The findings by secret and kind of place, in the order they first appear. */
export function groupLeaks(findings: readonly LeakFinding[]): LeakGroup[] {
  const groups = new Map<string, LeakGroup>();
  for (const finding of findings) {
    const kind = leakKind(finding.place);
    const id = `${LEAK_IGNORE_PREFIX}${kind}:${secretKey(finding.secret)}`;
    const group = groups.get(id);
    if (group) {
      group.findings.push(finding);
      if (RANK[finding.severity] < RANK[group.severity]) group.severity = finding.severity;
    } else {
      groups.set(id, {
        ignoreId: id,
        kind,
        severity: finding.severity,
        secret: finding.secret,
        findings: [finding],
      });
    }
  }
  return [...groups.values()];
}

/** The tools (or shells) a group's files belong to, each once, in order. */
export function placeNames(group: LeakGroup): string[] {
  const names: string[] = [];
  for (const { place } of group.findings) {
    const name =
      place.kind === 'aiSession'
        ? AI_TOOL_NAMES[place.tool]
        : place.kind === 'shellHistory'
          ? SHELL_NAMES[place.shell]
          : null;
    if (name && !names.includes(name)) names.push(name);
  }
  return names;
}

/** The Git working trees a group's files are in, each once. */
export function repositories(group: LeakGroup): string[] {
  const out: string[] = [];
  for (const { place } of group.findings) {
    if (place.kind === 'file' && place.repository && !out.includes(place.repository)) {
      out.push(place.repository);
    }
  }
  return out;
}

/** The last part of a path, for labels. */
export function baseName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

/** The file and its folder (`shop-api/.env`), so two `.env` files get different labels. */
export function shortPath(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).slice(-2).join('/') || path;
}

/** How far a scan got, 0–100; `null` while it is still finding files. */
export function scanPercent(status: {
  phase: 'listing' | 'reading' | null;
  bytesDone: number;
  bytesTotal: number;
}): number | null {
  if (status.phase !== 'reading') return null;
  if (status.bytesTotal <= 0) return 0;
  return Math.min(100, Math.floor((status.bytesDone / status.bytesTotal) * 100));
}
