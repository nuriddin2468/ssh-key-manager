// How the files environments are written to are shown: each state's tone,
// icon and words, and which files need the user (src-tauri/src/commands/env_files.rs).

import type { TFunction } from 'i18next';
import {
  AlertOctagon,
  CheckCircle2,
  Copy,
  FileWarning,
  FileX2,
  FolderX,
  GitCompareArrows,
  type LucideIcon,
  PauseCircle,
  RefreshCw,
  ShieldAlert,
} from 'lucide-react';
import type { CloudService } from '@/bindings/CloudService';
import type { EnvFile } from '@/bindings/EnvFile';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { EnvFileStatus } from '@/bindings/EnvFileStatus';
import type { FileLevel } from '@/bindings/FileLevel';
import type { FileState } from '@/bindings/FileState';

export type StateTone = 'ok' | 'info' | 'warning' | 'critical' | 'neutral';

/** Text and tile classes per tone, from the app's severity colors. */
export const TONE_CLASSES: Record<StateTone, { text: string; tile: string }> = {
  ok: { text: 'text-ok', tile: 'border-ok/30 bg-ok/10 text-ok' },
  info: { text: 'text-info', tile: 'border-info-solid/30 bg-info-solid/11 text-info' },
  warning: {
    text: 'text-warning',
    tile: 'border-warning-solid/30 bg-warning-solid/11 text-warning',
  },
  critical: {
    text: 'text-critical',
    tile: 'border-critical-solid/30 bg-critical-solid/12 text-critical',
  },
  neutral: { text: 'text-muted', tile: 'border-white/10 bg-white/[0.05] text-muted' },
};

const LOOK: Record<FileState['type'], { tone: StateTone; icon: LucideIcon }> = {
  inSync: { tone: 'ok', icon: CheckCircle2 },
  fileChanged: { tone: 'info', icon: RefreshCw },
  vaultChanged: { tone: 'info', icon: RefreshCw },
  conflict: { tone: 'warning', icon: GitCompareArrows },
  missing: { tone: 'warning', icon: FileX2 },
  folderMissing: { tone: 'neutral', icon: FolderX },
  inactive: { tone: 'neutral', icon: PauseCircle },
  invalid: { tone: 'warning', icon: FileWarning },
  duplicate: { tone: 'warning', icon: Copy },
  refused: { tone: 'critical', icon: ShieldAlert },
  failed: { tone: 'critical', icon: AlertOctagon },
};

export function stateLook(state: FileState) {
  return LOOK[state.type];
}

/** A short label for the state. */
export function stateLabel(t: TFunction, state: FileState): string {
  switch (state.type) {
    case 'inactive':
      return t(`envs.files.state.inactive.${state.reason}`);
    case 'refused':
      return t(`envs.files.state.refused.${state.reason}`);
    default:
      return t(`envs.files.state.${state.type}`);
  }
}

/**
 * A sentence on what the state means and what to do next. A failure's own
 * message, in English from the backend, is for `title`: see [`stateDetail`].
 */
export function stateText(t: TFunction, state: FileState): string {
  switch (state.type) {
    case 'invalid': {
      const lines = state.problems.map((problem) => problem.line);
      return t('envs.files.explain.invalid', { count: lines.length, lines: lines.join(', ') });
    }
    case 'inactive':
      return t(`envs.files.explain.inactive.${state.reason}`);
    case 'refused':
      return t(`envs.files.explain.refused.${state.reason}`);
    default:
      return t(`envs.files.explain.${state.type}`);
  }
}

/** What the backend said about a failure (paths, never values), if anything. */
export function stateDetail(state: FileState): string | undefined {
  return state.type === 'failed' ? state.message : undefined;
}

/** The file's path as the binding names it: its project folder and the path in it. */
export function bindingPath(file: EnvFile): string {
  const folder = file.folder.replace(/[\\/]+$/, '');
  const separator = folder.includes('\\') && !folder.includes('/') ? '\\' : '/';
  return `${folder}${separator}${file.path}`;
}

/** A file's level, by the environment's lists of level-2 and level-3 files. */
export function levelOf(
  file: EnvFile,
  whileUnlocked: readonly EnvFile[],
  virtualFiles: readonly EnvFile[],
): FileLevel {
  if (virtualFiles.some((x) => sameFile(x, file))) return 'virtual';
  if (whileUnlocked.some((x) => sameFile(x, file))) return 'whileUnlocked';
  return 'always';
}

/**
 * A file's state as its row says it: a virtual file in step is served, and
 * one still to come is its pipe being made.
 */
export function levelStateLabel(t: TFunction, state: FileState, level: FileLevel): string {
  if (level === 'virtual' && state.type === 'inSync') return t('envs.files.state.served');
  if (level === 'virtual' && state.type === 'vaultChanged') return t('envs.files.state.makingPipe');
  return stateLabel(t, state);
}

/** What a state means for a file at `level`, as [`stateText`]. */
export function levelStateText(t: TFunction, state: FileState, level: FileLevel): string {
  if (level === 'virtual' && state.type === 'conflict') {
    return t('envs.files.explain.conflictVirtual');
  }
  return stateText(t, state);
}

/** The file's name, the last part of its path. */
export function fileName(file: EnvFile): string {
  return file.path.split('/').at(-1) ?? file.path;
}

export function sameFile(a: EnvFile, b: EnvFile): boolean {
  return a.folder === b.folder && a.path === b.path;
}

/** A file whose state asks the user for something. */
export function needsAction(state: FileState): boolean {
  return (
    ['conflict', 'missing', 'invalid', 'duplicate', 'refused', 'failed'].includes(state.type) ||
    (state.type === 'inactive' && state.reason === 'notInProject')
  );
}

export function gitRisk(report: EnvFileReport): boolean {
  return report.git?.state === 'untracked' || report.git?.state === 'tracked';
}

export function missingNames(report: EnvFileReport): string[] {
  return report.example?.missing ?? [];
}

/** A file in the management center that needs the user's attention. */
export function needsAttention(report: EnvFileReport): boolean {
  return (
    needsAction(report.state) ||
    gitRisk(report) ||
    report.cloud !== null ||
    missingNames(report).length > 0
  );
}

/**
 * A file's report with the state it has now: states refresh with the
 * environments, reports only now and then. A file without a report yet
 * (just bound) goes by its state alone.
 */
export function liveReport(
  status: EnvFileStatus,
  reports: readonly EnvFileReport[] | undefined,
): EnvFileReport {
  const report = reports?.find(
    (item) => item.envId === status.envId && sameFile(item.file, status.file),
  );
  return report
    ? { ...report, state: status.state }
    : { ...status, projects: [], cloud: null, example: null, git: null };
}

/**
 * A project's files that need the user: the reports know the projects that
 * hold each file's folder, the states (once known) what each file is now
 * and which are still written to.
 */
export function projectFilesNeedingAttention(
  projectId: string,
  statuses: readonly EnvFileStatus[] | undefined,
  reports: readonly EnvFileReport[] | undefined,
): EnvFileReport[] {
  return (reports ?? []).flatMap((report) => {
    if (!report.projects.includes(projectId)) return [];
    if (!statuses) return needsAttention(report) ? [report] : [];
    const status = statuses.find(
      (item) => item.envId === report.envId && sameFile(item.file, report.file),
    );
    const live = status ? { ...report, state: status.state } : null;
    return live && needsAttention(live) ? [live] : [];
  });
}

export type CenterFilter = 'all' | 'attention' | 'git' | 'cloud' | 'example';

export function matchesFilter(report: EnvFileReport, filter: CenterFilter): boolean {
  switch (filter) {
    case 'all':
      return true;
    case 'attention':
      return needsAttention(report);
    case 'git':
      return gitRisk(report);
    case 'cloud':
      return report.cloud !== null;
    case 'example':
      return missingNames(report).length > 0;
  }
}

export function cloudName(t: TFunction, service: CloudService): string {
  return t(`envs.center.services.${service}`);
}

/** The badge for a file in a cloud folder. */
export function cloudBadge(t: TFunction, service: CloudService): string {
  return service === 'other'
    ? t('envs.center.cloudBadgeOther')
    : t('envs.center.cloudBadge', { service: cloudName(t, service) });
}

/** What a cloud folder means for a file. */
export function cloudText(t: TFunction, service: CloudService): string {
  return service === 'other'
    ? t('envs.center.cloudTextOther')
    : t('envs.center.cloudText', { service: cloudName(t, service) });
}

/** The statuses of one environment's files, in its bindings' order. */
export function filesOf(statuses: EnvFileStatus[] | undefined, envId: string): EnvFileStatus[] {
  return (statuses ?? []).filter((status) => status.envId === envId);
}

const TEMPLATE_WORDS = ['example', 'sample', 'template', 'dist', 'defaults', 'tmpl'];

/** `.env.example`, `.env.local.sample`, `example.env`: a template to commit, never written. */
export function isTemplateName(name: string): boolean {
  const last = name.split(/[/\\]/).at(-1) ?? name;
  return last
    .toLowerCase()
    .split('.')
    .some((part) => TEMPLATE_WORDS.includes(part));
}

/** Names of a `.env` file people use most. */
export const QUICK_NAMES = ['.env', '.env.local', '.env.development.local'] as const;
