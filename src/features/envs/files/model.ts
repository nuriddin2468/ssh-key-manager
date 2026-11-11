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

/** A sentence on what the state means and what happens next. */
export function stateText(t: TFunction, state: FileState): string {
  switch (state.type) {
    case 'invalid': {
      const lines = state.problems.map((problem) => problem.line);
      return t('envs.files.explain.invalid', { count: lines.length, lines: lines.join(', ') });
    }
    case 'failed':
      return state.message;
    default:
      return t(`envs.files.explain.${state.type}`);
  }
}

/** The file's path as the binding names it: its project folder and the path in it. */
export function bindingPath(file: EnvFile): string {
  const folder = file.folder.replace(/[\\/]+$/, '');
  const separator = folder.includes('\\') && !folder.includes('/') ? '\\' : '/';
  return `${folder}${separator}${file.path}`;
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

/** The statuses of one environment's files, in its bindings' order. */
export function filesOf(statuses: EnvFileStatus[] | undefined, envId: string): EnvFileStatus[] {
  return (statuses ?? []).filter((status) => status.envId === envId);
}

/** Names of a `.env` file people use most. */
export const QUICK_NAMES = ['.env', '.env.local', '.env.development.local'] as const;
