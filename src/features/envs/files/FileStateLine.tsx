import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { EnvFileStatus } from '@/bindings/EnvFileStatus';
import { cn } from '@/lib/cn';
import { liveReport, needsAttention, type StateTone } from './model';
import { useFileRisks, useFileStatuses } from './queries';

/** One line on where an environment's files stand, and its tone. */
export interface FileLine {
  text: string;
  tone: StateTone;
  /** A file needs the user: the line leads to it. */
  attention: boolean;
}

/**
 * Sums up an environment's files: how many need attention (a state to act
 * on, Git or a cloud folder that would take the values along, missing
 * names), else syncing, else in sync; files whose folder isn't on this
 * computer only, said so. `null` for an environment without files.
 */
export function fileLine(
  t: TFunction,
  envId: string,
  statuses: EnvFileStatus[] | undefined,
  risks: EnvFileReport[] | undefined,
): FileLine | null {
  const mine = (statuses ?? []).filter((status) => status.envId === envId);
  if (mine.length === 0) return null;
  const attention = mine.filter((status) => needsAttention(liveReport(status, risks))).length;
  if (attention > 0) {
    return {
      text: t('envs.files.line.attention', { count: attention }),
      tone: 'warning',
      attention: true,
    };
  }
  const types = mine.map((status) => status.state.type);
  if (types.some((type) => type === 'fileChanged' || type === 'vaultChanged')) {
    return { text: t('envs.files.line.syncing'), tone: 'info', attention: false };
  }
  if (types.every((type) => type === 'folderMissing')) {
    return { text: t('envs.files.line.away'), tone: 'neutral', attention: false };
  }
  const inSync = types.filter((type) => type === 'inSync').length;
  return {
    text: t('envs.files.line.inSync', { count: inSync }),
    tone: inSync === mine.length ? 'ok' : 'neutral',
    attention: false,
  };
}

const DOT: Record<StateTone, string> = {
  ok: 'bg-ok',
  info: 'bg-info-solid',
  warning: 'bg-warning-solid',
  critical: 'bg-critical-solid',
  neutral: 'bg-white/30',
};

const TEXT: Record<StateTone, string> = {
  ok: 'text-subtle',
  info: 'text-info',
  warning: 'text-warning',
  critical: 'text-critical',
  neutral: 'text-subtle',
};

interface FileStateLineProps {
  envId: string;
  /** Names the environment in the link's label: `shop-api · dev`. */
  label: string;
  /** Opens the environment's files: where a file that needs the user is. */
  onOpen: () => void;
}

/**
 * Where an environment's files stand, on one line with a dot of its tone,
 * for a list of environments (a project's page); a link to them when one
 * needs the user. Nothing for an environment without files.
 */
export function FileStateLine({ envId, label, onOpen }: FileStateLineProps) {
  const { t } = useTranslation();
  const statuses = useFileStatuses();
  const risks = useFileRisks();
  const line = fileLine(t, envId, statuses.data, risks.data);
  if (!line) return null;
  const content = (
    <>
      <span aria-hidden="true" className={cn('size-1.5 shrink-0 rounded-full', DOT[line.tone])} />
      <span className="truncate">{line.text}</span>
    </>
  );
  if (!line.attention) {
    return (
      <span className={cn('inline-flex max-w-full items-center gap-1.5', TEXT[line.tone])}>
        {content}
      </span>
    );
  }
  return (
    <button
      type="button"
      aria-label={t('envs.files.line.open', { env: label, state: line.text })}
      onClick={onOpen}
      className={cn(
        '-my-0.5 inline-flex max-w-full items-center gap-1.5 rounded py-0.5 text-left decoration-current/40 underline-offset-[3px] outline-none hover:underline focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.6)]',
        TEXT[line.tone],
      )}
    >
      {content}
    </button>
  );
}
