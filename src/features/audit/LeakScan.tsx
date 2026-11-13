import { useMutation, useQuery } from '@tanstack/react-query';
import { CircleCheck, FolderPlus, ScanSearch, X } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { queryClient, useEnvironment } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import type { LeakStatus } from '@/bindings/LeakStatus';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { IconButton } from '@/components/ui/IconButton';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { displayPath } from '@/lib/format';
import { AI_TOOL_NAMES, scanPercent } from './leakModel';

export const leakKeys = {
  status: ['leaks', 'status'] as const,
  findings: ['leaks', 'findings'] as const,
};

/**
 * The leak scanner's state: polled while a scan runs, and its findings are
 * read again when it ends.
 */
export function useLeakStatus(): LeakStatus | undefined {
  const status = useQuery({
    queryKey: leakKeys.status,
    queryFn: api.leaksStatus,
    refetchInterval: (query) => (query.state.data?.phase ? 400 : false),
  });
  const running = Boolean(status.data?.phase);
  const wasRunning = useRef(running);
  useEffect(() => {
    if (wasRunning.current && !running) {
      void queryClient.invalidateQueries({ queryKey: leakKeys.findings });
    }
    wasRunning.current = running;
  }, [running]);
  return status.data;
}

/** A command that answers with the new status, which replaces the old one. */
function useStatusAction<T>(run: (vars: T) => Promise<LeakStatus>) {
  const { t } = useTranslation();
  return useMutation({
    mutationFn: run,
    gcTime: 0,
    onSuccess: (status) => queryClient.setQueryData(leakKeys.status, status),
    onError: (error) => toastError(t, error),
  });
}

interface LeakScanCardProps {
  status: LeakStatus;
  /** The vault is locked: the scanner needs its values. */
  locked: boolean;
}

/**
 * The leak scanner: where it looks, Scan and Cancel, and how the scan is
 * going or went. Sources are open until the first scan.
 */
export function LeakScanCard({ status, locked }: LeakScanCardProps) {
  const { t, i18n } = useTranslation();
  const id = useId();
  const dialogs = useDialogs();
  const [sourcesOpen, setSourcesOpen] = useState<boolean | null>(null);
  const running = status.phase !== null;
  const scanned = status.scannedAt !== null;
  const sourcesShown = !running && (sourcesOpen ?? !scanned);

  const start = useStatusAction(() => api.leaksStart());
  const cancel = useMutation({
    mutationFn: () => api.leaksCancel(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: leakKeys.status }),
  });

  let action: { label: string; variant: 'primary' | 'secondary'; run: () => void };
  if (locked) {
    action = {
      label: t('audit.leaks.unlock'),
      variant: 'primary',
      run: () => dialogs.unlockVault({ description: t('audit.leaks.lockedText') }),
    };
  } else if (running) {
    action = { label: t('common.cancel'), variant: 'secondary', run: () => cancel.mutate() };
  } else {
    action = {
      label: scanned ? t('audit.leaks.scanAgain') : t('audit.leaks.scan'),
      variant: scanned ? 'secondary' : 'primary',
      run: () => start.mutate(undefined),
    };
  }

  return (
    <section
      aria-labelledby={`${id}-h`}
      className="glass flex flex-col gap-3 rounded-2xl px-4 py-[13px]"
    >
      <div className="flex flex-wrap items-center gap-x-3.5 gap-y-3">
        <Tile tone="orange" size={36}>
          <ScanSearch className="size-[18px]" strokeWidth={2} />
        </Tile>
        <span className="flex min-w-[240px] flex-1 flex-col gap-0.5">
          <h2 id={`${id}-h`} className="text-[13px] leading-5 font-semibold">
            {t('audit.leaks.title')}
          </h2>
          <span className="text-[12.5px] text-muted">
            {locked ? t('audit.leaks.lockedText') : t('audit.leaks.lead')}
          </span>
        </span>
        <span className="flex shrink-0 flex-wrap gap-1.5">
          {!running && !locked ? (
            <Button
              variant="ghost"
              size="sm"
              aria-expanded={sourcesShown}
              aria-controls={sourcesShown ? `${id}-sources` : undefined}
              onClick={() => setSourcesOpen(!sourcesShown)}
            >
              {t('audit.leaks.sources')}
            </Button>
          ) : null}
          {/* One element whose label changes, so focus stays on it. */}
          <Button
            key="leak-scan-action"
            size="sm"
            variant={action.variant}
            onClick={() => {
              if (!start.isPending) action.run();
            }}
          >
            {action.label}
          </Button>
        </span>
      </div>

      {sourcesShown && !locked ? <Sources id={`${id}-sources`} status={status} /> : null}

      {locked ? null : <ScanLine status={status} language={i18n.language} />}
    </section>
  );
}

/** Where to look: AI tools' history, the shell history, the folders picked. */
function Sources({ id, status }: { id: string; status: LeakStatus }) {
  const { t, i18n } = useTranslation();
  const home = useEnvironment().data?.paths.home;
  const setSources = useStatusAction((next: { ai: boolean; history: boolean }) =>
    api.leaksSetSources(next.ai, next.history),
  );
  const addFolders = useStatusAction(() => api.leaksAddFolders());
  const removeFolder = useStatusAction((folder: string) => api.leaksRemoveFolder(folder));
  const { ai, history, folders } = status.settings;
  const found = status.tools.filter((tool) => tool.found).map((tool) => AI_TOOL_NAMES[tool.tool]);
  const list = new Intl.ListFormat(i18n.language, { type: 'conjunction' });

  const hint = (text: string) => (
    <span className="block text-[12px] leading-[18px] font-normal text-subtle">{text}</span>
  );

  return (
    <fieldset
      id={id}
      className="m-0 flex min-w-0 flex-col gap-2.5 border-0 border-t border-line-soft p-0 pt-3"
    >
      <legend className="sr-only">{t('audit.leaks.sources')}</legend>
      <Checkbox
        checked={ai}
        disabled={setSources.isPending}
        onCheckedChange={(next) => setSources.mutate({ ai: next, history })}
        label={
          <>
            {t('audit.leaks.sourceAi')}
            {hint(
              found.length > 0
                ? t('audit.leaks.sourceAiFound', { tools: list.format(found) })
                : t('audit.leaks.sourceAiNone'),
            )}
          </>
        }
      />
      <Checkbox
        checked={history}
        disabled={setSources.isPending}
        onCheckedChange={(next) => setSources.mutate({ ai, history: next })}
        label={
          <>
            {t('audit.leaks.sourceHistory')}
            {hint(t('audit.leaks.sourceHistoryHint'))}
          </>
        }
      />
      <div className="flex flex-col gap-2 pl-[28px]">
        <span className="leading-[22px] font-medium text-fg">
          {t('audit.leaks.sourceFolders')}
          {hint(t('audit.leaks.sourceFoldersHint'))}
        </span>
        {folders.length > 0 ? (
          <ul className="flex flex-wrap gap-1.5">
            {folders.map((folder) => (
              <li
                key={folder}
                className="inline-flex h-7 max-w-full items-center gap-1 rounded-md border border-line-strong bg-fill pr-0.5 pl-2 font-mono text-[11.5px] text-fg-2"
              >
                <span className="truncate" title={folder}>
                  {displayPath(folder, home)}
                </span>
                <IconButton
                  label={t('audit.leaks.removeFolder', { folder: displayPath(folder, home) })}
                  variant="ghost"
                  className="size-6 shrink-0"
                  icon={<X className="size-3.5" strokeWidth={2} />}
                  disabled={removeFolder.isPending}
                  onClick={() => removeFolder.mutate(folder)}
                />
              </li>
            ))}
          </ul>
        ) : null}
        <span>
          <Button
            variant="ghost"
            size="sm"
            className="-ml-2"
            icon={<FolderPlus className="size-4" strokeWidth={1.9} />}
            loading={addFolders.isPending}
            onClick={() => addFolders.mutate(undefined)}
          >
            {t('audit.leaks.addFolder')}
          </Button>
        </span>
      </div>
    </fieldset>
  );
}

/** The running scan's progress, or how the last one went. */
function ScanLine({ status, language }: { status: LeakStatus; language: string }) {
  const { t } = useTranslation();
  const number = new Intl.NumberFormat(language);
  const percent = scanPercent(status);
  const running = status.phase !== null;

  let text: string;
  let tone = 'text-subtle';
  let clean = false;
  if (status.phase === 'listing') {
    text = t('audit.leaks.listing');
  } else if (status.phase === 'reading') {
    text = t('audit.leaks.reading', {
      done: number.format(status.filesDone),
      total: number.format(status.filesTotal),
      count: status.filesTotal,
    });
  } else if (status.stopped) {
    tone = 'text-warning';
    text = t(`audit.leaks.stopped.${status.stopped}`);
  } else if (status.scannedAt) {
    const time = new Intl.DateTimeFormat(language, { timeStyle: 'short' }).format(
      new Date(status.scannedAt),
    );
    const files = number.format(status.filesScanned);
    clean = status.findings === 0;
    tone = clean ? 'text-ok' : 'text-muted';
    const parts: string[] = [
      clean
        ? t('audit.leaks.doneClean', { time, files, count: status.filesScanned })
        : t('audit.leaks.doneFound', {
            time,
            count: status.leaked,
            found: number.format(status.leaked),
          }),
    ];
    if (status.unreadable > 0) {
      parts.push(t('audit.leaks.unreadable', { count: status.unreadable }));
    }
    if (status.truncated) parts.push(t('audit.leaks.truncated'));
    text = parts.join(' · ');
  } else {
    text = t('audit.leaks.notScanned');
  }

  return (
    <div className="flex flex-col gap-2">
      {running ? (
        <div
          role="progressbar"
          aria-label={t('audit.leaks.title')}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={percent ?? undefined}
          aria-valuetext={text}
          className="h-1.5 overflow-hidden rounded-full bg-ink/[0.08]"
        >
          <div
            className={cn(
              'h-full rounded-full bg-[var(--accent-2)] transition-[width] duration-300',
              percent === null && 'w-1/3 animate-pulse',
            )}
            style={percent === null ? undefined : { width: `${Math.max(percent, 2)}%` }}
          />
        </div>
      ) : null}
      <p className={cn('flex items-center gap-1.5 text-[12px]', tone)}>
        {clean ? <CircleCheck aria-hidden="true" className="size-3.5" strokeWidth={2} /> : null}
        {/* Announced when the scan starts, ends or stops, not at every step. */}
        <span aria-hidden={running || undefined}>{text}</span>
        {running && percent !== null ? (
          <span aria-hidden="true" className="ml-auto text-subtle tabular-nums">
            {percent}%
          </span>
        ) : null}
      </p>
      <span role="status" className="sr-only">
        {running ? t('audit.leaks.scanningShort') : text}
      </span>
    </div>
  );
}
