import { useQuery } from '@tanstack/react-query';
import { FileDiff, Info, Laptop, Lock, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { errorMessage } from '@/api/useAppMutation';
import type { HostsApplyResult } from '@/bindings/HostsApplyResult';
import type { HostsChange } from '@/bindings/HostsChange';
import type { HostsDiffLine } from '@/bindings/HostsDiffLine';
import type { HostsFileInfo } from '@/bindings/HostsFileInfo';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { SwitchRow } from '@/components/ui/Switch';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { AppError } from '@/lib/ipc';
import { useHostsApply } from './useHostsApply';

/** A group another computer sent, which the changes add. */
export interface ReceivedNote {
  /** Its name in the draft. */
  group: string;
  /** The other computer. */
  from: string;
  count: number;
}

/** Something the person should know before saving, shown above the diff. */
export interface ReviewNote {
  tone: 'info' | 'warning';
  text: string;
}

interface ReviewDialogProps {
  revision: string;
  changes: HostsChange[];
  /** Saving found the file changed elsewhere; these are the changes carried over to it. */
  conflict: boolean;
  received?: ReceivedNote;
  /** Read out with the description too, so nobody saves without them. */
  notes?: ReviewNote[];
  /** The toast after saving can undo it through the backup it made. */
  undoable?: boolean;
  /** The file was written. */
  onApplied: (result: HostsApplyResult) => void;
  /** The file changed elsewhere (`file` is how it is now), so nothing was written. */
  onStale: (file: HostsFileInfo) => void;
  onDone: () => void;
}

const ROW_STYLE = {
  same: { sign: ' ', className: 'text-muted' },
  added: { sign: '+', className: 'bg-ok/[0.09] text-ok' },
  removed: { sign: '−', className: 'bg-critical-solid/10 text-critical' },
  skipped: { sign: ' ', className: 'text-subtle italic' },
} as const;

/** The diff of the drafted changes, applied with the administrator password. */
export function ReviewDialog({
  revision,
  changes,
  conflict,
  received,
  notes = [],
  undoable = false,
  onApplied,
  onStale,
  onDone,
}: ReviewDialogProps) {
  const { t } = useTranslation();
  const [flushDns, setFlushDns] = useState(true);
  const { apply } = useHostsApply({ undo: undoable });
  const preview = useQuery({
    queryKey: ['hosts-file', 'preview', revision, changes],
    queryFn: () => api.previewHostsChanges(revision, changes),
    staleTime: Number.POSITIVE_INFINITY,
    refetchOnWindowFocus: false,
  });
  const stale = preview.data?.stale ?? false;
  // The file may already read this way (it changed while the review was
  // open): then there is nothing to write, nor a password to ask for.
  const changing =
    preview.data?.diff.some((line) => line.kind === 'added' || line.kind === 'removed') ?? false;
  const receivedText = received
    ? t('hostsFile.received', {
        count: received.count,
        from: received.from,
        name: received.group,
      })
    : null;

  const submit = () =>
    apply.mutate(
      { revision, changes, flushDns },
      {
        onSuccess: (result) => {
          if (result.outcome === 'applied') onApplied(result);
          else if (result.outcome === 'stale') onStale(result.file);
        },
      },
    );

  return (
    <DialogContent section="hostsFile" className="max-w-[760px]">
      <DialogHeader
        icon={
          <Tile tone="indigo" size={44} glow>
            <FileDiff className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('hostsFile.reviewTitle')}
        description={
          <>
            {t('hostsFile.reviewDescription')}
            {/* Read when the dialog opens: where the changes came from. */}
            {receivedText ? <span className="sr-only"> {receivedText}</span> : null}
            {notes.map((note) => (
              <span key={note.text} className="sr-only">
                {' '}
                {note.text}
              </span>
            ))}
          </>
        }
      />
      <DialogBody>
        {receivedText ? (
          // The dialog's description says it to screen readers already.
          <p
            aria-hidden="true"
            className="flex gap-2.5 rounded-xl border border-info-solid/30 bg-info-solid/[0.09] px-3 py-2.5 text-[12.5px] leading-[18px] text-fg-2"
          >
            <Laptop className="mt-0.5 size-4 shrink-0 text-info" strokeWidth={2} />
            {receivedText}
          </p>
        ) : null}
        {notes.map((note) => (
          // The dialog's description says it to screen readers already.
          <p
            key={note.text}
            aria-hidden="true"
            className={cn(
              'flex gap-2.5 rounded-xl border px-3 py-2.5 text-[12.5px] leading-[18px] text-fg-2',
              note.tone === 'warning'
                ? 'border-warning-solid/30 bg-warning-solid/[0.09]'
                : 'border-info-solid/30 bg-info-solid/[0.09]',
            )}
          >
            {note.tone === 'warning' ? (
              <TriangleAlert className="mt-0.5 size-4 shrink-0 text-warning" strokeWidth={2} />
            ) : (
              <Info className="mt-0.5 size-4 shrink-0 text-info" strokeWidth={2} />
            )}
            {note.text}
          </p>
        ))}
        {conflict && !stale ? (
          <p
            role="alert"
            className="rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5 text-[12.5px] text-warning"
          >
            {t('hostsFile.reviewConflict')}
          </p>
        ) : null}
        {preview.isPending ? (
          <div className="grid h-32 place-items-center text-subtle">
            <Spinner className="size-5" />
          </div>
        ) : stale ? (
          <p
            role="alert"
            className="rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5 text-[12.5px] text-warning"
          >
            {t('hostsFile.previewStale')}
          </p>
        ) : preview.isError ? (
          <p
            role="alert"
            className="rounded-xl border border-critical-solid/30 bg-critical-solid/10 px-3 py-2.5 text-[12.5px] text-critical"
          >
            {t('hostsFile.previewFailed', { error: errorMessage(t, preview.error) })}
            {/* The core's own words, as error toasts give them. */}
            {AppError.from(preview.error).message ? (
              <span className="mt-0.5 block font-mono text-[11.5px] text-subtle">
                {AppError.from(preview.error).message}
              </span>
            ) : null}
          </p>
        ) : preview.data && !changing ? (
          <p
            role="status"
            className="rounded-xl border border-info-solid/30 bg-info-solid/[0.09] px-3 py-2.5 text-[12.5px] text-fg-2"
          >
            {t('hostsFile.nothingToChange')}
          </p>
        ) : preview.data ? (
          <section
            aria-label={t('hostsFile.reviewTitle')}
            className="selectable max-h-[46vh] overflow-auto rounded-xl border border-line bg-shade/25 py-1.5 font-mono text-[12px] leading-[19px]"
          >
            {preview.data.diff.map((line, index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: the diff is static
              <DiffRow key={index} line={line} />
            ))}
          </section>
        ) : null}
        <SwitchRow
          label={t('hostsFile.flushDns')}
          hint={t('hostsFile.flushDnsHint')}
          checked={flushDns}
          onCheckedChange={setFlushDns}
        />
      </DialogBody>
      <DialogFooter>
        <Button size="lg" onClick={onDone}>
          {t('common.cancel')}
        </Button>
        <Button
          variant="primary"
          size="lg"
          icon={<Lock className="size-4" strokeWidth={2} />}
          loading={apply.isPending}
          disabled={!preview.data || stale || !changing}
          onClick={submit}
        >
          {t('hostsFile.apply')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

function DiffRow({ line }: { line: HostsDiffLine }) {
  const { t } = useTranslation();
  const style = ROW_STYLE[line.kind];
  const number = line.kind === 'removed' ? line.oldLine : line.newLine;
  return (
    <div className={cn('flex min-w-max gap-3 px-3', style.className)}>
      <span aria-hidden="true" className="w-9 shrink-0 text-right text-subtle tabular-nums">
        {number ?? ''}
      </span>
      <span aria-hidden="true" className="w-3 shrink-0">
        {style.sign}
      </span>
      <span className="whitespace-pre">
        {line.kind === 'skipped' ? (
          `⋯ ${t('hostsFile.skippedLines', { count: line.count })}`
        ) : (
          <>
            <span className="sr-only">
              {line.kind === 'added'
                ? `${t('hostsFile.diffAdded')}: `
                : line.kind === 'removed'
                  ? `${t('hostsFile.diffRemoved')}: `
                  : ''}
            </span>
            {line.text || ' '}
          </>
        )}
      </span>
    </div>
  );
}
