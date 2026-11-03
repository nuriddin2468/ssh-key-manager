import { useMutation } from '@tanstack/react-query';
import {
  Check,
  FileSpreadsheet,
  FileUp,
  Lock,
  ShieldAlert,
  Trash2,
  TriangleAlert,
} from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { ImportPreview } from '@/bindings/ImportPreview';
import type { ImportRow } from '@/bindings/ImportRow';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { CheckboxControl } from '@/components/ui/Checkbox';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { AppError } from '@/lib/ipc';
import { Callout } from './Callout';
import { showFileError } from './errors';
import { baseName } from './pickers';

export interface ImportDialogProps {
  /** Closes the dialog. Render it inside `<Dialog>`, like the app's other dialogs. */
  onDone: () => void;
}

type Step =
  | { kind: 'choose' }
  | { kind: 'preview'; path: string; preview: ImportPreview; selected: ReadonlySet<number> }
  | { kind: 'done'; path: string; count: number };

/**
 * Imports a CSV export of another password manager: choose the file (in a
 * system dialog the backend opens, so the page never names a file to read),
 * check the rows (entries already in the vault start unchecked), import, then
 * move the plain-text file to the Trash.
 */
export function ImportDialog({ onDone }: ImportDialogProps) {
  const { t } = useTranslation();
  const doneId = useId();
  const status = useVaultStatus();
  const locked = status.data !== undefined && status.data.state !== 'unlocked';
  const [step, setStep] = useState<Step>({ kind: 'choose' });
  const [error, setError] = useState<string | null>(null);

  const preview = useMutation({
    mutationFn: () => api.vaultImportPreview(),
    onSuccess: (picked) => {
      if (!picked) return;
      const { path, preview } = picked;
      setStep({
        kind: 'preview',
        path,
        preview,
        selected: new Set(preview.rows.filter((r) => !r.duplicateOf).map((r) => r.index)),
      });
    },
    onError: (cause) => {
      const appError = AppError.from(cause);
      const messages: Partial<Record<string, string>> = {
        unsupported: t('vaultFiles.import.notExport'),
        parse: t('vaultFiles.import.notText'),
        invalid_input: t('vaultFiles.import.tooLarge'),
        vault_locked: t('vaultFiles.import.unlockFirst'),
      };
      const message = messages[appError.code];
      if (message) setError(message);
      else if (appError.code !== 'cancelled') toastError(t, appError);
    },
  });

  const importRows = useAppMutation(
    (vars: { path: string; indices: number[] }) => api.vaultImport(vars.indices),
    {
      onSuccess: (count, vars) => setStep({ kind: 'done', path: vars.path, count }),
      onError: (appError) =>
        showFileError(t, appError, {
          invalid_input: t('vaultFiles.import.changed'),
          vault_locked: t('vaultFiles.import.unlockFirst'),
        }),
    },
  );

  const trash = useAppMutation((_path: string) => api.vaultTrashImportFile(), {
    success: (_, path) => t('vaultFiles.import.trashed', { file: baseName(path) }),
    onSuccess: onDone,
  });

  const choose = () => {
    setError(null);
    preview.mutate();
  };

  return (
    <DialogContent section="passwords" className="max-w-[760px]">
      <DialogHeader
        icon={
          <Tile tone="pink" size={44} glow>
            <FileUp className="size-[22px]" strokeWidth={2} />
          </Tile>
        }
        title={t('vaultFiles.import.title')}
        description={t('vaultFiles.import.description')}
      />

      {step.kind === 'choose' ? (
        <>
          <DialogBody>
            <p className="text-[13px] leading-5 text-fg-2">{t('vaultFiles.import.sources')}</p>
            <Callout
              tone="warning"
              icon={TriangleAlert}
              title={t('vaultFiles.import.plaintextTitle')}
            >
              {t('vaultFiles.import.plaintext')}
            </Callout>
            {locked ? (
              <Callout tone="info" icon={Lock}>
                {t('vaultFiles.import.unlockFirst')}
              </Callout>
            ) : null}
            {error ? (
              <p role="alert" className="text-[12.5px] text-critical">
                {error}
              </p>
            ) : null}
          </DialogBody>
          <DialogFooter>
            <Button size="lg" onClick={onDone}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              size="lg"
              icon={<FileSpreadsheet className="size-4" strokeWidth={2} />}
              autoFocus
              loading={preview.isPending}
              disabled={locked}
              onClick={choose}
            >
              {preview.isPending ? t('vaultFiles.import.reading') : t('vaultFiles.import.choose')}
            </Button>
          </DialogFooter>
        </>
      ) : null}

      {step.kind === 'preview' ? (
        <PreviewStep
          path={step.path}
          preview={step.preview}
          selected={step.selected}
          onSelect={(selected) => setStep({ ...step, selected })}
          busy={importRows.isPending}
          onChooseOther={choose}
          onCancel={onDone}
          onImport={() =>
            importRows.mutate({
              path: step.path,
              indices: step.preview.rows
                .map((r) => r.index)
                .filter((index) => step.selected.has(index)),
            })
          }
        />
      ) : null}

      {step.kind === 'done' ? (
        <>
          <DialogBody>
            <div className="flex flex-col items-center gap-3 pt-2 text-center">
              <Tile tone="teal" size={52} glow>
                <Check className="size-6" strokeWidth={2.25} />
              </Tile>
              <p id={`${doneId}-count`} className="text-[17px] font-semibold tracking-[-0.01em]">
                {t('vaultFiles.import.imported', { count: step.count })}
              </p>
            </div>
            <Callout
              id={`${doneId}-warning`}
              tone="critical"
              icon={ShieldAlert}
              title={t('vaultFiles.import.doneTitle')}
            >
              {t('vaultFiles.import.doneText', { file: baseName(step.path) })}
            </Callout>
          </DialogBody>
          <DialogFooter>
            <Button size="lg" onClick={onDone}>
              {t('vaultFiles.import.keep')}
            </Button>
            <Button
              variant="primary"
              size="lg"
              autoFocus
              // Focus lands here, so the result and the warning are read with it.
              aria-describedby={`${doneId}-count ${doneId}-warning`}
              icon={<Trash2 className="size-4" strokeWidth={2} />}
              loading={trash.isPending}
              onClick={() => trash.mutate(step.path)}
            >
              {t('vaultFiles.import.trash')}
            </Button>
          </DialogFooter>
        </>
      ) : null}
    </DialogContent>
  );
}

interface PreviewStepProps {
  path: string;
  preview: ImportPreview;
  selected: ReadonlySet<number>;
  onSelect: (selected: ReadonlySet<number>) => void;
  busy: boolean;
  onChooseOther: () => void;
  onCancel: () => void;
  onImport: () => void;
}

function PreviewStep({
  path,
  preview,
  selected,
  onSelect,
  busy,
  onChooseOther,
  onCancel,
  onImport,
}: PreviewStepProps) {
  const { t } = useTranslation();
  const summaryId = useId();
  const { rows, skipped, format } = preview;
  const duplicates = rows.filter((r) => r.duplicateOf).length;
  const count = selected.size;
  const all = rows.length > 0 && count === rows.length;

  const toggle = (index: number) => {
    const next = new Set(selected);
    if (next.has(index)) next.delete(index);
    else next.add(index);
    onSelect(next);
  };
  const toggleAll = () => onSelect(all ? new Set() : new Set(rows.map((r) => r.index)));

  const summary = [
    t('vaultFiles.import.found', { count: rows.length }),
    duplicates > 0 ? t('vaultFiles.import.duplicates', { count: duplicates }) : null,
    skipped > 0 ? t('vaultFiles.import.skipped', { count: skipped }) : null,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <>
      <DialogBody>
        <div className="flex flex-col gap-1.5">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <FileSpreadsheet aria-hidden="true" className="size-4 text-subtle" strokeWidth={1.75} />
            <span className="selectable min-w-0 truncate font-mono text-[12.5px] text-fg-2">
              {baseName(path)}
            </span>
            <Badge tone="accent">
              {t('vaultFiles.import.source', { format: t(`vaultFiles.formats.${format}`) })}
            </Badge>
          </div>
          <p id={summaryId} className="text-[12.5px] text-muted">
            {summary}
          </p>
        </div>

        {rows.length === 0 ? (
          <p className="rounded-2xl border border-dashed border-white/[0.14] px-4 py-8 text-center text-muted">
            {t('vaultFiles.import.nothing')}
          </p>
        ) : (
          <div className="glass max-h-[340px] overflow-auto rounded-2xl">
            <table
              className="w-full min-w-[600px] table-fixed border-collapse text-left"
              aria-label={t('vaultFiles.import.tableLabel', { file: baseName(path) })}
            >
              <colgroup>
                <col className="w-11" />
                <col />
                <col className="w-[24%]" />
                <col className="w-[24%]" />
                <col className="w-[132px]" />
              </colgroup>
              <thead className="sticky top-0 z-10 bg-popover">
                <tr className="h-[36px] text-[11.5px] tracking-[0.02em] text-subtle">
                  <th scope="col" className="pl-3.5 font-medium">
                    <CheckboxControl
                      aria-label={t('vaultFiles.import.selectAll')}
                      checked={all ? true : count > 0 ? 'indeterminate' : false}
                      onCheckedChange={toggleAll}
                    />
                  </th>
                  <th scope="col" className="pr-3 font-medium">
                    {t('vaultFiles.import.colName')}
                  </th>
                  <th scope="col" className="pr-3 font-medium">
                    {t('vaultFiles.import.colUsername')}
                  </th>
                  <th scope="col" className="pr-3 font-medium">
                    {t('vaultFiles.import.colWebsite')}
                  </th>
                  <th scope="col" className="pr-3.5 font-medium">
                    <span className="sr-only">{t('vaultFiles.import.colStatus')}</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <PreviewRow
                    key={row.index}
                    row={row}
                    checked={selected.has(row.index)}
                    onToggle={() => toggle(row.index)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" size="lg" className="mr-auto" onClick={onChooseOther}>
          {t('vaultFiles.import.chooseOther')}
        </Button>
        <Button size="lg" onClick={onCancel}>
          {t('common.cancel')}
        </Button>
        <Button
          variant="primary"
          size="lg"
          autoFocus
          aria-describedby={summaryId}
          loading={busy}
          disabled={count === 0}
          icon={<FileUp className="size-4" strokeWidth={2} />}
          onClick={onImport}
        >
          {t('vaultFiles.import.submit', { count })}
        </Button>
      </DialogFooter>
    </>
  );
}

function PreviewRow({
  row,
  checked,
  onToggle,
}: {
  row: ImportRow;
  checked: boolean;
  onToggle: () => void;
}) {
  const { t } = useTranslation();
  return (
    // The checkbox is the control; clicking anywhere on the row is a shortcut.
    <tr
      onClick={onToggle}
      className={cn(
        'h-[46px] border-t border-white/[0.05] transition-colors',
        checked ? 'bg-[rgb(var(--accent-rgb)/0.07)]' : 'hover:bg-white/[0.03]',
      )}
    >
      <td className="pl-3.5">
        <CheckboxControl
          aria-label={t('vaultFiles.import.select', { title: row.title })}
          checked={checked}
          onCheckedChange={onToggle}
          onClick={(event) => event.stopPropagation()}
        />
      </td>
      <td className="pr-3">
        <span className="block truncate font-medium" title={row.title}>
          {row.title}
        </span>
        {row.group ? (
          <span className="block truncate text-[11.5px] text-subtle">
            {t('vaultFiles.import.folder', { folder: row.group })}
          </span>
        ) : null}
      </td>
      <td className="truncate pr-3 text-fg-2" title={row.username || undefined}>
        {row.username || t('common.dash')}
      </td>
      <td className="truncate pr-3 font-mono text-[12px] text-muted" title={row.url || undefined}>
        {shortUrl(row.url) || t('common.dash')}
      </td>
      <td className="pr-3.5">
        <span className="flex flex-wrap justify-end gap-1">
          {row.duplicateOf ? <Badge tone="warning">{t('vaultFiles.import.inVault')}</Badge> : null}
          {row.hasOtp ? <Badge tone="info">{t('vaultFiles.import.otp')}</Badge> : null}
          {row.hasUnreadableOtp ? (
            <span title={t('vaultFiles.import.otpUnreadableHint')}>
              <Badge>{t('vaultFiles.import.otpUnreadable')}</Badge>
            </span>
          ) : null}
          {row.hasPassword ? null : <Badge>{t('vaultFiles.import.noPassword')}</Badge>}
        </span>
      </td>
    </tr>
  );
}

/** `https://github.com/login/` → `github.com/login`. */
function shortUrl(url: string): string {
  return url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/$/, '');
}
