import { useMutation, useQuery } from '@tanstack/react-query';
import {
  ArrowLeft,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Eye,
  EyeOff,
  FileSpreadsheet,
  FileUp,
  Globe,
  Info,
  Lightbulb,
  Lock,
  ShieldAlert,
  Trash2,
  TriangleAlert,
} from 'lucide-react';
import { Fragment, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { BrowserProfile } from '@/bindings/BrowserProfile';
import type { ImportOutcome } from '@/bindings/ImportOutcome';
import type { ImportPasswords } from '@/bindings/ImportPasswords';
import type { ImportPreview } from '@/bindings/ImportPreview';
import type { ImportRow } from '@/bindings/ImportRow';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { CheckboxControl } from '@/components/ui/Checkbox';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { useBrowserStatus } from '@/features/browser/queries';
import { copyText } from '@/lib/clipboard';
import { cn } from '@/lib/cn';
import { formatDate } from '@/lib/format';
import { AppError } from '@/lib/ipc';
import { platform } from '@/lib/platform';
import { MASK, REVEAL_MS } from '../SavedSecret';
import { type BrowserFallback, BrowserImportStep, type BrowserRead } from './BrowserImportStep';
import { Callout } from './Callout';
import { showFileError } from './errors';
import { type ImportSource, sourcesFor } from './importSources';
import { baseName } from './pickers';

export interface ImportDialogProps {
  /** Closes the dialog. Render it inside `<Dialog>`, like the app's other dialogs. */
  onDone: () => void;
}

type Step =
  | { kind: 'source' }
  | { kind: 'choose'; source: ImportSource; fallback?: BrowserFallback }
  | { kind: 'browser'; source: ImportSource; profiles: BrowserProfile[] }
  | {
      kind: 'preview';
      source: ImportSource;
      path: string;
      preview: ImportPreview;
      selected: ReadonlySet<number>;
      /** Read from a browser profile, not from a file (`path` is empty then). */
      browser?: BrowserRead;
    }
  | {
      kind: 'done';
      source: ImportSource;
      path: string;
      outcome: ImportOutcome;
      browser?: BrowserRead;
    };

/**
 * Imports logins from a browser or another password manager: say where they
 * are now (the browsers on this computer first, any CSV file last), export
 * them there as the guide says, choose the file (in a system dialog the
 * backend opens, so the page never names a file to read), check the rows
 * (new ones first; entries whose password differs from the vault's next, to
 * update them; entries already in the vault as they are last, unchecked),
 * import, then move the
 * plain-text file to the Trash. After a browser, it says how to stop the
 * browser offering the same logins.
 */
export function ImportDialog({ onDone }: ImportDialogProps) {
  const { t } = useTranslation();
  const doneId = useId();
  const status = useVaultStatus();
  const locked = status.data !== undefined && status.data.state !== 'unlocked';
  const [step, setStep] = useState<Step>({ kind: 'source' });
  const [error, setError] = useState<string | null>(null);
  const installed = new Set(
    (useBrowserStatus().data?.browsers ?? []).map((browser) => browser.name),
  );
  const browserProfiles = useQuery({
    queryKey: ['vault', 'browserProfiles'],
    queryFn: api.vaultBrowserProfiles,
    staleTime: 0,
  });
  const profilesOf = (source: ImportSource, listed = browserProfiles.data) =>
    source.direct ? (listed ?? []).filter((profile) => profile.browser === source.installName) : [];
  // Logins read from a browser stay on the other side until they are imported; drop them
  // when the dialog closes.
  useEffect(
    () => () => {
      void api.vaultBrowserImportForget().catch(() => {});
    },
    [],
  );

  const preview = useMutation({
    mutationFn: (_source: ImportSource) => api.vaultImportPreview(),
    onSuccess: (picked, source) => {
      if (!picked) return;
      const { path } = picked;
      // Ordered once here, so rows don't move while they are ticked.
      const preview = { ...picked.preview, rows: byStatus(picked.preview.rows) };
      setStep({
        kind: 'preview',
        source,
        path,
        preview,
        selected: new Set(preview.rows.filter((r) => rowStatus(r) !== 'same').map((r) => r.index)),
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
    (vars: { source: ImportSource; path: string; indices: number[]; browser?: BrowserRead }) =>
      vars.browser ? api.vaultBrowserImport(vars.indices) : api.vaultImport(vars.indices),
    {
      onSuccess: (outcome, vars) =>
        setStep({
          kind: 'done',
          source: vars.source,
          path: vars.path,
          outcome,
          browser: vars.browser,
        }),
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

  const choose = (source: ImportSource) => {
    setError(null);
    preview.mutate(source);
  };
  const lockedNote = locked ? (
    <Callout tone="info" icon={Lock}>
      {t('vaultFiles.import.unlockFirst')}
    </Callout>
  ) : null;

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

      {step.kind === 'source' ? (
        <>
          <DialogBody>
            <SourceStep
              sources={sourcesFor(platform, installed)}
              installed={installed}
              onPick={async (source) => {
                setError(null);
                // The first pick may come before the profiles are listed.
                const listed =
                  source.direct && !browserProfiles.isSuccess
                    ? (await browserProfiles.refetch()).data
                    : browserProfiles.data;
                const profiles = profilesOf(source, listed);
                setStep(
                  profiles.length > 0
                    ? { kind: 'browser', source, profiles }
                    : { kind: 'choose', source },
                );
              }}
            />
            {lockedNote}
          </DialogBody>
          <DialogFooter>
            <Button size="lg" onClick={onDone}>
              {t('common.cancel')}
            </Button>
          </DialogFooter>
        </>
      ) : null}

      {step.kind === 'browser' ? (
        <BrowserImportStep
          source={step.source}
          profiles={step.profiles}
          locked={locked}
          onRead={(read) => {
            // Ordered and ticked as a file's rows are.
            const preview = { ...read.preview, rows: byStatus(read.preview.rows) };
            setStep({
              kind: 'preview',
              source: step.source,
              path: '',
              preview,
              selected: new Set(
                preview.rows.filter((r) => rowStatus(r) !== 'same').map((r) => r.index),
              ),
              browser: { ...read, preview },
            });
          }}
          onCsv={(fallback) => setStep({ kind: 'choose', source: step.source, fallback })}
          onBack={() => setStep({ kind: 'source' })}
        />
      ) : null}

      {step.kind === 'choose' ? (
        <>
          <DialogBody>
            {step.fallback ? (
              <Callout
                id={`${doneId}-fallback`}
                tone="warning"
                icon={TriangleAlert}
                title={t(`vaultFiles.import.browser.fallbackTitle.${step.fallback}`, {
                  name: step.source.name ?? '',
                })}
              >
                {t(`vaultFiles.import.browser.fallback.${step.fallback}`, {
                  name: step.source.name ?? '',
                })}
              </Callout>
            ) : null}
            <GuideStep source={step.source} />
            <Callout
              tone="warning"
              icon={TriangleAlert}
              title={t('vaultFiles.import.plaintextTitle')}
            >
              {t('vaultFiles.import.plaintext')}
            </Callout>
            {lockedNote}
            {error ? (
              <p role="alert" className="text-[12.5px] text-critical">
                {error}
              </p>
            ) : null}
          </DialogBody>
          <DialogFooter>
            <Button
              variant="ghost"
              size="lg"
              className="mr-auto"
              icon={<ArrowLeft className="size-4" strokeWidth={2} />}
              onClick={() => {
                const profiles = profilesOf(step.source);
                setStep(
                  profiles.length > 0 && !step.fallback
                    ? { kind: 'browser', source: step.source, profiles }
                    : { kind: 'source' },
                );
              }}
            >
              {t('vaultFiles.import.back')}
            </Button>
            <Button size="lg" onClick={onDone}>
              {t('common.cancel')}
            </Button>
            <Button
              variant="primary"
              size="lg"
              icon={<FileSpreadsheet className="size-4" strokeWidth={2} />}
              autoFocus
              // The reason a browser couldn't be read directly is read with it.
              aria-describedby={step.fallback ? `${doneId}-fallback` : undefined}
              loading={preview.isPending}
              disabled={locked}
              onClick={() => choose(step.source)}
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
          browser={step.browser}
          browserName={step.source.name}
          onSelect={(selected) => setStep({ ...step, selected })}
          busy={importRows.isPending}
          onChooseOther={() => {
            const profiles = profilesOf(step.source);
            if (step.browser && profiles.length > 0) {
              void api.vaultBrowserImportForget().catch(() => {});
              setStep({ kind: 'browser', source: step.source, profiles });
            } else choose(step.source);
          }}
          onCancel={onDone}
          onImport={() =>
            importRows.mutate({
              source: step.source,
              path: step.path,
              browser: step.browser,
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
              <div id={`${doneId}-count`} className="flex flex-col gap-1">
                <p className="text-[17px] font-semibold tracking-[-0.01em]">
                  {step.outcome.added > 0 || step.outcome.updated === 0
                    ? t('vaultFiles.import.imported', { count: step.outcome.added })
                    : t('vaultFiles.import.updated', { count: step.outcome.updated })}
                </p>
                {step.outcome.added > 0 && step.outcome.updated > 0 ? (
                  <p className="text-[13px] text-muted">
                    {t('vaultFiles.import.updated', { count: step.outcome.updated })}
                  </p>
                ) : null}
              </div>
            </div>
            {step.browser ? null : (
              <Callout
                id={`${doneId}-warning`}
                tone="critical"
                icon={ShieldAlert}
                title={t('vaultFiles.import.doneTitle')}
              >
                {t('vaultFiles.import.doneText', { file: baseName(step.path) })}
              </Callout>
            )}
            {step.source.kind === 'browser' && step.source.name ? (
              <Callout
                tone="info"
                icon={Lightbulb}
                title={t('vaultFiles.import.cleanupTitle', { name: step.source.name })}
              >
                {t('vaultFiles.import.cleanupText', { name: step.source.name })}
              </Callout>
            ) : null}
          </DialogBody>
          {step.browser ? (
            <DialogFooter>
              <Button
                variant="primary"
                size="lg"
                autoFocus
                aria-describedby={`${doneId}-count`}
                onClick={onDone}
              >
                {t('vaultFiles.import.browser.done')}
              </Button>
            </DialogFooter>
          ) : (
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
          )}
        </>
      ) : null}
    </DialogContent>
  );
}

interface PreviewStepProps {
  path: string;
  preview: ImportPreview;
  /** Logins read from a browser profile instead of a file. */
  browser?: BrowserRead;
  /** The browser's name, as the import's sources give it. */
  browserName?: string;
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
  browser,
  browserName,
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
  const duplicates = rows.filter((r) => rowStatus(r) === 'same').length;
  const changed = rows.filter((r) => rowStatus(r) === 'changed').length;
  const count = selected.size;
  const updates = rows.filter((r) => selected.has(r.index) && rowStatus(r) === 'changed').length;
  const adds = count - updates;
  const submitLabel =
    updates === 0
      ? t('vaultFiles.import.submit', { count })
      : adds === 0
        ? t('vaultFiles.import.submitUpdate', { count: updates })
        : t('vaultFiles.import.submitBoth', { added: adds, updated: updates });
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
    changed > 0 ? t('vaultFiles.import.changedRows', { count: changed }) : null,
    duplicates > 0 ? t('vaultFiles.import.duplicates', { count: duplicates }) : null,
    skipped > 0 ? t('vaultFiles.import.skipped', { count: skipped }) : null,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <>
      <DialogBody>
        <div className="flex flex-col gap-1.5">
          {browser ? (
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <Globe aria-hidden="true" className="size-4 text-subtle" strokeWidth={1.75} />
              <span className="min-w-0 truncate text-[12.5px] font-medium text-fg-2">
                {t('vaultFiles.import.browser.from', {
                  name: browserName ?? browser.profile.browser,
                  profile: browser.profile.name,
                })}
              </span>
            </div>
          ) : (
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <FileSpreadsheet
                aria-hidden="true"
                className="size-4 text-subtle"
                strokeWidth={1.75}
              />
              <span className="selectable min-w-0 truncate font-mono text-[12.5px] text-fg-2">
                {baseName(path)}
              </span>
              <Badge tone="accent">
                {t('vaultFiles.import.source', { format: t(`vaultFiles.formats.${format}`) })}
              </Badge>
            </div>
          )}
          <p id={summaryId} className="text-[12.5px] text-muted">
            {summary}
          </p>
        </div>

        {browser && browser.unreadable > 0 ? (
          <Callout id={`${summaryId}-unreadable`} tone="info" icon={Info}>
            {browser.appBound > 0
              ? t('vaultFiles.import.browser.someAppBound', {
                  count: browser.unreadable,
                  name: browserName ?? browser.profile.browser,
                })
              : t('vaultFiles.import.browser.someUnreadable', { count: browser.unreadable })}
          </Callout>
        ) : null}

        {rows.length === 0 ? (
          <p className="rounded-2xl border border-dashed border-ink/[0.14] px-4 py-8 text-center text-muted">
            {browser ? t('vaultFiles.import.browser.nothing') : t('vaultFiles.import.nothing')}
          </p>
        ) : (
          <div className="glass max-h-[340px] overflow-auto rounded-2xl">
            <table
              className="w-full min-w-[600px] table-fixed border-collapse text-left"
              aria-label={
                browser
                  ? t('vaultFiles.import.browser.tableLabel', { profile: browser.profile.name })
                  : t('vaultFiles.import.tableLabel', { file: baseName(path) })
              }
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
                    browserName={browser ? (browserName ?? browser.profile.browser) : undefined}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </DialogBody>
      <DialogFooter>
        <Button variant="ghost" size="lg" className="mr-auto" onClick={onChooseOther}>
          {browser ? t('vaultFiles.import.back') : t('vaultFiles.import.chooseOther')}
        </Button>
        <Button size="lg" onClick={onCancel}>
          {t('common.cancel')}
        </Button>
        <Button
          variant="primary"
          size="lg"
          autoFocus
          aria-describedby={
            browser && browser.unreadable > 0 ? `${summaryId} ${summaryId}-unreadable` : summaryId
          }
          loading={busy}
          disabled={count === 0}
          icon={<FileUp className="size-4" strokeWidth={2} />}
          onClick={onImport}
        >
          {submitLabel}
        </Button>
      </DialogFooter>
    </>
  );
}

function PreviewRow({
  row,
  checked,
  onToggle,
  browserName,
}: {
  row: ImportRow;
  checked: boolean;
  onToggle: () => void;
  /** The browser the row was read from, when it wasn't a file. */
  browserName?: string;
}) {
  const { t } = useTranslation();
  const compareId = useId();
  const [comparing, setComparing] = useState(false);
  const panel = useRef<HTMLTableRowElement>(null);
  // The table scrolls on its own; bring the opened comparison into view.
  useEffect(() => {
    if (comparing) panel.current?.scrollIntoView?.({ block: 'nearest' });
  }, [comparing]);
  return (
    <Fragment>
      {/* The checkbox is the control; clicking anywhere on the row is a shortcut. */}
      <tr
        onClick={onToggle}
        className={cn(
          'h-[46px] border-t border-ink/[0.05] transition-colors',
          checked ? 'bg-[rgb(var(--accent-rgb)/0.07)]' : 'hover:bg-fill-subtle',
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
            {row.passwordChanged ? (
              <>
                <span title={t('vaultFiles.import.passwordDiffersHint')}>
                  <Badge tone="accent">{t('vaultFiles.import.passwordDiffers')}</Badge>
                </span>
                <button
                  type="button"
                  aria-expanded={comparing}
                  aria-controls={comparing ? compareId : undefined}
                  aria-label={t('vaultFiles.import.compareFor', { title: row.title })}
                  onClick={(event) => {
                    event.stopPropagation();
                    setComparing(!comparing);
                  }}
                  className="inline-flex items-center gap-0.5 rounded-md px-1 text-[11.5px] font-medium text-[var(--accent-text)] hover:underline"
                >
                  {comparing ? t('vaultFiles.import.compareHide') : t('vaultFiles.import.compare')}
                  <ChevronDown
                    aria-hidden="true"
                    className={cn('size-3.5 transition-transform', comparing && 'rotate-180')}
                    strokeWidth={2}
                  />
                </button>
              </>
            ) : row.duplicateOf ? (
              <Badge tone="warning">{t('vaultFiles.import.inVault')}</Badge>
            ) : null}
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
      {comparing ? (
        <tr ref={panel} id={compareId} className="border-t border-ink/[0.05] bg-ink/[0.02]">
          <td colSpan={5} className="px-3.5 py-3">
            <ComparePasswords row={row} browserName={browserName} />
          </td>
        </tr>
      ) : null}
    </Fragment>
  );
}

/**
 * The file's and the vault's password of a row side by side, with when each was last changed, so
 * the user can tell which to keep. The dates come with the preview; the passwords only on request,
 * and they hide themselves again after a while.
 */
function ComparePasswords({ row, browserName }: { row: ImportRow; browserName?: string }) {
  const { t, i18n } = useTranslation();
  const [shown, setShown] = useState<ImportPasswords | null>(null);
  const fromBrowser = browserName !== undefined;
  const reveal = useAppMutation(
    () =>
      fromBrowser ? api.vaultBrowserImportCompare(row.index) : api.vaultImportCompare(row.index),
    {
      onSuccess: setShown,
      onError: (appError) =>
        showFileError(t, appError, {
          invalid_input: t('vaultFiles.import.changed'),
          vault_locked: t('vaultFiles.import.unlockFirst'),
        }),
    },
  );
  useEffect(() => {
    if (shown === null) return;
    const timer = window.setTimeout(() => setShown(null), REVEAL_MS);
    return () => window.clearTimeout(timer);
  }, [shown]);

  const file = row.changedInFile ? new Date(row.changedInFile) : null;
  const vault = row.changedInVault ? new Date(row.changedInVault) : null;
  const newer = file && vault ? (file > vault ? 'file' : vault > file ? 'vault' : null) : null;
  const sides = [
    {
      key: 'file',
      label: fromBrowser
        ? t('vaultFiles.import.browser.inBrowser', { name: browserName })
        : t('vaultFiles.import.inFile'),
      date: row.changedInFile,
      noDate: fromBrowser
        ? t('vaultFiles.import.browser.browserNoDate', { name: browserName })
        : t('vaultFiles.import.fileNoDate'),
      password: shown?.file,
    },
    {
      key: 'vault',
      label: t('vaultFiles.import.inVaultSide'),
      date: row.changedInVault,
      noDate: t('vaultFiles.import.vaultNoDate'),
      password: shown?.vault,
    },
  ] as const;

  return (
    <div className="flex flex-col gap-2.5">
      <dl className="grid grid-cols-2 gap-2">
        {sides.map((side) => (
          <div
            key={side.key}
            className="flex min-w-0 flex-col gap-1 rounded-xl border border-line bg-fill-subtle px-3 py-2"
          >
            <dt className="flex items-center gap-1.5 text-[11.5px] font-semibold tracking-[0.02em] text-subtle">
              {side.label}
              {newer === side.key ? (
                <Badge tone="accent" pill>
                  {t('vaultFiles.import.newer')}
                </Badge>
              ) : null}
            </dt>
            <dd className="flex min-w-0 flex-col gap-0.5">
              <span className="selectable truncate font-mono text-[12.5px] text-fg">
                {side.password ?? MASK}
              </span>
              <span className="text-[11.5px] text-muted">
                {side.date
                  ? t('vaultFiles.import.changedOn', { date: formatDate(side.date, i18n.language) })
                  : side.noDate}
              </span>
            </dd>
          </div>
        ))}
      </dl>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <Button
          size="sm"
          loading={reveal.isPending}
          icon={
            shown ? (
              <EyeOff className="size-3.5" strokeWidth={2} />
            ) : (
              <Eye className="size-3.5" strokeWidth={2} />
            )
          }
          onClick={() => (shown ? setShown(null) : reveal.mutate(undefined))}
        >
          {shown ? t('vaultFiles.import.hidePasswords') : t('vaultFiles.import.showPasswords')}
        </Button>
        <p className="min-w-0 flex-1 text-[11.5px] leading-4 text-muted">
          {fromBrowser
            ? t('vaultFiles.import.browser.compareHint', { name: browserName })
            : t('vaultFiles.import.compareHint')}
        </p>
      </div>
    </div>
  );
}

type RowStatus = 'new' | 'changed' | 'same';

/** New to the vault, in it with another password, or in it as it is. */
export function rowStatus(row: ImportRow): RowStatus {
  if (!row.duplicateOf) return 'new';
  return row.passwordChanged ? 'changed' : 'same';
}

/**
 * New rows first, then rows that update an entry's password, then rows already in the vault,
 * each in the file's order: what will be imported sits at the top of a long list.
 */
export function byStatus(rows: ImportRow[]): ImportRow[] {
  const rank: Record<RowStatus, number> = { new: 0, changed: 1, same: 2 };
  return rows
    .map((row, at) => ({ row, at }))
    .sort((a, b) => rank[rowStatus(a.row)] - rank[rowStatus(b.row)] || a.at - b.at)
    .map(({ row }) => row);
}

/** `https://github.com/login/` → `github.com/login`. */
function shortUrl(url: string): string {
  return url.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').replace(/\/$/, '');
}

interface SourceStepProps {
  sources: ImportSource[];
  /** Browser names the app found on this computer. */
  installed: ReadonlySet<string>;
  onPick: (source: ImportSource) => void;
}

/** Where the passwords are now: browsers, password managers, then any CSV file. */
function SourceStep({ sources, installed, onPick }: SourceStepProps) {
  const { t } = useTranslation();
  const headingId = useId();
  const groups = [
    { kind: 'browser', label: t('vaultFiles.import.fromBrowser') },
    { kind: 'manager', label: t('vaultFiles.import.fromManager') },
    { kind: 'file', label: t('vaultFiles.import.fromFile') },
  ] as const;
  return (
    <div className="flex flex-col gap-3.5">
      <h3 id={headingId} className="text-[14px] font-semibold">
        {t('vaultFiles.import.whereFrom')}
      </h3>
      {groups.map((group) => {
        const inGroup = sources.filter((source) => source.kind === group.kind);
        if (inGroup.length === 0) return null;
        return (
          <div key={group.kind} className="flex flex-col gap-2">
            <h4 className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
              {group.label}
            </h4>
            <ul className="grid grid-cols-[repeat(auto-fill,minmax(200px,1fr))] gap-2">
              {inGroup.map((source) => {
                const Icon = source.icon;
                const here = source.installName !== undefined && installed.has(source.installName);
                const name = source.name ?? t('vaultFiles.import.otherSource');
                const hint =
                  source.kind === 'file'
                    ? t('vaultFiles.import.otherHint')
                    : here
                      ? t('vaultFiles.import.onThisComputer')
                      : undefined;
                return (
                  <li key={source.id} className={cn(source.kind === 'file' && 'col-span-full')}>
                    <button
                      type="button"
                      onClick={() => onPick(source)}
                      className="pressable-soft flex w-full min-w-0 items-center gap-2.5 rounded-[14px] border border-ink/[0.09] bg-fill-subtle p-2.5 text-left hover:bg-fill"
                    >
                      <Tile tone={source.tone} size={30}>
                        <Icon className="size-[15px]" strokeWidth={2} />
                      </Tile>
                      <span className="flex min-w-0 flex-1 flex-col">
                        <span className="truncate font-medium">{name}</span>
                        {hint ? (
                          <span
                            className={cn(
                              'flex items-center gap-1.5 text-[11.5px] leading-4',
                              here ? 'text-ok' : 'text-subtle',
                            )}
                          >
                            {here ? (
                              <span aria-hidden="true" className="size-1.5 rounded-full bg-ok" />
                            ) : null}
                            {hint}
                          </span>
                        ) : null}
                      </span>
                      <ChevronRight
                        aria-hidden="true"
                        className="size-4 shrink-0 text-subtle"
                        strokeWidth={2}
                      />
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
    </div>
  );
}

/** How to get the passwords out of `source`, step by step. */
function GuideStep({ source }: { source: ImportSource }) {
  const { t } = useTranslation();
  const Icon = source.icon;
  const name = source.name ?? '';
  const copy = async (address: string) => {
    try {
      await copyText(address);
      toast.success(t('vaultFiles.import.addressCopied'));
    } catch (cause) {
      toastError(t, cause);
    }
  };
  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-3">
        <Tile tone={source.tone} size={36}>
          <Icon className="size-[18px]" strokeWidth={2} />
        </Tile>
        <div className="flex min-w-0 flex-col">
          <h3 className="text-[14px] font-semibold">
            {source.name
              ? t('vaultFiles.import.guideTitle', { name })
              : t('vaultFiles.import.guideTitleOther')}
          </h3>
          <p className="text-[12.5px] text-muted">{t('vaultFiles.import.guideLead')}</p>
        </div>
      </div>
      <ol className="flex flex-col gap-2.5">
        {[...source.steps, 'chooseFile' as const].map((step, index) => (
          <li key={step} className="flex gap-3">
            <span
              aria-hidden="true"
              className="grid size-6 shrink-0 place-items-center rounded-full border border-ink/[0.12] bg-ink/[0.05] text-[12px] font-semibold text-fg-2 tabular-nums"
            >
              {index + 1}
            </span>
            <div className="flex min-w-0 flex-1 flex-col gap-2 pt-0.5 text-[13px] leading-5 text-fg-2">
              <p>{t(`vaultFiles.import.guide.${step}`, { name })}</p>
              {step === 'open' && source.address ? (
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <code className="selectable field min-w-0 truncate rounded-lg px-2.5 py-1.5 font-mono text-[12.5px] text-fg">
                    {source.address}
                  </code>
                  <Button
                    size="sm"
                    icon={<Copy className="size-3.5" strokeWidth={2} />}
                    onClick={() => void copy(source.address ?? '')}
                  >
                    {t('vaultFiles.import.copyAddress')}
                  </Button>
                </div>
              ) : null}
            </div>
          </li>
        ))}
      </ol>
    </div>
  );
}
