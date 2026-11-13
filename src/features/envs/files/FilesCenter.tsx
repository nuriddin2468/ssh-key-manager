import { AlertTriangle, FileSearch, GitBranch, RefreshCw, Variable } from 'lucide-react';
import { type ReactNode, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { errorMessage } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { EnvFile } from '@/bindings/EnvFile';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { UnmanagedEnvFile } from '@/bindings/UnmanagedEnvFile';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { Select } from '@/components/ui/Select';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { useProjects } from '@/features/projects/queries';
import { cn } from '@/lib/cn';
import { whereLabel } from '../model';
import { AdoptFileDialog } from './AdoptFileDialog';
import { announceSynced } from './announce';
import { ignoreFailed, isFileConflict } from './errors';
import { FileCompareDialog } from './FileCompareDialog';
import {
  bindingPath,
  type CenterFilter,
  cloudBadge,
  cloudText,
  fileName,
  matchesFilter,
  missingNames,
  needsAttention,
  sameFile,
  stateDetail,
  stateLabel,
  stateLook,
  stateText,
  TONE_CLASSES,
} from './model';
import { refreshFileReports, useFileStatuses, useFilesOverview } from './queries';

const ALL = '__all__';
const FILTERS: CenterFilter[] = ['all', 'attention', 'git', 'cloud', 'example'];

type Open =
  | { kind: 'compare'; envId: string; file: EnvFile }
  | { kind: 'adopt'; found: UnmanagedEnvFile };

interface FilesCenterProps {
  /** The project shown, or every one. */
  project?: string;
  onProject: (project?: string) => void;
}

/**
 * The management center: every file environments are written to, of every
 * project or one, with what needs the user — a conflict, a deleted file,
 * Git that would commit it, a cloud folder that copies it, names its
 * `.env.example` has and the environment lacks — and the `.env` files in
 * the projects' folders that no environment writes, to take under
 * management.
 */
export function FilesCenter({ project, onProject }: FilesCenterProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const projects = useProjects();
  const overview = useFilesOverview(project ?? null);
  const [filter, setFilter] = useState<CenterFilter>('all');
  const [open, setOpen] = useState<Open | null>(null);
  const [ignoring, setIgnoring] = useState<EnvFileReport | null>(null);
  const filesHeading = useId();
  const unmanagedHeading = useId();

  const statuses = useFileStatuses();
  // The overview is fetched when asked; states follow every round.
  const files = useMemo(
    () =>
      (overview.data?.files ?? []).map((report) => {
        const live = statuses.data?.find(
          (status) => status.envId === report.envId && sameFile(status.file, report.file),
        );
        return live ? { ...report, state: live.state, location: live.location } : report;
      }),
    [overview.data, statuses.data],
  );
  const unmanaged = overview.data?.unmanaged ?? [];
  // What needs the user first; the rest keeps the backend's order.
  const shown = useMemo(
    () =>
      files
        .filter((file) => matchesFilter(file, filter))
        .sort((a, b) => Number(needsAttention(b)) - Number(needsAttention(a))),
    [files, filter],
  );
  const projectName = (id: string) =>
    projects.data?.find((item) => item.id === id)?.name ?? t('common.dash');

  const sync = useVaultMutation(() => api.envsFilesSync(), {
    onSuccess: (synced) => {
      void refreshFileReports();
      announceSynced(t, synced, navigate);
      if (synced.written.length > 0) {
        toast.success(t('envs.files.written', { count: synced.written.length }));
      } else if (
        synced.changes.length === 0 &&
        synced.files.every((f) => f.state.type === 'inSync')
      ) {
        toast.success(t('envs.center.inSync'));
      }
    },
  });
  const ignore = useVaultMutation(
    (report: EnvFileReport) => api.envsFilesIgnore(report.envId, report.file),
    {
      success: (_, report) => t('envs.center.ignored', { file: fileName(report.file) }),
      onSuccess: () => {
        setIgnoring(null);
        void refreshFileReports();
      },
      onError: (error, report) => ignoreFailed(t, error, report.file),
    },
  );

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <Select
          size="sm"
          aria-label={t('envs.center.project')}
          value={project ?? ALL}
          onValueChange={(value) => onProject(value === ALL ? undefined : value)}
          className="w-[200px]"
          options={[
            { value: ALL, label: t('envs.center.allProjects') },
            ...(projects.data ?? []).map((item) => ({ value: item.id, label: item.name })),
          ]}
        />
        <fieldset className="flex flex-wrap gap-1.5">
          <legend className="sr-only">{t('envs.center.filters')}</legend>
          {FILTERS.map((item) => (
            <Chip
              key={item}
              label={t(`envs.center.${item}`)}
              count={files.filter((file) => matchesFilter(file, item)).length}
              pressed={filter === item}
              onClick={() => setFilter(item)}
            />
          ))}
        </fieldset>
        <Button
          size="sm"
          className="ml-auto"
          icon={<RefreshCw className="size-3.5" strokeWidth={2} />}
          loading={sync.isPending}
          onClick={() => sync.mutate(undefined)}
        >
          {t('envs.center.sync')}
        </Button>
      </div>

      {overview.isPending ? (
        <div className="grid place-items-center py-16 text-subtle">
          <Spinner className="size-6" />
        </div>
      ) : overview.isError ? (
        <p role="alert" className="text-[12.5px] text-critical">
          {errorMessage(t, overview.error)}
        </p>
      ) : files.length === 0 && unmanaged.length === 0 ? (
        <EmptyState
          className="my-10"
          icon={
            <Tile tone="lime" size={52} glow>
              <Variable className="size-6" strokeWidth={2} />
            </Tile>
          }
          title={t('envs.center.emptyTitle')}
          description={t('envs.center.emptyText')}
          action={
            <Button onClick={() => navigate({ page: 'envs' })}>{t('envs.center.openEnvs')}</Button>
          }
        />
      ) : (
        <>
          <section aria-labelledby={filesHeading} className="flex flex-col gap-2.5">
            <h2 id={filesHeading} className="text-[14px] font-semibold">
              {t('envs.center.filesTitle')}
              <span className="ml-1.5 font-normal text-subtle tabular-nums">{shown.length}</span>
            </h2>
            {shown.length === 0 ? (
              <p className="rounded-xl border border-dashed border-ink/[0.14] px-3 py-3 text-[12.5px] text-muted">
                {files.length === 0 ? t('envs.center.emptyText') : t('envs.center.nothing')}
              </p>
            ) : (
              <ul className="flex flex-col gap-2">
                {shown.map((report) => (
                  <FileReportRow
                    key={`${report.envId}\n${report.file.folder}\n${report.file.path}`}
                    report={report}
                    onCompare={() =>
                      setOpen({ kind: 'compare', envId: report.envId, file: report.file })
                    }
                    onIgnore={() => setIgnoring(report)}
                  />
                ))}
              </ul>
            )}
          </section>

          <section aria-labelledby={unmanagedHeading} className="flex flex-col gap-2.5">
            <div className="flex flex-col gap-0.5">
              <h2 id={unmanagedHeading} className="text-[14px] font-semibold">
                {t('envs.center.unmanagedTitle')}
                <span className="ml-1.5 font-normal text-subtle tabular-nums">
                  {unmanaged.length}
                </span>
              </h2>
              <p className="text-[12.5px] text-muted">{t('envs.center.unmanagedText')}</p>
            </div>
            {unmanaged.length === 0 ? (
              <p className="text-[12.5px] text-subtle">{t('envs.center.noUnmanaged')}</p>
            ) : (
              <ul className="flex flex-col gap-1.5">
                {unmanaged.map((found) => (
                  <UnmanagedRow
                    key={`${found.project}\n${found.location}`}
                    found={found}
                    projectName={projectName(found.project)}
                    onAdopt={() => setOpen({ kind: 'adopt', found })}
                  />
                ))}
              </ul>
            )}
            {overview.data?.truncated ? (
              <p className="flex items-center gap-1.5 text-[12px] text-warning">
                <AlertTriangle aria-hidden="true" className="size-3.5" strokeWidth={2} />
                {t('envs.center.truncated')}
              </p>
            ) : null}
          </section>
        </>
      )}

      <Dialog open={open !== null} onOpenChange={(next) => (next ? undefined : setOpen(null))}>
        {open?.kind === 'compare' ? (
          <FileCompareDialog envId={open.envId} file={open.file} onDone={() => setOpen(null)} />
        ) : null}
        {open?.kind === 'adopt' ? (
          <AdoptFileDialog found={open.found} onDone={() => setOpen(null)} />
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={ignoring !== null}
        onOpenChange={(next) => (next ? undefined : setIgnoring(null))}
        title={t('envs.center.ignoreTitle', { file: ignoring ? fileName(ignoring.file) : '' })}
        description={t('envs.center.ignoreText', {
          repository: ignoring?.git?.repository ?? '',
        })}
        confirmLabel={t('envs.center.ignoreConfirm')}
        busy={ignore.isPending}
        onConfirm={() => ignoring && ignore.mutate(ignoring)}
      />
    </div>
  );
}

interface FileReportRowProps {
  report: EnvFileReport;
  onCompare: () => void;
  onIgnore: () => void;
}

/** A file and everything about it that needs the user. */
function FileReportRow({ report, onCompare, onIgnore }: FileReportRowProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const look = stateLook(report.state);
  const tone = TONE_CLASSES[look.tone];
  const name = bindingPath(report.file);
  const missing = missingNames(report);
  const writeAgain = useVaultMutation(
    () => api.envsFilesResolve(report.envId, report.file, 'vault', null),
    {
      onSuccess: (synced) => announceSynced(t, synced, navigate),
      onError: (error) => {
        if (!isFileConflict(error)) return false;
        toast.warning(t('envs.files.errors.fileBack', { file: fileName(report.file) }));
        return true;
      },
    },
  );
  return (
    <li
      className={cn(
        'glass flex flex-wrap items-start gap-x-3.5 gap-y-3 rounded-2xl px-4 py-[13px]',
        !needsAttention(report) && 'opacity-90',
      )}
    >
      <span
        aria-hidden="true"
        className={cn('grid size-9 shrink-0 place-items-center rounded-[11px] border', tone.tile)}
      >
        <look.icon className="size-[17px]" strokeWidth={2} />
      </span>
      <div className="flex min-w-[260px] flex-1 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-mono text-[13px] font-semibold">{report.file.path}</span>
          <span className="inline-flex h-5 items-center rounded-md border border-line-strong bg-fill px-[7px] text-[11.5px] text-fg-2">
            {whereLabel(report.label || null, report.envName)}
          </span>
          <span className={cn('text-[11.5px] font-semibold', tone.text)}>
            {stateLabel(t, report.state)}
          </span>
        </div>
        {report.state.type === 'inSync' ? null : (
          <p className="text-[12.5px] text-muted" title={stateDetail(report.state)}>
            {stateText(t, report.state)}
          </p>
        )}
        <p
          className="selectable truncate font-mono text-[11.5px] text-subtle"
          title={report.location ?? bindingPath(report.file)}
        >
          {report.location ?? bindingPath(report.file)}
        </p>
        {report.git?.state === 'untracked' ||
        report.git?.state === 'tracked' ||
        report.cloud ||
        missing.length > 0 ? (
          <ul className="mt-1 flex flex-col gap-2">
            {report.git?.state === 'untracked' ? (
              <Flag
                badge={<Badge tone="warning">{t('envs.center.gitUntracked')}</Badge>}
                text={t('envs.center.gitUntrackedText')}
                action={
                  <Button
                    size="sm"
                    aria-label={t('envs.center.ignoreLabel', { file: name })}
                    icon={<GitBranch className="size-3.5" strokeWidth={2} />}
                    onClick={onIgnore}
                  >
                    {t('envs.center.ignore')}
                  </Button>
                }
              />
            ) : null}
            {report.git?.state === 'tracked' ? (
              <Flag
                badge={<Badge tone="critical">{t('envs.center.gitTracked')}</Badge>}
                text={t('envs.center.gitTrackedText')}
              />
            ) : null}
            {report.cloud ? (
              <Flag
                badge={<Badge tone="warning">{cloudBadge(t, report.cloud)}</Badge>}
                text={cloudText(t, report.cloud)}
              />
            ) : null}
            {missing.length > 0 && report.example ? (
              <Flag
                badge={
                  <Badge tone="info">
                    {t('envs.center.exampleBadge', { count: missing.length })}
                  </Badge>
                }
                text={t('envs.center.exampleText', { file: report.example.file })}
              >
                <ul className="flex flex-wrap gap-1.5">
                  {missing.map((variable) => (
                    <li
                      key={variable}
                      className="selectable rounded-md border border-line-strong bg-ink/[0.04] px-2 py-0.5 font-mono text-[11.5px] text-fg-2"
                    >
                      {variable}
                    </li>
                  ))}
                </ul>
              </Flag>
            ) : null}
          </ul>
        ) : null}
      </div>
      <div className="flex shrink-0 flex-wrap gap-1.5">
        <Button
          variant="ghost"
          size="sm"
          aria-label={t('envs.files.openEnvLabel', {
            env: whereLabel(report.label || null, report.envName),
          })}
          onClick={() => navigate({ page: 'envs', envId: report.envId })}
        >
          {t('envs.files.openEnv')}
        </Button>
        {report.state.type === 'conflict' ? (
          <Button
            size="sm"
            aria-label={t('envs.files.compareLabel', { file: name })}
            onClick={onCompare}
          >
            {t('envs.files.compare')}
          </Button>
        ) : null}
        {report.state.type === 'missing' ? (
          <Button
            size="sm"
            aria-label={t('envs.files.writeAgainLabel', { file: name })}
            loading={writeAgain.isPending}
            onClick={() => writeAgain.mutate(undefined)}
          >
            {t('envs.files.writeAgain')}
          </Button>
        ) : null}
      </div>
    </li>
  );
}

interface FlagProps {
  badge: ReactNode;
  text: string;
  action?: ReactNode;
  children?: ReactNode;
}

/** One risk of a file: a badge, what it means, and what to do. */
function Flag({ badge, text, action, children }: FlagProps) {
  return (
    <li className="flex flex-wrap items-center gap-x-2.5 gap-y-1.5">
      {badge}
      <span className="min-w-[200px] flex-1 text-[12.5px] text-fg-2">{text}</span>
      {action}
      {children ? <div className="basis-full">{children}</div> : null}
    </li>
  );
}

interface UnmanagedRowProps {
  found: UnmanagedEnvFile;
  projectName: string;
  onAdopt: () => void;
}

/** A `.env` file in a project's folder that no environment writes. */
function UnmanagedRow({ found, projectName, onAdopt }: UnmanagedRowProps) {
  const { t } = useTranslation();
  const name = bindingPath(found.file);
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-xl border border-ink/[0.07] bg-ink/[0.025] px-3 py-2">
      <span
        aria-hidden="true"
        className="grid size-7 shrink-0 place-items-center rounded-lg border border-line-strong bg-ink/[0.05] text-muted"
      >
        <FileSearch className="size-[14px]" strokeWidth={2} />
      </span>
      <span className="flex min-w-[220px] flex-1 flex-col gap-0.5">
        <span className="selectable truncate font-mono text-[12.5px]" title={found.location}>
          <span className="text-subtle">{found.file.folder}/</span>
          {found.file.path}
        </span>
        <span className="text-[12px] text-muted">
          {t('envs.center.unmanagedIn', { project: projectName })}
        </span>
      </span>
      {found.git?.state === 'untracked' ? (
        <Badge tone="warning">{t('envs.center.gitUntracked')}</Badge>
      ) : null}
      {found.git?.state === 'tracked' ? (
        <Badge tone="critical">{t('envs.center.gitTracked')}</Badge>
      ) : null}
      {found.cloud ? <Badge tone="warning">{cloudBadge(t, found.cloud)}</Badge> : null}
      <Button size="sm" aria-label={t('envs.center.adoptLabel', { file: name })} onClick={onAdopt}>
        {t('envs.center.adopt')}
      </Button>
    </li>
  );
}
