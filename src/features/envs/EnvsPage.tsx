import { AlertTriangle, FileUp, MoreHorizontal, Plus, Variable } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useVaultStatus } from '@/api/queries';
import { errorMessage } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import { useFindShortcut } from '@/app/useAppEvents';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/components/ui/Menu';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { CreateVault, RecoveryKeyScreen } from '@/features/passwords/CreateVault';
import { UnlockVault } from '@/features/passwords/UnlockVault';
import { usePendingRecoveryKey } from '@/features/passwords/vault';
import { BackToProject } from '@/features/projects/BackToProject';
import { EnvDialog } from './EnvDialog';
import { EnvList } from './EnvList';
import { EnvPane } from './EnvPane';
import { FilesCenter } from './files/FilesCenter';
import { needsAction, needsAttention, sameFile } from './files/model';
import { useFileRisks, useFileStatuses } from './files/queries';
import { ImportEnvDialog } from './ImportEnvDialog';
import { sectionsOf, showsParts, trashed } from './model';
import { useEnvs } from './queries';
import { useProjectNames } from './useProjectNames';
import { type EnvsView, ViewTabs, viewPanelId } from './ViewTabs';

/**
 * Secret environments: the variables of a project's `.env` files, kept in
 * the vault. Locked or missing, the page offers what the Passwords page
 * does: unlocking, or making the vault.
 */
interface EnvsPageProps {
  envId?: string;
  /** `files`: the management center instead of the environments. */
  view?: 'files';
  project?: string;
}

export function EnvsPage({ envId, view, project }: EnvsPageProps) {
  const { t } = useTranslation();
  const status = useVaultStatus();
  const recoveryKey = usePendingRecoveryKey();
  const state = status.data?.state;

  if (!recoveryKey && state === 'unlocked') {
    return <EnvBrowser envId={envId} view={view} project={project} />;
  }

  return (
    <>
      <Toolbar leading={<BackToProject />} title={t('envs.title')} />
      <PageBody>
        {recoveryKey ? (
          <RecoveryKeyScreen recoveryKey={recoveryKey} />
        ) : status.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : status.isError ? (
          <EmptyState
            className="my-auto"
            icon={
              <Tile tone="rose" size={52} glow>
                <AlertTriangle className="size-6" strokeWidth={2} />
              </Tile>
            }
            title={t('passwords.loadFailed')}
            description={errorMessage(t, status.error)}
            action={<Button onClick={() => void status.refetch()}>{t('common.retry')}</Button>}
          />
        ) : state === 'missing' ? (
          <CreateVault />
        ) : status.data ? (
          <UnlockVault files={status.data.files} device={status.data.device} />
        ) : null}
      </PageBody>
    </>
  );
}

type Editing =
  /** `project`: from a section's +, the project (or Personal, `null`) it starts in. */
  | { kind: 'new'; project?: string | null }
  | { kind: 'edit'; env: EnvDetail }
  /** `into`: opened from an environment, which the import then goes to. */
  | { kind: 'import'; into?: EnvSummary };

function EnvBrowser({ envId, view, project }: EnvsPageProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const envs = useEnvs();
  const statuses = useFileStatuses();
  const risks = useFileRisks();
  // As the Files view's "Needs attention" counts: a state to act on, Git or
  // a cloud folder that would take the values along, missing names.
  const attention = (statuses.data ?? []).filter((status) => {
    const report = risks.data?.find(
      (item) => item.envId === status.envId && sameFile(item.file, status.file),
    );
    return report ? needsAttention({ ...report, state: status.state }) : needsAction(status.state);
  }).length;
  const showFiles = view === 'files';
  const setView = (next: EnvsView) =>
    navigate(next === 'files' ? { page: 'envs', view: 'files', project } : { page: 'envs', envId });
  const [query, setQuery] = useState('');
  const [dialog, setDialog] = useState<Editing | null>(null);
  const search = useRef<HTMLInputElement>(null);
  useFindShortcut(search);

  const all = envs.data ?? [];
  const names = useProjectNames();
  const sections = useMemo(() => sectionsOf(all, names, query), [all, names, query]);
  const inTrash = useMemo(() => trashed(all), [all]);
  const active = all.filter((env) => !env.inTrash);
  const shown = sections.flatMap((section) => section.parts.flatMap((part) => part.envs));
  const selected =
    all.find((env) => env.id === envId) ?? shown[0] ?? (query ? undefined : inTrash[0]);

  const select = (id: string | undefined) => navigate({ page: 'envs', envId: id });

  return (
    <>
      <Toolbar
        leading={<BackToProject />}
        title={t('envs.title')}
        meta={envs.data && !showFiles ? t('envs.meta', { count: active.length }) : undefined}
      >
        <ViewTabs view={showFiles ? 'files' : 'envs'} onChange={setView} attention={attention} />
        {showFiles ? null : (
          <>
            <SearchField
              ref={search}
              value={query}
              onChange={setQuery}
              label={t('envs.searchLabel')}
              placeholder={t('envs.searchPlaceholder')}
              className="w-[230px]"
            />
            <Menu>
              <MenuTrigger asChild>
                <IconButton
                  label={t('envs.more')}
                  variant="secondary"
                  icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
                />
              </MenuTrigger>
              <MenuContent>
                <MenuItem
                  icon={<FileUp className="size-[15px]" strokeWidth={1.9} />}
                  onSelect={() => setDialog({ kind: 'import' })}
                >
                  {t('envs.importEnv')}
                </MenuItem>
              </MenuContent>
            </Menu>
            <Button
              variant="primary"
              size="sm"
              icon={<Plus className="size-3.5" strokeWidth={2.5} />}
              onClick={() => setDialog({ kind: 'new' })}
            >
              {t('envs.newEnv')}
            </Button>
          </>
        )}
      </Toolbar>

      <PageBody>
        {showFiles ? (
          <div id={viewPanelId('files')} role="tabpanel" aria-label={t('envs.views.files')}>
            <FilesCenter
              project={project}
              onProject={(next) => navigate({ page: 'envs', view: 'files', project: next })}
            />
          </div>
        ) : (
          <div
            id={viewPanelId('envs')}
            role="tabpanel"
            aria-label={t('envs.views.envs')}
            className="flex min-h-0 flex-1 flex-col"
          >
            {envs.isPending ? (
              <div className="grid flex-1 place-items-center text-subtle">
                <Spinner className="size-6" />
              </div>
            ) : all.length === 0 ? (
              <EmptyState
                className="my-auto"
                icon={
                  <Tile tone="lime" size={52} glow>
                    <Variable className="size-6" strokeWidth={2} />
                  </Tile>
                }
                title={t('envs.emptyTitle')}
                description={t('envs.emptyText')}
                action={
                  <div className="flex flex-wrap justify-center gap-2">
                    <Button
                      variant="primary"
                      icon={<FileUp className="size-4" strokeWidth={2} />}
                      onClick={() => setDialog({ kind: 'import' })}
                    >
                      {t('envs.importEnv')}
                    </Button>
                    <Button
                      icon={<Plus className="size-4" strokeWidth={2.25} />}
                      onClick={() => setDialog({ kind: 'new' })}
                    >
                      {t('envs.newEnv')}
                    </Button>
                  </div>
                }
              />
            ) : (
              <div className="flex min-h-0 flex-1 items-stretch gap-4">
                <EnvList
                  sections={sections}
                  names={names}
                  showsParts={(section) => showsParts(all, section)}
                  onNew={(section) => setDialog({ kind: 'new', project: section })}
                  trash={inTrash}
                  selectedId={selected?.id}
                  query={query}
                  onSelect={select}
                />
                {selected ? (
                  <EnvPane
                    key={selected.id}
                    summary={selected}
                    all={all}
                    onEdit={(env) => setDialog({ kind: 'edit', env })}
                    onGone={() => select(undefined)}
                    onImport={() => setDialog({ kind: 'import', into: selected })}
                  />
                ) : (
                  <div className="glass grid min-w-0 flex-1 place-items-center rounded-2xl px-6 text-center text-subtle">
                    {t('envs.noMatches')}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </PageBody>

      <Dialog open={dialog !== null} onOpenChange={(open) => (open ? undefined : setDialog(null))}>
        {dialog?.kind === 'new' || dialog?.kind === 'edit' ? (
          <EnvDialog
            env={dialog.kind === 'edit' ? dialog.env : null}
            all={all}
            defaultProject={
              dialog.kind === 'new' && dialog.project !== undefined
                ? dialog.project
                : selected?.project
            }
            onDone={(id) => {
              setDialog(null);
              if (id) select(id);
            }}
          />
        ) : null}
        {dialog?.kind === 'import' ? (
          <ImportEnvDialog
            all={all}
            into={dialog.into}
            onDone={(id) => {
              setDialog(null);
              if (id) select(id);
            }}
          />
        ) : null}
      </Dialog>
    </>
  );
}
