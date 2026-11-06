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
import { EnvDialog } from './EnvDialog';
import { EnvList } from './EnvList';
import { EnvPane } from './EnvPane';
import { ImportEnvDialog } from './ImportEnvDialog';
import { groupByProject, trashed } from './model';
import { useEnvs } from './queries';

/**
 * Secret environments: the variables of a project's `.env` files, kept in
 * the vault. Locked or missing, the page offers what the Passwords page
 * does: unlocking, or making the vault.
 */
export function EnvsPage({ envId }: { envId?: string }) {
  const { t } = useTranslation();
  const status = useVaultStatus();
  const recoveryKey = usePendingRecoveryKey();
  const state = status.data?.state;

  if (!recoveryKey && state === 'unlocked') return <EnvBrowser envId={envId} />;

  return (
    <>
      <Toolbar title={t('envs.title')} />
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
  | { kind: 'new' }
  | { kind: 'edit'; env: EnvDetail }
  /** `into`: opened from an environment, which the import then goes to. */
  | { kind: 'import'; into?: EnvSummary };

function EnvBrowser({ envId }: { envId?: string }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const envs = useEnvs();
  const [query, setQuery] = useState('');
  const [dialog, setDialog] = useState<Editing | null>(null);
  const search = useRef<HTMLInputElement>(null);
  useFindShortcut(search);

  const all = envs.data ?? [];
  const groups = useMemo(() => groupByProject(all, query), [all, query]);
  const inTrash = useMemo(() => trashed(all), [all]);
  const active = all.filter((env) => !env.inTrash);
  const shown = groups.flatMap((group) => group.envs);
  const selected =
    all.find((env) => env.id === envId) ?? shown[0] ?? (query ? undefined : inTrash[0]);

  const select = (id: string | undefined) => navigate({ page: 'envs', envId: id });

  return (
    <>
      <Toolbar
        title={t('envs.title')}
        meta={envs.data ? t('envs.meta', { count: active.length }) : undefined}
      >
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
      </Toolbar>

      <PageBody>
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
              groups={groups}
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
      </PageBody>

      <Dialog open={dialog !== null} onOpenChange={(open) => (open ? undefined : setDialog(null))}>
        {dialog?.kind === 'new' || dialog?.kind === 'edit' ? (
          <EnvDialog
            env={dialog.kind === 'edit' ? dialog.env : null}
            all={all}
            defaultProject={selected?.project}
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
