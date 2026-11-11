import { useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import {
  FolderKanban,
  FolderPlus,
  KeyRound,
  MoreHorizontal,
  Pencil,
  Plus,
  RectangleEllipsis,
  Server,
  Trash2,
  Variable,
} from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useConfig, useKeys, useVaultEntries, useVaultStatus } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { Project } from '@/bindings/Project';
import type { ProjectMember } from '@/bindings/ProjectMember';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/components/ui/Menu';
import { Spinner } from '@/components/ui/Spinner';
import { EnvDialog } from '@/features/envs/EnvDialog';
import { useEnvs } from '@/features/envs/queries';
import { EntryEditor } from '@/features/passwords/EntryEditor';
import { useVaultMutation } from '@/features/passwords/vault';
import { updateSettings } from '@/lib/settings';
import { AddMembersDialog, type MemberKind } from './AddMembersDialog';
import { Cards } from './cards';
import { holds, type Library, type Members, memberKey, personal } from './model';
import { ProjectDialog } from './ProjectDialog';
import { PersonalTile, ProjectTile } from './ProjectTile';
import { projectKeys, refreshSuggestions, useProjects } from './queries';

/** What the Add menu creates, in the dialogs the Library uses. */
type NewKind = 'host' | 'key' | 'login' | 'environment';

/**
 * A project's page, where its things are used: connect to its hosts, open a
 * terminal in its folders, run its environments, copy its logins, put its
 * keys in the agent, switch its tunnels, see its findings. Without `id`, the
 * same for Personal: everything in no project.
 */
export function ProjectPage({ id }: { id?: string }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const vaultState = useVaultStatus().data?.state;
  const projects = useProjects();
  const config = useConfig();
  const keys = useKeys();
  const envs = useEnvs();
  const entries = useVaultEntries();
  const project = id ? projects.data?.find((p) => p.id === id) : undefined;
  const dialogs = useDialogs();
  const [adding, setAdding] = useState<MemberKind | null>(null);
  const [creating, setCreating] = useState<'login' | 'environment' | null>(null);
  // What the Add menu made here, listed first on its card.
  const [made, setMade] = useState<Set<string>>(new Set());
  // biome-ignore lint/correctness/useExhaustiveDependencies: forgotten on another project
  useEffect(() => setMade(new Set()), [id]);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const gone = Boolean(id && projects.data && !project);
  const goneFolders = useQuery({
    queryKey: [...projectKeys.all, 'missing', id ?? ''],
    queryFn: () => api.projectsMissingFolders(id ?? ''),
    enabled: Boolean(project && project.folders.length > 0),
  });

  // The app opens on the project used last; one that is gone is forgotten.
  useEffect(() => {
    if (!id || gone) updateSettings({ lastProject: 'personal' });
    else if (project) updateSettings({ lastProject: project.id });
  }, [id, project, gone]);
  // Without a vault there are no projects: Personal is all there is.
  useEffect(() => {
    if (id && vaultState === 'missing') navigate({ page: 'personal' });
  }, [id, vaultState, navigate]);

  const library: Library = {
    hosts: config.data?.view.hosts,
    includes: (config.data?.view.includes.length ?? 0) > 0,
    keys: keys.data?.keys,
    envs: vaultState === 'unlocked' ? envs.data : undefined,
    entries: vaultState === 'unlocked' ? entries.data : undefined,
  };
  const members: Members | undefined = id
    ? project
    : projects.data || vaultState === 'missing'
      ? personal(projects.data ?? [], library)
      : undefined;

  const deleteProject = useVaultMutation(() => api.projectsDelete(id ?? ''), {
    success: () => t('projects.deleted', { name: project?.name ?? '' }),
    onSuccess: () => {
      setDeleting(false);
      void refreshSuggestions();
      navigate({ page: 'personal' });
    },
  });
  const addFolder = useVaultMutation(() => api.projectsAddFolder(id ?? ''), {
    success: (saved) => (saved ? t('projects.folderAdded') : undefined),
    onSuccess: () => void refreshSuggestions(),
  });
  // What was just made joins the project; the dialog's own toast says it.
  const join = useVaultMutation(
    (member: ProjectMember) => api.projectsSetMember(id ?? '', member, true),
    { onSuccess: () => void refreshSuggestions() },
  );
  // Marks what was made (`memberKey`, or `envs:<id>`) and puts it in the project.
  const remember = (made: string) => setMade((current) => new Set(current).add(made));
  const joinMade = (into: Project, member: ProjectMember) => {
    remember(memberKey(member));
    if (!holds(into, member)) join.mutate(member);
  };

  if (id && !projects.data) {
    // Loading, or between the locked and the unlocked list: not Personal.
    return (
      <>
        <Toolbar />
        <PageBody className="items-center justify-center">
          <Spinner />
        </PageBody>
      </>
    );
  }

  if (gone) {
    return (
      <>
        <Toolbar title={t('projects.goneTitle')} />
        <PageBody className="justify-center">
          <EmptyState
            icon={<FolderKanban className="size-6" strokeWidth={2} />}
            title={t('projects.goneTitle')}
            description={t('projects.goneText')}
            action={
              <Button variant="primary" onClick={() => navigate({ page: 'personal' })}>
                {t('projects.openPersonal')}
              </Button>
            }
          />
        </PageBody>
      </>
    );
  }

  const locked = vaultState === 'locked';
  const counts = members ? summary(t, members, locked) : '';
  const empty =
    members &&
    members.hosts.length +
      members.keys.length +
      members.environments.length +
      members.logins.length +
      members.folders.length ===
      0;

  const startAdding = (kind: MemberKind) => {
    if (locked) {
      dialogs.unlockVault({ description: t('projects.unlockToChange') });
      return;
    }
    if (kind === 'folder') addFolder.mutate(undefined);
    else setAdding(kind);
  };

  const openNew = (kind: NewKind, into: Project) => {
    if (kind === 'host') dialogs.addHostFor((alias) => joinMade(into, { type: 'host', alias }));
    else if (kind === 'key') {
      dialogs.generateKeyFor((key) => {
        if (key.fingerprint) joinMade(into, { type: 'key', fingerprint: key.fingerprint });
      });
    } else setCreating(kind);
  };
  // Made things join the project, which lives in the vault: unlocked first.
  const startNew = (kind: NewKind) => {
    if (!project) return;
    if (locked) {
      dialogs.unlockVault({
        description: t('projects.unlockToChange'),
        onUnlocked: () => openNew(kind, project),
      });
    } else openNew(kind, project);
  };

  return (
    <>
      <Toolbar
        title={
          <span className="flex items-center gap-2.5">
            {project ? <ProjectTile project={project} size={24} /> : <PersonalTile size={24} />}
            <span className="truncate">{project ? project.name : t('projects.personal')}</span>
          </span>
        }
        meta={counts}
      >
        {project ? (
          <>
            <AddMenu onAdd={startAdding} onNew={startNew} />
            <Menu>
              <MenuTrigger asChild>
                <IconButton
                  label={t('projects.moreActions')}
                  variant="ghost"
                  icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
                />
              </MenuTrigger>
              <MenuContent>
                <MenuItem
                  icon={<Pencil className="size-[15px]" strokeWidth={1.9} />}
                  onSelect={() =>
                    locked
                      ? dialogs.unlockVault({ description: t('projects.unlockToChange') })
                      : setEditing(true)
                  }
                >
                  {t('projects.edit')}
                </MenuItem>
                <MenuSeparator />
                <MenuItem
                  destructive
                  icon={<Trash2 className="size-[15px]" strokeWidth={1.9} />}
                  onSelect={() =>
                    locked
                      ? dialogs.unlockVault({ description: t('projects.unlockToChange') })
                      : setDeleting(true)
                  }
                >
                  {t('projects.delete')}
                </MenuItem>
              </MenuContent>
            </Menu>
          </>
        ) : null}
      </Toolbar>
      <PageBody>
        {project ? null : <PersonalIntro vaultState={vaultState} />}
        {!members ? null : empty && project ? (
          <EmptyState
            className="my-auto"
            icon={<ProjectTile project={project} size={44} />}
            title={t('projects.emptyTitle', { name: project.name })}
            description={t('projects.emptyText')}
            action={<AddMenu onAdd={startAdding} onNew={startNew} primary />}
          />
        ) : empty && !project && !locked && (projects.data ?? []).length === 0 ? (
          <EmptyState
            className="my-auto"
            icon={<PersonalTile size={44} />}
            title={t('projects.welcomeTitle')}
            description={t('projects.welcomeText')}
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Button variant="primary" onClick={() => dialogs.generateKey()}>
                  {t('projects.generateKey')}
                </Button>
                <Button onClick={() => dialogs.addHost()}>{t('projects.addHost')}</Button>
              </div>
            }
          />
        ) : empty && !project && !locked ? (
          <EmptyState
            className="my-auto"
            icon={<PersonalTile size={44} />}
            title={t('projects.personalEmptyTitle')}
            description={t('projects.personalEmptyText')}
          />
        ) : (
          <Cards
            key={project?.id ?? 'personal'}
            project={project}
            members={members}
            library={library}
            goneFolders={goneFolders.data ?? []}
            locked={locked}
            made={made}
            onAdd={startAdding}
          />
        )}
      </PageBody>
      {project ? (
        <>
          <Dialog open={adding !== null} onOpenChange={(open) => !open && setAdding(null)}>
            {adding && adding !== 'folder' ? (
              <AddMembersDialog
                project={project}
                kind={adding}
                library={library}
                onDone={() => setAdding(null)}
              />
            ) : null}
          </Dialog>
          <Dialog open={creating !== null} onOpenChange={(open) => !open && setCreating(null)}>
            {creating === 'login' ? (
              <EntryEditor
                entry={null}
                onDone={(savedId) => {
                  setCreating(null);
                  if (savedId) joinMade(project, { type: 'login', id: savedId });
                }}
              />
            ) : null}
            {creating === 'environment' ? (
              <EnvDialog
                env={null}
                all={envs.data ?? []}
                defaultProject={project.environments[0] ?? project.name}
                onSaved={(saved) => {
                  remember(`envs:${saved.id}`);
                  joinMade(project, { type: 'environment', group: saved.project });
                }}
                onDone={() => setCreating(null)}
              />
            ) : null}
          </Dialog>
          <Dialog open={editing} onOpenChange={setEditing}>
            {editing ? (
              <ProjectDialog
                project={project}
                all={projects.data ?? []}
                onDone={() => setEditing(false)}
              />
            ) : null}
          </Dialog>
          <ConfirmDialog
            open={deleting}
            onOpenChange={setDeleting}
            title={t('projects.deleteTitle', { name: project.name })}
            description={t('projects.deleteText')}
            confirmLabel={t('projects.deleteConfirm')}
            cancelLabel={t('projects.deleteCancel')}
            destructive
            busy={deleteProject.isPending}
            onConfirm={() => deleteProject.mutate(undefined)}
          />
        </>
      ) : null}
    </>
  );
}

/** "3 hosts · 2 folders · …": what the project shows, kinds it has only. */
function summary(t: TFunction, members: Members, locked: boolean) {
  const parts = [
    members.hosts.length ? t('projects.count.hosts', { count: members.hosts.length }) : null,
    members.folders.length ? t('projects.count.folders', { count: members.folders.length }) : null,
    members.environments.length
      ? t('projects.count.environments', { count: members.environments.length })
      : null,
    !locked && members.logins.length
      ? t('projects.count.logins', { count: members.logins.length })
      : null,
    members.keys.length ? t('projects.count.keys', { count: members.keys.length }) : null,
  ];
  return parts.filter(Boolean).join(' · ');
}

/**
 * Add: items the user has (from the library, or a folder on disk) or new
 * ones, made in the dialogs the Library uses; a new one joins the project.
 */
function AddMenu({
  onAdd,
  onNew,
  primary,
}: {
  onAdd: (kind: MemberKind) => void;
  onNew: (kind: NewKind) => void;
  primary?: boolean;
}) {
  const { t } = useTranslation();
  const icon = (node: ReactNode) => <span className="text-subtle">{node}</span>;
  const server = icon(<Server className="size-[15px]" strokeWidth={1.9} />);
  const key = icon(<KeyRound className="size-[15px]" strokeWidth={1.9} />);
  const login = icon(<RectangleEllipsis className="size-[15px]" strokeWidth={1.9} />);
  const env = icon(<Variable className="size-[15px]" strokeWidth={1.9} />);
  return (
    <Menu>
      <MenuTrigger asChild>
        <Button
          variant={primary ? 'primary' : 'secondary'}
          size={primary ? 'md' : 'sm'}
          icon={<Plus className="size-4" strokeWidth={2.2} />}
        >
          {t('projects.add')}
        </Button>
      </MenuTrigger>
      <MenuContent align={primary ? 'start' : 'end'}>
        <MenuItem icon={server} onSelect={() => onAdd('hosts')}>
          {t('projects.addHosts')}
        </MenuItem>
        <MenuItem icon={key} onSelect={() => onAdd('keys')}>
          {t('projects.addKeys')}
        </MenuItem>
        <MenuItem icon={login} onSelect={() => onAdd('logins')}>
          {t('projects.addLogins')}
        </MenuItem>
        <MenuItem icon={env} onSelect={() => onAdd('environments')}>
          {t('projects.addEnvironments')}
        </MenuItem>
        <MenuItem
          icon={icon(<FolderPlus className="size-[15px]" strokeWidth={1.9} />)}
          onSelect={() => onAdd('folder')}
        >
          {t('projects.addFolder')}
        </MenuItem>
        <MenuSeparator />
        <MenuItem icon={server} onSelect={() => onNew('host')}>
          {t('projects.newHost')}
        </MenuItem>
        <MenuItem icon={key} onSelect={() => onNew('key')}>
          {t('projects.newKey')}
        </MenuItem>
        <MenuItem icon={login} onSelect={() => onNew('login')}>
          {t('projects.newLogin')}
        </MenuItem>
        <MenuItem icon={env} onSelect={() => onNew('environment')}>
          {t('projects.newEnvironment')}
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}

/** What Personal is, and what the vault has to do with projects. */
function PersonalIntro({ vaultState }: { vaultState: string | undefined }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  return (
    <div className="flex flex-col gap-3">
      <p className="max-w-[640px] text-[13px] text-muted">{t('projects.personalText')}</p>
      {vaultState === 'missing' ? (
        <Notice
          icon={<FolderKanban className="size-4" strokeWidth={2} />}
          text={t('projects.noVault')}
          action={
            <Button size="sm" variant="primary" onClick={() => navigate({ page: 'passwords' })}>
              {t('projects.createVault')}
            </Button>
          }
        />
      ) : null}
    </div>
  );
}

function Notice({ icon, text, action }: { icon: ReactNode; text: string; action?: ReactNode }) {
  return (
    <div className="glass flex flex-wrap items-center gap-3 rounded-xl px-3.5 py-2.5 text-[13px] text-fg-2">
      <span className="text-subtle">{icon}</span>
      <span className="min-w-[200px] flex-1">{text}</span>
      {action}
    </div>
  );
}
