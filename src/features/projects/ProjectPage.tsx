import { useMutation, useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import {
  ArrowLeftRight,
  Copy,
  FolderKanban,
  FolderOpen,
  FolderPlus,
  KeyRound,
  LockKeyhole,
  MoreHorizontal,
  Pencil,
  Play,
  Plus,
  RectangleEllipsis,
  Server,
  ShieldCheck,
  SquareTerminal,
  Trash2,
  User,
  Variable,
} from 'lucide-react';
import { type ReactNode, useEffect, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useAudit, useConfig, useKeys, useVaultEntries, useVaultStatus } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { CopyField } from '@/bindings/CopyField';
import type { HostEntry } from '@/bindings/HostEntry';
import type { Project } from '@/bindings/Project';
import type { ProjectMember } from '@/bindings/ProjectMember';
import type { Severity } from '@/bindings/Severity';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/components/ui/Menu';
import { Spinner } from '@/components/ui/Spinner';
import { Switch } from '@/components/ui/Switch';
import { findingTitle } from '@/features/audit/model';
import { vaultFindingTitle } from '@/features/audit/vaultModel';
import { useEnvs } from '@/features/envs/queries';
import { toastVaultError, useVaultMutation } from '@/features/passwords/vault';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { cn } from '@/lib/cn';
import { updateSettings, useSettings } from '@/lib/settings';
import { AddMembersDialog, type MemberKind } from './AddMembersDialog';
import { useSetMember } from './actions';
import { type Library, type Members, missing, personal } from './model';
import { ProjectDialog } from './ProjectDialog';
import { AddToProjectButton } from './ProjectMenu';
import { PersonalTile, ProjectTile } from './ProjectTile';
import { projectKeys, refreshSuggestions, useProjects } from './queries';

const COPIED = {
  username: 'passwords.copiedUsername',
  password: 'passwords.copiedPassword',
  url: 'passwords.copiedUrl',
  otp: 'passwords.copiedOtp',
} as const;

const SEVERITY_DOT: Record<Severity, string> = {
  critical: 'bg-critical-solid',
  warning: 'bg-warning-solid',
  info: 'bg-info-solid',
};

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
            <AddMenu onAdd={startAdding} />
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
            action={<AddMenu onAdd={startAdding} primary />}
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
            project={project}
            members={members}
            library={library}
            goneFolders={goneFolders.data ?? []}
            locked={locked}
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

function AddMenu({ onAdd, primary }: { onAdd: (kind: MemberKind) => void; primary?: boolean }) {
  const { t } = useTranslation();
  const icon = (node: ReactNode) => <span className="text-subtle">{node}</span>;
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
        <MenuItem
          icon={icon(<Server className="size-[15px]" strokeWidth={1.9} />)}
          onSelect={() => onAdd('hosts')}
        >
          {t('projects.addHosts')}
        </MenuItem>
        <MenuItem
          icon={icon(<KeyRound className="size-[15px]" strokeWidth={1.9} />)}
          onSelect={() => onAdd('keys')}
        >
          {t('projects.addKeys')}
        </MenuItem>
        <MenuItem
          icon={icon(<RectangleEllipsis className="size-[15px]" strokeWidth={1.9} />)}
          onSelect={() => onAdd('logins')}
        >
          {t('projects.addLogins')}
        </MenuItem>
        <MenuItem
          icon={icon(<Variable className="size-[15px]" strokeWidth={1.9} />)}
          onSelect={() => onAdd('environments')}
        >
          {t('projects.addEnvironments')}
        </MenuItem>
        <MenuSeparator />
        <MenuItem
          icon={icon(<FolderPlus className="size-[15px]" strokeWidth={1.9} />)}
          onSelect={() => onAdd('folder')}
        >
          {t('projects.addFolder')}
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

interface CardsProps {
  project: Project | undefined;
  members: Members;
  library: Library;
  /** The project's folders not found on this computer. */
  goneFolders: string[];
  locked: boolean;
  onAdd: (kind: MemberKind) => void;
}

/** The project's cards, only for the kinds it has. */
function Cards({ project, members, library, goneFolders, locked, onAdd }: CardsProps) {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const gone = project
    ? missing(project, library, goneFolders)
    : {
        hosts: new Set<string>(),
        keys: new Set<string>(),
        environments: new Set<string>(),
        folders: new Set<string>(),
      };
  const lockedNotice =
    locked && (!project || project.environments.length > 0 || project.logins.length === 0);
  return (
    <div className="grid items-start gap-3 xl:grid-cols-2">
      {members.hosts.length ? (
        <HostsCard project={project} hosts={members.hosts} gone={gone.hosts} />
      ) : null}
      {members.folders.length && project ? (
        <FoldersCard
          project={project}
          folders={members.folders}
          gone={gone.folders}
          locked={locked}
          library={library}
        />
      ) : null}
      {lockedNotice ? (
        <Card
          icon={<LockKeyhole className="size-3.5 text-subtle" strokeWidth={2.2} />}
          title={t('projects.lockedTitle')}
        >
          <li className="flex flex-wrap items-center gap-3 px-1 py-2 text-[13px] text-fg-2">
            <span className="min-w-[220px] flex-1">
              {project ? t('projects.lockedText') : t('projects.lockedTextPersonal')}
            </span>
            <Button size="sm" variant="primary" onClick={() => dialogs.unlockVault()}>
              {t('projects.unlock')}
            </Button>
          </li>
        </Card>
      ) : null}
      {!locked && members.environments.length ? (
        <EnvironmentsCard
          project={project}
          groups={members.environments}
          gone={gone.environments}
          library={library}
        />
      ) : null}
      {!locked && members.logins.length ? (
        <LoginsCard project={project} logins={members.logins} library={library} />
      ) : null}
      {members.keys.length ? (
        <KeysCard project={project} keys={members.keys} gone={gone.keys} library={library} />
      ) : null}
      <TunnelsCard hosts={members.hosts} />
      <FindingsCard members={members} library={library} />
      {project && members.hosts.length === 0 && members.folders.length === 0 ? (
        <div className="flex flex-wrap gap-2 xl:col-span-2">
          <Button
            size="sm"
            variant="ghost"
            icon={<Plus className="size-4" strokeWidth={2} />}
            onClick={() => onAdd('hosts')}
          >
            {t('projects.addHosts')}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            icon={<FolderPlus className="size-4" strokeWidth={2} />}
            onClick={() => onAdd('folder')}
          >
            {t('projects.addFolder')}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

function Card({
  icon,
  title,
  count,
  action,
  children,
}: {
  icon: ReactNode;
  title: string;
  count?: string | number;
  action?: ReactNode;
  children: ReactNode;
}) {
  const headingId = useId();
  return (
    <section
      aria-labelledby={headingId}
      className="glass flex min-w-0 flex-col rounded-2xl px-3 pt-2.5 pb-1.5"
    >
      <header className="flex min-h-7 items-center gap-2 px-1 pb-1">
        {icon}
        <h2 id={headingId} className="text-[13px] font-semibold">
          {title}
        </h2>
        {count !== undefined ? <span className="text-[12px] text-subtle">{count}</span> : null}
        <span className="flex-1" />
        {action}
      </header>
      <ul className="flex flex-col">{children}</ul>
    </section>
  );
}

function Row({
  leading,
  title,
  subtitle,
  mono,
  children,
}: {
  leading?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  mono?: boolean;
  children?: ReactNode;
}) {
  return (
    <li className="flex min-h-11 items-center gap-2.5 border-t border-white/[0.045] px-1 py-1.5 first:border-t-0">
      {leading}
      <div className="min-w-0 flex-1">
        <div className={cn('truncate font-medium', mono && 'font-mono text-[12.5px]')}>{title}</div>
        {subtitle ? <div className="truncate text-[11.5px] text-subtle">{subtitle}</div> : null}
      </div>
      <div className="flex shrink-0 items-center gap-1.5">{children}</div>
    </li>
  );
}

/** "Not in ~/.ssh/config" with its warning dot. */
function Problem({ text }: { text: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-warning">
      <span aria-hidden="true" className="size-1.5 rounded-full bg-warning-solid" />
      {text}
    </span>
  );
}

function Monogram({ text, className }: { text: string; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cn(
        'grid size-7 shrink-0 place-items-center rounded-lg bg-white/[0.07] text-[10px] font-bold text-fg-2',
        className,
      )}
    >
      {text.slice(0, 2).toUpperCase()}
    </span>
  );
}

/** "Remove" for a member that is gone, or "Add to project…" on Personal. */
/**
 * "Remove" for a member missing on this computer. It may be fine on the
 * user's other devices, and the project is the same everywhere, so it asks
 * first; the toast can undo it.
 */
function RemoveButton({
  project,
  member,
  name,
}: {
  project: Project;
  member: ProjectMember;
  name: string;
}) {
  const { t } = useTranslation();
  const setMember = useSetMember();
  const [asking, setAsking] = useState(false);
  return (
    <>
      <Button
        size="sm"
        variant="ghost"
        aria-label={t('projects.removeNamed', { name, project: project.name })}
        onClick={() => setAsking(true)}
      >
        {t('projects.remove')}
      </Button>
      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        title={t('projects.removeGoneTitle', { name, project: project.name })}
        description={t('projects.removeGoneText', { project: project.name })}
        confirmLabel={t('projects.removeGoneConfirm')}
        cancelLabel={t('projects.removeGoneCancel')}
        destructive
        busy={setMember.isPending}
        onConfirm={() =>
          setMember.mutate(
            { project, member, included: false },
            { onSettled: () => setAsking(false) },
          )
        }
      />
    </>
  );
}

function hostLine(host: HostEntry | undefined, alias: string, t: TFunction) {
  if (!host) return '';
  const target = `${host.user ? `${host.user}@` : ''}${host.hostName ?? alias}${host.port && host.port !== 22 ? `:${host.port}` : ''}`;
  return host.proxyJump ? t('projects.via', { target, jump: host.proxyJump }) : target;
}

function HostsCard({
  project,
  hosts,
  gone,
}: {
  project?: Project;
  hosts: string[];
  gone: Set<string>;
}) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  const config = useConfig();
  const byAlias = useMemo(() => {
    const map = new Map<string, HostEntry>();
    for (const host of config.data?.view.hosts ?? [])
      for (const p of host.patterns) map.set(p, host);
    return map;
  }, [config.data]);
  return (
    <Card
      icon={<Server className="size-3.5 text-[#7DD3FC]" strokeWidth={2.2} />}
      title={t('projects.cards.hosts')}
      count={hosts.length}
    >
      {hosts.map((alias) => {
        const member: ProjectMember = { type: 'host', alias };
        return (
          <Row
            key={alias}
            mono
            leading={<Monogram text={alias} />}
            title={alias}
            subtitle={
              gone.has(alias) ? (
                <Problem text={t('projects.hostGone')} />
              ) : (
                hostLine(byAlias.get(alias), alias, t)
              )
            }
          >
            {gone.has(alias) && project ? (
              <RemoveButton project={project} member={member} name={alias} />
            ) : (
              <>
                {project ? null : <AddToProjectButton member={member} name={alias} />}
                <Button
                  size="sm"
                  icon={<SquareTerminal className="size-3.5" strokeWidth={2} />}
                  aria-label={t('projects.connectTo', { name: alias })}
                  onClick={() => {
                    terminals.open(alias);
                    navigate({ page: 'terminal' });
                  }}
                >
                  {t('projects.connect')}
                </Button>
              </>
            )}
          </Row>
        );
      })}
    </Card>
  );
}

function FoldersCard({
  project,
  folders,
  gone,
  locked,
  library,
}: {
  project: Project;
  folders: string[];
  gone: Set<string>;
  locked: boolean;
  library: Library;
}) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  const hasLocal =
    !locked &&
    (library.envs ?? []).some(
      (env) =>
        !env.inTrash &&
        env.name.toLowerCase() === 'local' &&
        project.environments.includes(env.project),
    );
  return (
    <Card
      icon={<FolderOpen className="size-3.5 text-[#86EFAC]" strokeWidth={2.2} />}
      title={t('projects.cards.folders')}
      count={folders.length}
    >
      {folders.map((path) => {
        const name = path.split(/[\\/]/).filter(Boolean).pop() ?? path;
        return (
          <Row
            key={path}
            mono
            leading={
              <FolderOpen
                aria-hidden="true"
                className="size-4 shrink-0 text-subtle"
                strokeWidth={1.9}
              />
            }
            title={path}
            subtitle={
              gone.has(path) ? (
                <Problem text={t('projects.folderGone')} />
              ) : hasLocal ? (
                t('projects.withLocal')
              ) : undefined
            }
          >
            {gone.has(path) ? (
              <RemoveButton project={project} member={{ type: 'folder', path }} name={path} />
            ) : (
              <Button
                size="sm"
                icon={<SquareTerminal className="size-3.5" strokeWidth={2} />}
                aria-label={t('projects.openTerminalIn', { name: path })}
                onClick={() => {
                  terminals.openLocal({
                    folder: { project: project.id, path, label: `${project.name} · ${name}` },
                  });
                  navigate({ page: 'terminal' });
                }}
              >
                {t('projects.openTerminal')}
              </Button>
            )}
          </Row>
        );
      })}
    </Card>
  );
}

function EnvironmentsCard({
  project,
  groups,
  gone,
  library,
}: {
  project?: Project;
  groups: string[];
  gone: Set<string>;
  library: Library;
}) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  return (
    <Card
      icon={<Variable className="size-3.5 text-[#D9F99D]" strokeWidth={2.2} />}
      title={t('projects.cards.environments')}
      count={groups.length > 1 ? groups.length : groups[0]}
    >
      {groups.map((group) => {
        const member: ProjectMember = { type: 'environment', group };
        if (!library.envs) {
          return <Row key={group} mono title={group} subtitle={t('common.loading')} />;
        }
        const envs = library.envs.filter((env) => !env.inTrash && env.project === group);
        if (gone.has(group) || envs.length === 0) {
          return (
            <Row
              key={group}
              mono
              title={group}
              subtitle={<Problem text={t('projects.groupGone')} />}
            >
              {project ? <RemoveButton project={project} member={member} name={group} /> : null}
            </Row>
          );
        }
        return envs.map((env, index) => (
          <Row
            key={env.id}
            leading={
              <span
                className={cn(
                  'inline-flex h-[22px] min-w-12 items-center justify-center rounded-full px-2 font-mono text-[11.5px]',
                  ['prod', 'production', 'live'].includes(env.name.toLowerCase())
                    ? 'bg-[rgb(225_29_72/0.18)] text-[#fecdd3]'
                    : 'bg-white/[0.06] text-fg-2',
                )}
              >
                {env.name}
              </span>
            }
            title={groups.length > 1 && index === 0 ? group : ''}
            subtitle={
              env.secretCount
                ? t('envs.countsWithSecrets', {
                    count: env.variableCount,
                    secrets: env.secretCount,
                  })
                : t('envs.counts', { count: env.variableCount })
            }
          >
            {project || index > 0 ? null : <AddToProjectButton member={member} name={group} />}
            <Button
              size="sm"
              icon={<Play className="size-3" strokeWidth={2.4} />}
              aria-label={t('projects.runIn', { name: `${group} · ${env.name}` })}
              onClick={() => {
                terminals.openLocal({ env: { id: env.id, label: `${group} · ${env.name}` } });
                navigate({ page: 'terminal' });
              }}
            >
              {t('projects.run')}
            </Button>
          </Row>
        ));
      })}
    </Card>
  );
}

function LoginsCard({
  project,
  logins,
  library,
}: {
  project?: Project;
  logins: string[];
  library: Library;
}) {
  const { t } = useTranslation();
  const byId = new Map((library.entries ?? []).map((entry) => [entry.id, entry]));
  const copy = useMutation({
    mutationFn: ({ id, field }: { id: string; field: CopyField }) => api.vaultCopy(id, field),
    onSuccess: (result, { field }) => {
      toast.success(t(COPIED[field]), {
        id: 'vault-copy',
        description:
          result.clearsInSecs !== null
            ? t('passwords.clearsIn', { seconds: result.clearsInSecs })
            : undefined,
      });
    },
    onError: (error) => toastVaultError(t, error),
  });
  const shown = logins.map((id) => byId.get(id)).filter((entry) => entry !== undefined);
  if (shown.length === 0) return null;
  return (
    <Card
      icon={<RectangleEllipsis className="size-3.5 text-[#F9A8D4]" strokeWidth={2.2} />}
      title={t('projects.cards.logins')}
      count={shown.length}
    >
      {shown.map((entry) => {
        const site = entry.url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
        return (
          <Row
            key={entry.id}
            leading={<Monogram text={entry.title} />}
            title={entry.title}
            subtitle={[entry.username, site].filter(Boolean).join(' · ')}
          >
            {project ? null : (
              <AddToProjectButton member={{ type: 'login', id: entry.id }} name={entry.title} />
            )}
            {entry.username ? (
              <IconButton
                label={t('projects.copyUsername', { name: entry.title })}
                variant="ghost"
                icon={<User className="size-4" strokeWidth={1.9} />}
                onClick={() => copy.mutate({ id: entry.id, field: 'username' })}
              />
            ) : null}
            {entry.hasPassword ? (
              <Button
                size="sm"
                icon={<Copy className="size-3.5" strokeWidth={2} />}
                aria-label={t('projects.copyPasswordOf', { name: entry.title })}
                onClick={() => copy.mutate({ id: entry.id, field: 'password' })}
              >
                {t('projects.copyPassword')}
              </Button>
            ) : null}
          </Row>
        );
      })}
    </Card>
  );
}

function KeysCard({
  project,
  keys,
  gone,
  library,
}: {
  project?: Project;
  keys: string[];
  gone: Set<string>;
  library: Library;
}) {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const byFingerprint = new Map((library.keys ?? []).map((key) => [key.fingerprint, key]));
  return (
    <Card
      icon={<KeyRound className="size-3.5 text-[#5EEAD4]" strokeWidth={2.2} />}
      title={t('projects.cards.keys')}
      count={keys.length}
    >
      {keys.map((fingerprint) => {
        const key = byFingerprint.get(fingerprint);
        const member: ProjectMember = { type: 'key', fingerprint };
        const short = `${fingerprint.slice(0, 15)}…${fingerprint.slice(-4)}`;
        return (
          <Row
            key={fingerprint}
            mono
            leading={
              <KeyRound
                aria-hidden="true"
                className="size-4 shrink-0 text-subtle"
                strokeWidth={1.9}
              />
            }
            title={key?.name ?? short}
            subtitle={
              gone.has(fingerprint) ? (
                <Problem text={t('projects.keyGone')} />
              ) : (
                <span className="font-mono">{short}</span>
              )
            }
          >
            {gone.has(fingerprint) && project ? (
              <RemoveButton project={project} member={member} name={key?.name ?? short} />
            ) : key ? (
              <>
                {project ? null : <AddToProjectButton member={member} name={key.name} />}
                {key.inAgent ? (
                  <span className="inline-flex h-[22px] items-center gap-1.5 rounded-full bg-[rgb(94_234_212/0.1)] px-2 text-[11.5px] text-ok">
                    <span aria-hidden="true" className="size-1.5 rounded-full bg-ok" />
                    {t('projects.inAgent')}
                  </span>
                ) : (
                  <Button
                    size="sm"
                    aria-label={t('projects.addToAgentNamed', { name: key.name })}
                    onClick={() => dialogs.unlockKey(key)}
                  >
                    {t('projects.addToAgent')}
                  </Button>
                )}
              </>
            ) : null}
          </Row>
        );
      })}
    </Card>
  );
}

function TunnelsCard({ hosts }: { hosts: string[] }) {
  const { t } = useTranslation();
  const tunnels = useQuery({ queryKey: ['tunnels'], queryFn: api.tunnelList });
  const toggle = useMutation({
    mutationFn: ({ id, on }: { id: string; on: boolean }) => api.tunnelSetOn(id, on),
    onSettled: () => void tunnels.refetch(),
    onError: (error) => toastVaultError(t, error),
  });
  const mine = (tunnels.data ?? []).filter((view) => hosts.includes(view.tunnel.alias));
  if (mine.length === 0) return null;
  return (
    <Card
      icon={<ArrowLeftRight className="size-3.5 text-[#67E8F9]" strokeWidth={2.2} />}
      title={t('projects.cards.tunnels')}
      count={mine.length}
    >
      {mine.map(({ tunnel, state }) => {
        const route =
          tunnel.kind === 'dynamic'
            ? t('projects.tunnelSocks', { port: tunnel.listenPort })
            : `${tunnel.listenPort} → ${tunnel.targetHost ?? ''}:${tunnel.targetPort ?? ''}`;
        const on = state.state !== 'off' && state.state !== 'failed';
        const label = tunnel.name || route;
        return (
          <Row
            key={tunnel.id}
            mono={!tunnel.name}
            title={label}
            subtitle={t('projects.through', { alias: tunnel.alias })}
          >
            <Switch
              checked={on}
              aria-label={t('projects.tunnelSwitch', { name: label })}
              onCheckedChange={(checked) => toggle.mutate({ id: tunnel.id, on: checked })}
            />
          </Row>
        );
      })}
    </Card>
  );
}

function FindingsCard({ members, library }: { members: Members; library: Library }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const audit = useAudit();
  const vaultState = useVaultStatus().data?.state;
  const vaultAudit = useQuery({
    queryKey: ['vault', 'audit', vaultState],
    queryFn: api.vaultAudit,
    enabled: vaultState !== undefined,
  });
  const ignored = new Set(useSettings().ignoredFindings);
  const hostIds = new Set(
    (library.hosts ?? [])
      .filter((h) => h.patterns.some((p) => members.hosts.includes(p)))
      .map((h) => h.id),
  );
  const keyIds = new Set(
    (library.keys ?? [])
      .filter((k) => k.fingerprint !== null && members.keys.includes(k.fingerprint))
      .map((k) => k.id),
  );
  const logins = new Set(members.logins);
  const keyNames = new Map((library.keys ?? []).map((k) => [k.id, k.name]));
  const hostNames = new Map((library.hosts ?? []).map((h) => [h.id, h.patterns.join(' ')]));
  const entryNames = new Map((library.entries ?? []).map((e) => [e.id, e.title]));
  const found = [
    ...(audit.data?.findings ?? [])
      .filter((f) => !ignored.has(f.id))
      .filter(
        (f) =>
          (f.subject.hostId !== null && hostIds.has(f.subject.hostId)) ||
          (f.subject.keyId !== null && keyIds.has(f.subject.keyId)),
      )
      .map((f) => ({
        id: f.id,
        severity: f.severity,
        title: findingTitle(t, f),
        about:
          (f.subject.keyId !== null ? keyNames.get(f.subject.keyId) : undefined) ??
          (f.subject.hostId !== null ? hostNames.get(f.subject.hostId) : undefined),
      })),
    ...(vaultAudit.data?.findings ?? [])
      .filter((f) => !ignored.has(f.id) && logins.has(f.entryId))
      .map((f) => ({
        id: f.id,
        severity: f.severity,
        title: vaultFindingTitle(t, f),
        about: entryNames.get(f.entryId),
      })),
  ];
  if (found.length === 0) return null;
  return (
    <Card
      icon={<ShieldCheck className="size-3.5 text-[#FDA4AF]" strokeWidth={2.2} />}
      title={t('projects.cards.findings')}
      count={found.length}
      action={
        <Button size="sm" variant="ghost" onClick={() => navigate({ page: 'audit' })}>
          {t('projects.openAudit')}
        </Button>
      }
    >
      {found.slice(0, 6).map((finding) => (
        <Row
          key={finding.id}
          leading={
            <span
              aria-hidden="true"
              className={cn('size-2 shrink-0 rounded-full', SEVERITY_DOT[finding.severity])}
            />
          }
          title={finding.title}
          subtitle={[t(`projects.severity.${finding.severity}`), finding.about]
            .filter(Boolean)
            .join(' · ')}
        />
      ))}
    </Card>
  );
}
