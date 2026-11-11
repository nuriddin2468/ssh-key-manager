import { useMutation, useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import {
  ArrowLeftRight,
  ChevronDown,
  Copy,
  Folder,
  FolderOpen,
  FolderPlus,
  KeyRound,
  LockKeyhole,
  Network,
  Play,
  Plus,
  RectangleEllipsis,
  Server,
  ShieldCheck,
  SquareTerminal,
  User,
  Variable,
} from 'lucide-react';
import { Fragment, type ReactNode, useId, useMemo, useState, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useAudit, useConfig, useHostsFile } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { CopyField } from '@/bindings/CopyField';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { Project } from '@/bindings/Project';
import type { ProjectMember } from '@/bindings/ProjectMember';
import type { Severity } from '@/bindings/Severity';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { MixedSwitch, Switch } from '@/components/ui/Switch';
import { findingTitle } from '@/features/audit/model';
import { useVaultAudit } from '@/features/audit/queries';
import { vaultFindingTitle } from '@/features/audit/vaultModel';
import { editOf } from '@/features/hostsFile/draft';
import { normalizeName } from '@/features/hostsFile/model';
import { ReviewDialog, type ReviewNote } from '@/features/hostsFile/ReviewDialog';
import { toastVaultError } from '@/features/passwords/vault';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { cn } from '@/lib/cn';
import { fileManagerName } from '@/lib/platform';
import { useSettings } from '@/lib/settings';
import type { MemberKind } from './AddMembersDialog';
import { useSetMember } from './actions';
import {
  bySeverity,
  CARD_LIMIT,
  cardColumns,
  hostsFileEntries,
  type Library,
  type Members,
  type Missing,
  memberKey,
  missing,
  planHostsFileSwitch,
  problemsFirst,
  projectFindings,
} from './model';
import { AddToProjectButton } from './ProjectMenu';
import { useProjects } from './queries';

const COPIED = {
  username: 'passwords.copiedUsername',
  password: 'passwords.copiedPassword',
  url: 'passwords.copiedUrl',
  otp: 'passwords.copiedOtp',
} as const;

export const SEVERITY_DOT: Record<Severity, string> = {
  critical: 'bg-critical-solid',
  warning: 'bg-warning-solid',
  info: 'bg-info-solid',
};

/** One row of a card; rows with a `problem` come first. */
interface CardRow {
  key: string;
  problem?: boolean;
  /** Just made on the page: shown before the rest, so it's seen folded too. */
  fresh?: boolean;
  node: ReactNode;
}

/** What a card shows: the page lays the cards out by their rows. */
interface CardSpec {
  id: string;
  icon: ReactNode;
  title: string;
  count?: string | number;
  action?: ReactNode;
  rows: CardRow[];
}

/** Where items open from: the project, or Personal. */
interface Origin {
  project?: Project;
  /** `back` for the Library's routes. */
  back: string;
  /** What was made on the page (`memberKey`, `envs:<id>`), shown first. */
  made: Set<string>;
}

const WIDE = '(min-width: 80rem)';

/** Two columns from Tailwind's `xl` on, like the rest of the app. */
function useWide() {
  return useSyncExternalStore(
    (changed) => {
      if (typeof window.matchMedia !== 'function') return () => {};
      const query = window.matchMedia(WIDE);
      query.addEventListener('change', changed);
      return () => query.removeEventListener('change', changed);
    },
    () => typeof window.matchMedia === 'function' && window.matchMedia(WIDE).matches,
  );
}

interface CardsProps {
  project: Project | undefined;
  members: Members;
  library: Library;
  /** The project's folders not found on this computer. */
  goneFolders: string[];
  locked: boolean;
  /** What the Add menu made on the page (`memberKey`, `envs:<id>`). */
  made: Set<string>;
  onAdd: (kind: MemberKind) => void;
}

const NOTHING_GONE: Missing = {
  hosts: new Set(),
  keys: new Set(),
  environments: new Set(),
  folders: new Set(),
  hostsFile: new Set(),
};

/**
 * The project's cards, only for the kinds it has. Each shows five rows,
 * problems first, and the rest on "Show all". Wide, they stand in two
 * columns of their own, so a long card doesn't push the other column down.
 */
export function Cards({ project, members, library, goneFolders, locked, made, onAdd }: CardsProps) {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const wide = useWide();
  const gone = project ? missing(project, library, goneFolders) : NOTHING_GONE;
  const origin: Origin = { project, back: project ? project.id : 'personal', made };
  const lockedNotice =
    locked && (!project || project.environments.length > 0 || project.logins.length === 0);

  const hosts = useHostsCard(origin, members.hosts, gone.hosts);
  const hostsFile = useHostsFileCard(origin, members.hostsFile, gone.hostsFile);
  const folders = useFoldersCard(project, members.folders, gone.folders, locked, library);
  const environments = useEnvironmentsCard(
    origin,
    locked ? [] : members.environments,
    gone.environments,
    library,
  );
  const logins = useLoginsCard(origin, locked ? [] : members.logins, library);
  const keys = useKeysCard(origin, members.keys, gone.keys, library);
  const tunnels = useTunnelsCard(members.hosts);
  const findings = useFindingsCard(members, library);
  const notice: CardSpec | null = lockedNotice
    ? {
        id: 'locked',
        icon: <LockKeyhole className="size-3.5 text-subtle" strokeWidth={2.2} />,
        title: t('projects.lockedTitle'),
        rows: [
          {
            key: 'locked',
            node: (
              <li className="flex flex-wrap items-center gap-3 px-1 py-2 text-[13px] text-fg-2">
                <span className="min-w-[220px] flex-1">
                  {project ? t('projects.lockedText') : t('projects.lockedTextPersonal')}
                </span>
                <Button size="sm" variant="primary" onClick={() => dialogs.unlockVault()}>
                  {t('projects.unlock')}
                </Button>
              </li>
            ),
          },
        ],
      }
    : null;

  const cards = [
    hosts,
    hostsFile,
    folders,
    notice,
    environments,
    logins,
    keys,
    tunnels,
    findings,
  ].filter((card) => card !== null);
  const quickAdd =
    project && members.hosts.length === 0 && members.folders.length === 0 ? (
      <div className="flex flex-wrap gap-2">
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
    ) : null;

  if (!wide) {
    return (
      <div className="flex flex-col gap-3">
        {cards.map((card) => (
          <Card key={card.id} card={card} />
        ))}
        {quickAdd}
      </div>
    );
  }
  const columns = cardColumns(cards.map((card) => card.rows.length)).map((column) =>
    column.flatMap((index) => cards[index] ?? []),
  );
  return (
    <div className="flex flex-col gap-3">
      <div className="grid grid-cols-2 items-start gap-3">
        {columns.map((column, side) => (
          <div key={side === 0 ? 'left' : 'right'} className="flex min-w-0 flex-col gap-3">
            {column.map((card) => (
              <Card key={card.id} card={card} />
            ))}
          </div>
        ))}
      </div>
      {quickAdd}
    </div>
  );
}

function Card({ card }: { card: CardSpec }) {
  const { t } = useTranslation();
  const headingId = useId();
  const listId = useId();
  const [all, setAll] = useState(false);
  const rows = problemsFirst(card.rows);
  const folds = rows.length > CARD_LIMIT;
  const shown = folds && !all ? rows.slice(0, CARD_LIMIT) : rows;
  return (
    <section
      aria-labelledby={headingId}
      className="glass flex min-w-0 flex-col rounded-2xl px-3 pt-2.5 pb-1.5"
    >
      <header className="flex min-h-7 items-center gap-2 px-1 pb-1">
        {card.icon}
        <h2 id={headingId} className="text-[13px] font-semibold">
          {card.title}
        </h2>
        {card.count !== undefined ? (
          <span className="truncate text-[12px] text-subtle">{card.count}</span>
        ) : null}
        <span className="flex-1" />
        {card.action}
      </header>
      <ul id={listId} className="flex flex-col">
        {shown.map((row) => (
          <Fragment key={row.key}>{row.node}</Fragment>
        ))}
      </ul>
      {folds ? (
        <Button
          variant="ghost"
          size="sm"
          className="mt-0.5 mb-1 self-start px-2 text-[12px] text-subtle"
          aria-expanded={all}
          aria-controls={listId}
          icon={
            <ChevronDown
              aria-hidden="true"
              className={cn('size-3.5 transition-transform', all && 'rotate-180')}
              strokeWidth={2.2}
            />
          }
          onClick={() => setAll((current) => !current)}
        >
          {all ? t('projects.showFewer') : t('projects.showAll', { total: rows.length })}
        </Button>
      ) : null}
    </section>
  );
}

/** Opens an item in its Library section. */
interface Opener {
  /** "Open prod in Hosts": the tooltip, and the name screen readers hear. */
  label: string;
  onOpen: () => void;
}

/**
 * A row: an item's name (a link to it in the Library, with `open`), a line
 * under it, an optional `detail` line for what's going on with it, and its
 * actions on the right.
 */
function Row({
  leading,
  title,
  subtitle,
  detail,
  mono,
  open,
  children,
}: {
  leading?: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  detail?: ReactNode;
  mono?: boolean;
  open?: Opener;
  children?: ReactNode;
}) {
  const text = cn('truncate font-medium', mono && 'font-mono text-[12.5px]');
  return (
    <li className="flex min-h-11 items-center gap-2.5 border-t border-white/[0.045] px-1 py-1.5 first:border-t-0">
      {leading}
      <div className="min-w-0 flex-1">
        {open ? (
          <button
            type="button"
            title={open.label}
            aria-label={open.label}
            onClick={open.onOpen}
            className={cn(
              text,
              '-my-0.5 block max-w-full rounded py-0.5 text-left decoration-white/40 underline-offset-[3px] outline-none hover:underline focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.6)]',
            )}
          >
            {title}
          </button>
        ) : title ? (
          <div className={text}>{title}</div>
        ) : null}
        {subtitle ? <div className="truncate text-[11.5px] text-subtle">{subtitle}</div> : null}
        {detail ? <div className="truncate text-[11.5px] text-subtle">{detail}</div> : null}
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

function useHostsCard(
  { project, back, made }: Origin,
  hosts: string[],
  gone: Set<string>,
): CardSpec | null {
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
  if (hosts.length === 0) return null;
  const section = t('nav.hosts');
  return {
    id: 'hosts',
    icon: <Server className="size-3.5 text-[#7DD3FC]" strokeWidth={2.2} />,
    title: t('projects.cards.hosts'),
    count: hosts.length,
    rows: hosts.map((alias) => {
      const member: ProjectMember = { type: 'host', alias };
      const host = byAlias.get(alias);
      const problem = gone.has(alias);
      return {
        key: alias,
        problem,
        fresh: made.has(memberKey(member)),
        node: (
          <Row
            mono
            leading={<Monogram text={alias} />}
            title={alias}
            open={
              host && !problem
                ? {
                    label: t('projects.openIn', { name: alias, section }),
                    onOpen: () => navigate({ page: 'hosts', hostId: host.id, back }),
                  }
                : undefined
            }
            subtitle={
              problem ? <Problem text={t('projects.hostGone')} /> : hostLine(host, alias, t)
            }
          >
            {problem && project ? (
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
        ),
      };
    }),
  };
}

/**
 * The hosts file's lines for the project's names: name → address, each
 * turned on or off. A switch changes the file the hosts file's way: the
 * change is shown, then written with the administrator password, with a
 * backup.
 */
function useHostsFileCard(
  { project, back }: Origin,
  names: string[],
  gone: Set<string>,
): CardSpec | null {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const file = useHostsFile();
  if (names.length === 0) return null;
  const info = file.data;
  const section = t('nav.hostsFile');
  const wanted = new Set(names);
  const lines = info ? hostsFileEntries(info.view.entries, names) : [];
  const rows: CardRow[] = [
    ...names
      .filter((name) => gone.has(name))
      .map(
        (name): CardRow => ({
          key: `gone:${name}`,
          problem: true,
          node: (
            <Row
              mono
              leading={
                <Network
                  aria-hidden="true"
                  className="size-4 shrink-0 text-subtle"
                  strokeWidth={1.9}
                />
              }
              title={name}
              subtitle={<Problem text={t('projects.hostsFileGone')} />}
            >
              {project ? (
                <RemoveButton project={project} member={{ type: 'hostsFile', name }} name={name} />
              ) : null}
            </Row>
          ),
        }),
      ),
    ...lines.map((entry): CardRow => {
      const title = entry.names.filter((name) => wanted.has(normalizeName(name))).join(' ');
      return {
        key: `line:${entry.line}`,
        node: (
          <Row
            mono
            leading={
              <Network
                aria-hidden="true"
                className="size-4 shrink-0 text-subtle"
                strokeWidth={1.9}
              />
            }
            title={entry.enabled ? title : <span className="text-muted">{title}</span>}
            open={{
              label: t('projects.openIn', { name: title, section }),
              onOpen: () => navigate({ page: 'hostsFile', line: entry.line, back }),
            }}
            // Off is said in words too, as in the Hosts file section.
            subtitle={[entry.enabled ? null : t('hostsFile.off'), `→ ${entry.address}`, entry.group]
              .filter(Boolean)
              .join(' · ')}
            detail={
              // A warning, as the Hosts file section shows it; the line keeps its place.
              entry.shadowed.some((name) => wanted.has(normalizeName(name))) ? (
                <Problem text={t('projects.hostsFileShadowed')} />
              ) : undefined
            }
          >
            {entry.system || !info || info.readOnly ? null : (
              <HostsFileSwitch
                entry={entry}
                revision={info.revision}
                // Several lines may list one name: the address tells them apart.
                name={`${title} → ${entry.address}`}
              />
            )}
          </Row>
        ),
      };
    }),
  ];
  return {
    id: 'hostsFile',
    icon: <Network className="size-3.5 text-[#A5B4FC]" strokeWidth={2.2} />,
    title: t('projects.cards.hostsFile'),
    count: names.length,
    action:
      project && info && !info.readOnly ? (
        <HostsFileAllSwitch
          project={project}
          file={info.view.entries}
          revision={info.revision}
          gone={[...gone]}
        />
      ) : undefined,
    rows,
  };
}

/**
 * One switch for all of the project's entries: on when all are, off when
 * none is, in the middle when some are. It turns them all on (or, when all
 * are on, off) through the hosts file's review: one diff, one password, one
 * backup, and Undo in the toast. What else it touches is said first.
 */
function HostsFileAllSwitch({
  project,
  file,
  revision,
  gone,
}: {
  project: Project;
  file: HostsFileEntry[];
  revision: string;
  gone: string[];
}) {
  const { t } = useTranslation();
  const countId = useId();
  const projects = useProjects().data ?? [];
  const [target, setTarget] = useState<boolean | null>(null);
  const now = planHostsFileSwitch(project, projects, file, true);
  if (now.entries.length === 0) return null;
  const on = now.entries.filter((entry) => entry.enabled).length;
  const state = on === 0 ? false : on === now.entries.length ? true : 'mixed';
  const plan = target === null ? null : planHostsFileSwitch(project, projects, file, target);
  const notes: ReviewNote[] = [];
  if (plan) {
    const count = plan.lines.length;
    notes.push({
      tone: 'info',
      text: target
        ? t('projects.hostsFileTurnOn', { count, name: project.name })
        : t('projects.hostsFileTurnOff', { count, name: project.name }),
    });
  }
  if (plan && plan.shared.length > 0) {
    notes.push({
      tone: 'warning',
      text: t('projects.hostsFileSharedNote', {
        list: plan.shared.map((s) => `${s.name} (${s.projects.join(', ')})`).join(', '),
      }),
    });
  }
  if (plan && plan.several.length > 0) {
    notes.push({
      tone: 'warning',
      text: t('projects.hostsFileSeveralNote', { names: plan.several.join(', ') }),
    });
  }
  if (plan && gone.length > 0) {
    notes.push({
      tone: 'info',
      text: t('projects.hostsFileMissingNote', { names: gone.join(', ') }),
    });
  }
  return (
    <span className="flex items-center gap-2">
      <span id={countId} className="text-[12px] text-subtle tabular-nums">
        {t('projects.hostsFileOnCount', { on, total: now.entries.length })}
      </span>
      <MixedSwitch
        checked={state}
        aria-label={t('projects.hostsFileAll')}
        aria-describedby={countId}
        // It shows the change for review first: screen readers say a dialog opens.
        aria-haspopup="dialog"
        onCheckedChange={() => setTarget(state !== true)}
      />
      <Dialog open={target !== null} onOpenChange={(open) => !open && setTarget(null)}>
        {plan ? (
          <ReviewDialog
            revision={revision}
            changes={plan.lines.map((entry) => ({
              kind: 'set',
              line: entry.line,
              entry: { ...editOf(entry), enabled: target === true },
            }))}
            conflict={false}
            notes={notes}
            undoable
            onApplied={() => setTarget(null)}
            onStale={() => {
              toast.error(t('hostsFile.stale'));
              setTarget(null);
            }}
            onDone={() => setTarget(null)}
          />
        ) : null}
      </Dialog>
    </span>
  );
}

/** Turns a hosts file line on or off through the hosts file's review. */
function HostsFileSwitch({
  entry,
  revision,
  name,
}: {
  entry: HostsFileEntry;
  revision: string;
  name: string;
}) {
  const { t } = useTranslation();
  const [reviewing, setReviewing] = useState(false);
  return (
    <>
      <Switch
        checked={entry.enabled}
        aria-label={t('hostsFile.toggle', { name })}
        // It shows the change for review first: screen readers say a dialog opens.
        aria-haspopup="dialog"
        onCheckedChange={() => setReviewing(true)}
      />
      <Dialog open={reviewing} onOpenChange={setReviewing}>
        {reviewing ? (
          <ReviewDialog
            revision={revision}
            changes={[
              {
                kind: 'set',
                line: entry.line,
                entry: { ...editOf(entry), enabled: !entry.enabled },
              },
            ]}
            conflict={false}
            undoable
            onApplied={() => setReviewing(false)}
            onStale={() => {
              // The line may be another one now: the card shows the file again.
              toast.error(t('hostsFile.stale'));
              setReviewing(false);
            }}
            onDone={() => setReviewing(false)}
          />
        ) : null}
      </Dialog>
    </>
  );
}

function useFoldersCard(
  project: Project | undefined,
  folders: string[],
  gone: Set<string>,
  locked: boolean,
  library: Library,
): CardSpec | null {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  const reveal = useMutation({
    mutationFn: ({ id, path }: { id: string; path: string }) => api.projectsRevealFolder(id, path),
    onError: (error) => toastError(t, error),
  });
  if (!project || folders.length === 0) return null;
  const hasLocal =
    !locked &&
    (library.envs ?? []).some(
      (env) =>
        !env.inTrash &&
        env.name.toLowerCase() === 'local' &&
        project.environments.includes(env.project),
    );
  return {
    id: 'folders',
    icon: <FolderOpen className="size-3.5 text-[#86EFAC]" strokeWidth={2.2} />,
    title: t('projects.cards.folders'),
    count: folders.length,
    rows: folders.map((path) => {
      const name = path.split(/[\\/]/).filter(Boolean).pop() ?? path;
      const problem = gone.has(path);
      return {
        key: path,
        problem,
        node: (
          <Row
            mono
            leading={
              <Folder
                aria-hidden="true"
                className="size-4 shrink-0 text-subtle"
                strokeWidth={1.9}
              />
            }
            title={path}
            subtitle={
              problem ? (
                <Problem text={t('projects.folderGone')} />
              ) : hasLocal ? (
                t('projects.withLocal')
              ) : undefined
            }
          >
            {problem ? (
              <RemoveButton project={project} member={{ type: 'folder', path }} name={path} />
            ) : (
              <>
                <IconButton
                  label={t('projects.showFolderIn', { name: path, app: fileManagerName })}
                  tooltip={t('keys.showIn', { app: fileManagerName })}
                  variant="ghost"
                  icon={<FolderOpen className="size-4" strokeWidth={1.9} />}
                  onClick={() => reveal.mutate({ id: project.id, path })}
                />
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
              </>
            )}
          </Row>
        ),
      };
    }),
  };
}

function useEnvironmentsCard(
  { project, back, made }: Origin,
  groups: string[],
  gone: Set<string>,
  library: Library,
): CardSpec | null {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  if (groups.length === 0) return null;
  const section = t('nav.envs');
  const rows = groups.flatMap((group): CardRow[] => {
    const member: ProjectMember = { type: 'environment', group };
    if (!library.envs) {
      return [{ key: group, node: <Row mono title={group} subtitle={t('common.loading')} /> }];
    }
    const envs = library.envs.filter((env) => !env.inTrash && env.project === group);
    if (gone.has(group) || envs.length === 0) {
      return [
        {
          key: group,
          problem: true,
          node: (
            <Row mono title={group} subtitle={<Problem text={t('projects.groupGone')} />}>
              {project ? <RemoveButton project={project} member={member} name={group} /> : null}
            </Row>
          ),
        },
      ];
    }
    return envs.map((env, index) => {
      const label = `${group} · ${env.name}`;
      const open = t('projects.openIn', { name: label, section });
      return {
        key: env.id,
        fresh: made.has(`envs:${env.id}`),
        node: (
          <Row
            leading={
              // The environment's name is its link to the Environments section.
              <button
                type="button"
                title={open}
                aria-label={open}
                onClick={() => navigate({ page: 'envs', envId: env.id, back })}
                className={cn(
                  'pressable inline-flex h-[22px] min-w-12 max-w-[140px] shrink-0 items-center justify-center rounded-full px-2 font-mono text-[11.5px] outline-none focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.6)]',
                  ['prod', 'production', 'live'].includes(env.name.toLowerCase())
                    ? 'bg-[rgb(225_29_72/0.18)] text-[#fecdd3] hover:bg-[rgb(225_29_72/0.28)]'
                    : 'bg-white/[0.06] text-fg-2 hover:bg-white/[0.12]',
                )}
              >
                <span className="truncate">{env.name}</span>
              </button>
            }
            title={groups.length > 1 && index === 0 ? group : ''}
            mono
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
              aria-label={t('projects.runIn', { name: label })}
              onClick={() => {
                terminals.openLocal({ env: { id: env.id, label } });
                navigate({ page: 'terminal' });
              }}
            >
              {t('projects.run')}
            </Button>
          </Row>
        ),
      };
    });
  });
  return {
    id: 'environments',
    icon: <Variable className="size-3.5 text-[#D9F99D]" strokeWidth={2.2} />,
    title: t('projects.cards.environments'),
    count: groups.length > 1 ? groups.length : groups[0],
    rows,
  };
}

function useLoginsCard(
  { project, back, made }: Origin,
  logins: string[],
  library: Library,
): CardSpec | null {
  const { t } = useTranslation();
  const { navigate } = useRouter();
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
  const byId = new Map((library.entries ?? []).map((entry) => [entry.id, entry]));
  const shown = logins.map((id) => byId.get(id)).filter((entry) => entry !== undefined);
  if (shown.length === 0) return null;
  const section = t('nav.passwords');
  return {
    id: 'logins',
    icon: <RectangleEllipsis className="size-3.5 text-[#F9A8D4]" strokeWidth={2.2} />,
    title: t('projects.cards.logins'),
    count: shown.length,
    rows: shown.map((entry) => {
      const site = entry.url.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
      return {
        key: entry.id,
        fresh: made.has(memberKey({ type: 'login', id: entry.id })),
        node: (
          <Row
            leading={<Monogram text={entry.title} />}
            title={entry.title}
            open={{
              label: t('projects.openIn', { name: entry.title, section }),
              onOpen: () => navigate({ page: 'passwords', entryId: entry.id, back }),
            }}
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
        ),
      };
    }),
  };
}

function useKeysCard(
  { project, back, made }: Origin,
  keys: string[],
  gone: Set<string>,
  library: Library,
): CardSpec | null {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  if (keys.length === 0) return null;
  const byFingerprint = new Map((library.keys ?? []).map((key) => [key.fingerprint, key]));
  const section = t('nav.keys');
  return {
    id: 'keys',
    icon: <KeyRound className="size-3.5 text-[#5EEAD4]" strokeWidth={2.2} />,
    title: t('projects.cards.keys'),
    count: keys.length,
    rows: keys.map((fingerprint) => {
      const key = byFingerprint.get(fingerprint);
      const member: ProjectMember = { type: 'key', fingerprint };
      const short = `${fingerprint.slice(0, 15)}…${fingerprint.slice(-4)}`;
      const problem = gone.has(fingerprint);
      return {
        key: fingerprint,
        problem,
        fresh: made.has(memberKey(member)),
        node: (
          <Row
            mono
            leading={
              <KeyRound
                aria-hidden="true"
                className="size-4 shrink-0 text-subtle"
                strokeWidth={1.9}
              />
            }
            title={key?.name ?? short}
            open={
              key && !problem
                ? {
                    label: t('projects.openIn', { name: key.name, section }),
                    onOpen: () => navigate({ page: 'keys', keyId: key.id, back }),
                  }
                : undefined
            }
            subtitle={
              problem ? (
                <Problem text={t('projects.keyGone')} />
              ) : (
                <span className="font-mono">{short}</span>
              )
            }
          >
            {problem && project ? (
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
        ),
      };
    }),
  };
}

function useTunnelsCard(hosts: string[]): CardSpec | null {
  const { t } = useTranslation();
  const tunnels = useQuery({ queryKey: ['tunnels'], queryFn: api.tunnelList });
  const toggle = useMutation({
    mutationFn: ({ id, on }: { id: string; on: boolean }) => api.tunnelSetOn(id, on),
    onSettled: () => void tunnels.refetch(),
    onError: (error) => toastVaultError(t, error),
  });
  const mine = (tunnels.data ?? []).filter((view) => hosts.includes(view.tunnel.alias));
  if (mine.length === 0) return null;
  return {
    id: 'tunnels',
    icon: <ArrowLeftRight className="size-3.5 text-[#67E8F9]" strokeWidth={2.2} />,
    title: t('projects.cards.tunnels'),
    count: mine.length,
    rows: mine.map(({ tunnel, state }) => {
      const route =
        tunnel.kind === 'dynamic'
          ? t('projects.tunnelSocks', { port: tunnel.listenPort })
          : `${tunnel.listenPort} → ${tunnel.targetHost ?? ''}:${tunnel.targetPort ?? ''}`;
      const on = state.state !== 'off' && state.state !== 'failed';
      const label = tunnel.name || route;
      return {
        key: tunnel.id,
        problem: state.state === 'failed',
        node: (
          <Row
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
        ),
      };
    }),
  };
}

function useFindingsCard(members: Members, library: Library): CardSpec | null {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const audit = useAudit();
  const vaultAudit = useVaultAudit();
  const ignored = new Set(useSettings().ignoredFindings);
  const keyNames = new Map((library.keys ?? []).map((k) => [k.id, k.name]));
  const hostNames = new Map((library.hosts ?? []).map((h) => [h.id, h.patterns.join(' ')]));
  const entryNames = new Map((library.entries ?? []).map((e) => [e.id, e.title]));
  const mine = projectFindings(
    members,
    library,
    { ssh: audit.data?.findings, vault: vaultAudit.data?.findings },
    ignored,
  );
  const found = bySeverity([
    ...mine.ssh.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: findingTitle(t, f),
      about:
        (f.subject.keyId !== null ? keyNames.get(f.subject.keyId) : undefined) ??
        (f.subject.hostId !== null ? hostNames.get(f.subject.hostId) : undefined),
    })),
    ...mine.vault.map((f) => ({
      id: f.id,
      severity: f.severity,
      title: vaultFindingTitle(t, f),
      about: entryNames.get(f.entryId),
    })),
  ]);
  if (found.length === 0) return null;
  return {
    id: 'findings',
    icon: <ShieldCheck className="size-3.5 text-[#FDA4AF]" strokeWidth={2.2} />,
    title: t('projects.cards.findings'),
    count: found.length,
    action: (
      <Button size="sm" variant="ghost" onClick={() => navigate({ page: 'audit' })}>
        {t('projects.openAudit')}
      </Button>
    ),
    rows: found.map((finding) => ({
      key: finding.id,
      node: (
        <Row
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
      ),
    })),
  };
}
