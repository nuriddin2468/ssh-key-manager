import { useMutation, useQueries } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import {
  Check,
  ChevronRight,
  FolderOpen,
  KeyRound,
  LockKeyhole,
  Plus,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  SquareTerminal,
} from 'lucide-react';
import { Fragment, type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import {
  useAudit,
  useConfig,
  useHostsFile,
  useKeys,
  useVaultEntries,
  useVaultStatus,
} from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { Project } from '@/bindings/Project';
import type { Severity } from '@/bindings/Severity';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { findingTitle } from '@/features/audit/model';
import { useOpenFindingCounts, useVaultAudit } from '@/features/audit/queries';
import { vaultFindingTitle } from '@/features/audit/vaultModel';
import { projectFilesNeedingAttention } from '@/features/envs/files/model';
import { useFileRisks, useFileStatuses } from '@/features/envs/files/queries';
import { useEnvs } from '@/features/envs/queries';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { cn } from '@/lib/cn';
import { fileManagerName } from '@/lib/platform';
import { useSettings } from '@/lib/settings';
import { SEVERITY_DOT } from './cards';
import {
  type Library,
  type Members,
  type Missing,
  memberSummary,
  missing,
  type ProjectProblem,
  personal,
  projectFindings,
  projectProblems,
  quickActions,
} from './model';
import { ProjectDialog } from './ProjectDialog';
import { PersonalTile, ProjectTile } from './ProjectTile';
import { usePlaces } from './places';
import { projectKeys, useProjects, useSuggestions } from './queries';
import { TerminalButton } from './TerminalButton';

/** How many problems a card lists before "+2 more". */
const PROBLEM_LIMIT = 3;

const NOTHING_GONE: Missing = {
  hosts: new Set(),
  keys: new Set(),
  environments: new Set(),
  folders: new Set(),
  hostsFile: new Set(),
};

/**
 * Where the app opens: every project at a glance, Personal first, each
 * with what it holds, what is wrong with it and a thing or two to do at
 * once. Audit's numbers, an Unlock prompt and suggestions sit above.
 */
export function AllProjectsPage() {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const vaultState = useVaultStatus().data?.state;
  const locked = vaultState === 'locked';
  const projects = useProjects();
  const config = useConfig();
  const keys = useKeys();
  const envs = useEnvs();
  const entries = useVaultEntries();
  const hostsFile = useHostsFile();
  // What was found already: looking reads code folders, and waits for the
  // Suggestions page (or a click on "Look for projects").
  const suggestions = useSuggestions({ look: false }).data;
  const [creating, setCreating] = useState(false);

  const library: Library = {
    hosts: config.data?.view.hosts,
    includes: (config.data?.view.includes.length ?? 0) > 0,
    keys: keys.data?.keys,
    envs: vaultState === 'unlocked' ? envs.data : undefined,
    entries: vaultState === 'unlocked' ? entries.data : undefined,
    hostsFile: hostsFile.data?.view.entries,
  };
  const list = projects.data ?? [];
  const mine = personal(list, library);
  const personalSize =
    mine.hosts.length + mine.keys.length + mine.environments.length + mine.logins.length;
  // No projects: only known with the vault open, or without one. Locked, a
  // device may have no copy of them yet (the vault came by sync or import).
  const firstRun =
    list.length === 0 &&
    ((projects.data !== undefined && vaultState === 'unlocked') || vaultState === 'missing');
  const unknown = locked && projects.data !== undefined && list.length === 0;
  const noKeys = keys.data !== undefined && keys.data.keys.length === 0;

  // A project's folders missing on this computer: the project page asks the same.
  const withFolders = list.filter((project) => project.folders.length > 0);
  // Checked now and then, not on every focus: a hung mount stalls the check.
  const goneFolders = useQueries({
    queries: withFolders.map((project) => ({
      queryKey: [...projectKeys.all, 'missing', project.id],
      queryFn: () => api.projectsMissingFolders(project.id),
      staleTime: 5 * 60_000,
      refetchOnWindowFocus: false,
    })),
  });
  const goneFor = (project: Project): string[] | undefined => {
    if (project.folders.length === 0) return [];
    return goneFolders[withFolders.indexOf(project)]?.data;
  };

  const newProject = () => {
    if (locked) {
      dialogs.unlockVault({
        description: t('projects.unlockToChange'),
        onUnlocked: () => setCreating(true),
      });
    } else setCreating(true);
  };

  return (
    <>
      <Toolbar
        title={t('nav.projects')}
        meta={list.length > 0 ? t('projects.home.count', { count: list.length }) : undefined}
      >
        {/* On the first run the intro has it. */}
        {projects.data && !firstRun && (vaultState === 'unlocked' || vaultState === 'locked') ? (
          <Button
            size="sm"
            icon={<Plus className="size-4" strokeWidth={2.2} />}
            onClick={newProject}
          >
            {t('projects.newProject')}
          </Button>
        ) : null}
      </Toolbar>
      <PageBody className="gap-3">
        {firstRun ? (
          <Intro
            missingVault={vaultState === 'missing'}
            noKeys={noKeys}
            onNewProject={newProject}
          />
        ) : null}
        {firstRun ? null : <HealthStrip />}
        {locked ? (
          <Banner
            icon={<LockKeyhole className="size-4" strokeWidth={2} />}
            text={unknown ? t('projects.home.lockedUnknown') : t('projects.home.locked')}
            action={
              <Button size="sm" variant="primary" onClick={() => dialogs.unlockVault()}>
                {t('projects.unlock')}
              </Button>
            }
          />
        ) : null}
        {vaultState === 'unlocked' && suggestions && suggestions.length > 0 ? (
          <Banner
            tone="ok"
            icon={<Sparkles className="size-4" strokeWidth={2} />}
            title={t('projects.home.suggestTitle', { count: suggestions.length })}
            text={t('projects.suggest.intro')}
            action={
              <Button
                size="sm"
                variant="soft"
                aria-label={t('projects.home.reviewSuggestions', { count: suggestions.length })}
                onClick={() => navigate({ page: 'suggestions' })}
              >
                {t('projects.home.review')}
              </Button>
            }
          />
        ) : firstRun && vaultState === 'unlocked' && suggestions === undefined ? (
          // Nobody looked yet: the Suggestions page looks, when asked.
          <Banner
            tone="ok"
            icon={<Sparkles className="size-4" strokeWidth={2} />}
            title={t('projects.home.lookTitle')}
            text={t('projects.home.lookText')}
            action={
              <Button size="sm" variant="soft" onClick={() => navigate({ page: 'suggestions' })}>
                {t('projects.home.look')}
              </Button>
            }
          />
        ) : null}
        {/* Locked without a copy of the projects: nothing to show but Unlock. */}
        {unknown ? null : (
          <ul className="grid grid-cols-[repeat(auto-fill,minmax(340px,1fr))] items-stretch gap-3">
            {personalSize > 0 || !firstRun ? (
              <ProjectCard
                members={mine}
                library={library}
                gone={NOTHING_GONE}
                goneFolders={[]}
                locked={locked}
                loading={!config.data || !keys.data}
              />
            ) : null}
            {list.map((project) => {
              const folders = goneFor(project);
              return (
                <ProjectCard
                  key={project.id}
                  project={project}
                  members={project}
                  library={library}
                  gone={missing(project, library, folders)}
                  goneFolders={folders}
                  locked={locked}
                />
              );
            })}
          </ul>
        )}
      </PageBody>
      <Dialog open={creating} onOpenChange={setCreating}>
        {creating ? (
          <ProjectDialog
            project={null}
            all={list}
            onDone={(saved) => {
              setCreating(false);
              if (saved) navigate({ page: 'project', id: saved.id });
            }}
          />
        ) : null}
      </Dialog>
    </>
  );
}

/** The first run, before any project: what projects are, and how to start. */
function Intro({
  missingVault,
  noKeys,
  onNewProject,
}: {
  missingVault: boolean;
  noKeys: boolean;
  onNewProject: () => void;
}) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  return (
    <section
      aria-labelledby="projects-intro"
      className="glass flex flex-col gap-2.5 rounded-2xl bg-[radial-gradient(500px_200px_at_0%_0%,rgb(45_212_191/0.10),transparent_70%)] p-[18px]"
    >
      <h2 id="projects-intro" className="text-[17px] font-semibold tracking-[-0.015em]">
        {t('projects.home.introTitle')}
      </h2>
      <p className="max-w-[620px] text-[13px] text-muted">{t('projects.home.introText')}</p>
      {missingVault ? (
        <p className="max-w-[620px] text-[13px] text-muted">{t('projects.noVault')}</p>
      ) : null}
      <div className="mt-1 flex flex-wrap gap-2">
        {noKeys ? (
          <Button
            variant="primary"
            icon={<KeyRound className="size-4" strokeWidth={2} />}
            onClick={() => dialogs.generateKey()}
          >
            {t('projects.generateKey')}
          </Button>
        ) : null}
        {missingVault ? (
          <Button
            variant={noKeys ? 'secondary' : 'primary'}
            onClick={() => navigate({ page: 'passwords' })}
          >
            {t('projects.createVault')}
          </Button>
        ) : (
          <Button
            variant={noKeys ? 'secondary' : 'primary'}
            icon={<Plus className="size-4" strokeWidth={2.2} />}
            onClick={onNewProject}
          >
            {t('projects.newProject')}
          </Button>
        )}
      </div>
    </section>
  );
}

const SEVERITIES: Severity[] = ['critical', 'warning', 'info'];
const LEGEND = {
  critical: 'audit.legendCritical',
  warning: 'audit.legendWarning',
  info: 'audit.legendInfo',
} as const;

/** Audit's numbers in one line, linking to it; a quiet line when there are none. */
function HealthStrip() {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const counts = useOpenFindingCounts();
  if (!counts) return null;
  const total = counts.critical + counts.warning + counts.info;
  if (total === 0) {
    return (
      <p className="flex items-center gap-2 px-1 text-[12.5px] text-subtle">
        <ShieldCheck aria-hidden="true" className="size-4 text-ok" strokeWidth={2} />
        {t('projects.home.noIssues')}
        <span aria-hidden="true">·</span>
        <button
          type="button"
          aria-label={t('projects.openAudit')}
          onClick={() => navigate({ page: 'audit' })}
          className="rounded text-fg-2 decoration-white/40 underline-offset-[3px] outline-none hover:underline focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.6)]"
        >
          {t('nav.audit')}
        </button>
      </p>
    );
  }
  return (
    <section
      aria-label={t('nav.audit')}
      className="glass flex flex-wrap items-center gap-x-4 gap-y-1.5 rounded-xl py-1.5 pr-1.5 pl-3 text-[12.5px] text-fg-2"
    >
      <ShieldAlert
        aria-hidden="true"
        className={cn(
          'size-4',
          counts.critical > 0 ? 'text-critical' : counts.warning > 0 ? 'text-warning' : 'text-info',
        )}
        strokeWidth={2}
      />
      {SEVERITIES.filter((severity) => counts[severity] > 0).map((severity) => (
        <span
          key={severity}
          className={cn('inline-flex items-center gap-1.5', severity === 'info' && 'text-subtle')}
        >
          <span aria-hidden="true" className={cn('size-2 rounded-full', SEVERITY_DOT[severity])} />
          {t(LEGEND[severity], { count: counts[severity] })}
        </span>
      ))}
      <span className="flex-1" />
      <Button size="sm" variant="ghost" onClick={() => navigate({ page: 'audit' })}>
        {t('projects.home.reviewAudit')}
      </Button>
    </section>
  );
}

/** A line above the cards: the vault is locked, or suggestions wait. */
function Banner({
  icon,
  title,
  text,
  action,
  tone,
}: {
  icon: ReactNode;
  title?: string;
  text: string;
  action: ReactNode;
  tone?: 'ok';
}) {
  return (
    <div
      className={cn(
        'flex flex-wrap items-center gap-3 rounded-xl px-3 py-2.5 text-[13px] text-fg-2',
        tone === 'ok' ? 'border border-[rgb(94_234_212/0.22)] bg-[rgb(94_234_212/0.08)]' : 'glass',
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          'grid size-7 shrink-0 place-items-center rounded-lg',
          tone === 'ok' ? 'bg-[rgb(94_234_212/0.14)] text-ok' : 'bg-white/[0.06] text-muted',
        )}
      >
        {icon}
      </span>
      <div className="min-w-[200px] flex-1">
        {title ? <p className="font-semibold text-ok">{title}</p> : null}
        <p className={cn(title && 'text-[12.5px] text-muted')}>{text}</p>
      </div>
      {action}
    </div>
  );
}

/** A problem's words: what is wrong, and what with. */
function problemText(
  t: TFunction,
  problem: ProjectProblem,
  library: Library,
): { title: string; about?: string; mono?: boolean } {
  if (problem.source === 'ssh') {
    const { keyId, hostId } = problem.finding.subject;
    const key = keyId !== null ? library.keys?.find((k) => k.id === keyId) : undefined;
    const host = hostId !== null ? library.hosts?.find((h) => h.id === hostId) : undefined;
    return {
      title: findingTitle(t, problem.finding),
      about: key?.name ?? host?.patterns.join(' '),
      mono: !key && Boolean(host),
    };
  }
  if (problem.source === 'vault') {
    return {
      title: vaultFindingTitle(t, problem.finding),
      about: library.entries?.find((e) => e.id === problem.finding.entryId)?.title,
    };
  }
  if (problem.source === 'files') {
    const [only] = problem.files;
    return {
      title: t('projects.home.envFiles', { count: problem.files.length }),
      // One file: which; several: the project's page tells them apart.
      about: problem.files.length === 1 ? only?.file.path : undefined,
      mono: true,
    };
  }
  const { member } = problem;
  switch (member.type) {
    case 'host':
      return { title: t('projects.hostGone'), about: member.alias, mono: true };
    case 'folder':
      return { title: t('projects.folderGone'), about: member.path, mono: true };
    case 'environment':
      return { title: t('projects.groupGone'), about: member.id.slice(0, 8) };
    case 'key':
      return {
        title: t('projects.keyGone'),
        about: shortFingerprint(member.fingerprint),
        mono: true,
      };
    case 'hostsFile':
      return { title: t('projects.hostsFileGone'), about: member.name, mono: true };
    case 'login':
      return { title: '' };
  }
}

/** `SHA256:4f9Kx…`: enough of a fingerprint to tell keys apart. */
function shortFingerprint(fingerprint: string): string {
  return fingerprint.length > 15 ? `${fingerprint.slice(0, 14)}…` : fingerprint;
}

/**
 * A project's card (Personal without `project`): its tile and name, what it
 * holds, its problems and its quick actions. The name opens the project, and
 * so does a click anywhere on the card that isn't a button.
 */
function ProjectCard({
  project,
  members,
  library,
  gone,
  goneFolders,
  locked,
  loading,
}: {
  project?: Project;
  members: Members;
  library: Library;
  gone: Missing;
  /** `undefined` until known. */
  goneFolders: string[] | undefined;
  locked: boolean;
  /** Personal's library is still loading: nothing to count yet. */
  loading?: boolean;
}) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  const audit = useAudit();
  const vaultAudit = useVaultAudit();
  const ignored = new Set(useSettings().ignoredFindings);
  const reveal = useMutation({
    mutationFn: ({ id, path }: { id: string; path: string }) =>
      api.projectsRevealFolder(id, { folder: path, path: '' }),
    onError: (error) => toastError(t, error),
  });

  const fileStatuses = useFileStatuses();
  const fileRisks = useFileRisks();

  const name = project ? project.name : t('projects.personal');
  const counts = memberSummary(t, members, locked);
  const problems = projectProblems(
    projectFindings(
      members,
      library,
      { ssh: audit.data?.findings, vault: vaultAudit.data?.findings },
      ignored,
    ),
    gone,
    // Files are written only to a project's folders: Personal has none.
    project && !locked
      ? projectFilesNeedingAttention(project.id, fileStatuses.data, fileRisks.data)
      : [],
  );
  const quick = quickActions(members, gone, goneFolders, library.hosts);
  // An environment in the terminal's menu: `part · stage` where parts show.
  const labelOf = (id: string) => {
    const env = library.envs?.find((item) => item.id === id);
    if (!env) return id;
    const parts = new Set(
      (library.envs ?? [])
        .filter((item) => item.project === env.project && !item.inTrash)
        .map((item) => item.part.toLowerCase()),
    );
    return [parts.size > 1 ? env.part : '', env.name].filter(Boolean).join(' · ');
  };
  // The files' reports, once in (or not asked for, the vault locked); if
  // they couldn't be had, the files are unknown, as a check still running.
  const filesKnown = fileRisks.data !== undefined || (!fileRisks.isLoading && !fileRisks.isError);
  // "No problems" only once everything was checked: the audits, the
  // folders on this computer, ~/.ssh/config, the keys, the hosts file and,
  // with the vault open, the .env files.
  const checked =
    audit.data !== undefined &&
    filesKnown &&
    vaultAudit.data !== undefined &&
    goneFolders !== undefined &&
    library.hosts !== undefined &&
    library.keys !== undefined &&
    (members.hostsFile.length === 0 || library.hostsFile !== undefined);
  const shown = problems.slice(0, PROBLEM_LIMIT);
  const open = () => navigate(project ? { page: 'project', id: project.id } : { page: 'personal' });

  return (
    <li className="glass relative flex min-w-0 flex-col gap-2.5 rounded-2xl p-3.5 transition-colors hover:bg-white/[0.05]">
      <div className="flex items-center gap-2.5">
        {project ? <ProjectTile project={project} size={32} /> : <PersonalTile size={32} />}
        <div className="min-w-0 flex-1">
          <h2 className="text-[14px] font-semibold tracking-[-0.01em]">
            <button
              type="button"
              aria-label={t('projects.home.open', { name })}
              onClick={open}
              className="block max-w-full truncate rounded text-left outline-none after:absolute after:inset-0 after:rounded-2xl after:content-[''] focus-visible:after:ring-2 focus-visible:after:ring-[rgb(var(--accent-rgb)/0.6)]"
            >
              {name}
            </button>
          </h2>
          <p className="text-[11.5px] text-subtle">
            {counts
              ? counts.split(' · ').map((part, index, parts) => (
                  // Each count stays on one line ("1 key", not "1" and "key"),
                  // and a line breaks after a dot.
                  <Fragment key={part}>
                    <span className="whitespace-nowrap">
                      {part}
                      {index < parts.length - 1 ? ' ·' : null}
                    </span>{' '}
                  </Fragment>
                ))
              : // Locked, its logins and environments don't show: say nothing.
                loading || locked
                ? '\u00a0'
                : project
                  ? t('projects.home.empty')
                  : t('projects.personalEmptyTitle')}
          </p>
        </div>
        <ChevronRight aria-hidden="true" className="size-4 shrink-0 text-faint" strokeWidth={2} />
      </div>
      {counts === '' ? null : !checked ? (
        <p aria-hidden="true" className="min-h-6" />
      ) : shown.length > 0 ? (
        <ul className="flex flex-col gap-0.5">
          {shown.map((problem) => {
            const text = problemText(t, problem, library);
            return (
              <li
                key={problem.key}
                className="flex min-h-6 items-center gap-2 text-[12.5px] text-fg-2"
              >
                <span
                  aria-hidden="true"
                  className={cn('size-2 shrink-0 rounded-full', SEVERITY_DOT[problem.severity])}
                />
                <span className="sr-only">{t(`projects.severity.${problem.severity}`)}: </span>
                {/* Critical ones stand out by weight too, not by color alone. */}
                <span
                  className={cn(
                    'min-w-0 truncate',
                    problem.severity === 'critical' && 'font-medium text-fg',
                  )}
                >
                  {text.title}
                </span>
                {text.about ? (
                  <span
                    className={cn(
                      'ml-auto max-w-[45%] shrink-0 truncate pl-2 text-[11.5px] text-subtle',
                      text.mono && 'font-mono',
                    )}
                  >
                    <span className="sr-only">, </span>
                    {text.about}
                  </span>
                ) : null}
              </li>
            );
          })}
          {problems.length > shown.length ? (
            <li className="pl-4 text-[12px] text-subtle">
              {t('projects.home.moreProblems', { count: problems.length - shown.length })}
            </li>
          ) : null}
        </ul>
      ) : (
        <p className="flex min-h-6 items-center gap-2 text-[12.5px] text-ok">
          <Check aria-hidden="true" className="size-3.5" strokeWidth={2.6} />
          {t('projects.home.noProblems')}
        </p>
      )}
      {quick.folder || quick.host ? (
        // Only the buttons sit above the card's link: the rest of the row opens it.
        <div className="mt-auto flex flex-wrap items-center gap-1.5 border-t border-white/[0.045] pt-2.5">
          {project && quick.folder ? (
            <FolderActions
              project={project}
              path={quick.folder}
              labelOf={labelOf}
              onReveal={() => reveal.mutate({ id: project.id, path: quick.folder ?? '' })}
            />
          ) : null}
          {quick.host ? (
            <Button
              size="sm"
              className="relative z-10 min-w-0"
              icon={<SquareTerminal className="size-3.5" strokeWidth={2} />}
              onClick={() => {
                terminals.open(quick.host ?? '');
                navigate({ page: 'terminal' });
              }}
            >
              <span className="truncate">{t('projects.connectTo', { name: quick.host })}</span>
            </Button>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

/**
 * "Open terminal" in a project's folder (asking which environment where
 * several parts work), and "Show in Finder" next to it.
 */
function FolderActions({
  project,
  path,
  labelOf,
  onReveal,
}: {
  project: Project;
  path: string;
  labelOf: (id: string) => string;
  onReveal: () => void;
}) {
  const { t } = useTranslation();
  const place = usePlaces(project.id).data?.find(
    (item) => item.folder === path && item.path === '',
  );
  return (
    <>
      <TerminalButton project={project} place={place} labelOf={labelOf} className="relative z-10" />
      <IconButton
        label={t('projects.showFolderIn', { name: path, app: fileManagerName })}
        tooltip={t('keys.showIn', { app: fileManagerName })}
        variant="ghost"
        className="relative z-10"
        icon={<FolderOpen className="size-4" strokeWidth={1.9} />}
        onClick={onReveal}
      />
    </>
  );
}
