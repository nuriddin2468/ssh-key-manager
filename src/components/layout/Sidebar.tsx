import {
  ChevronDown,
  Cpu,
  Globe,
  KeyRound,
  LockKeyhole,
  type LucideIcon,
  Network,
  Plus,
  Radar,
  RectangleEllipsis,
  Server,
  Settings as SettingsIcon,
  ShieldCheck,
  Sparkles,
  SquareTerminal,
  Variable,
  Wrench,
} from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  useAgent,
  useAudit,
  useConfig,
  useEnvironment,
  useHostsFile,
  useKeys,
  useKnownHosts,
  useVaultEntries,
  useVaultStatus,
} from '@/api/queries';
import { type Page, type Route, useRouter } from '@/app/router';
import type { Project } from '@/bindings/Project';
import { Logo } from '@/components/Logo';
import { Dialog } from '@/components/ui/Dialog';
import { Tile, type Tone } from '@/components/ui/Tile';
import { useEnvs } from '@/features/envs/queries';
import { personal } from '@/features/projects/model';
import { ProjectDialog } from '@/features/projects/ProjectDialog';
import { PersonalTile, ProjectTile } from '@/features/projects/ProjectTile';
import { useProjects, useSuggestions } from '@/features/projects/queries';
import { useSessionCounts } from '@/features/terminal/TerminalProvider';
import { TOOLS } from '@/features/tools/registry';
import { cn } from '@/lib/cn';
import { platform } from '@/lib/platform';
import { updateSettings, useSettings } from '@/lib/settings';
import { useUpdateState } from '@/lib/updater';

const PLATFORM_NAMES = { macos: 'macOS', windows: 'Windows', linux: 'Linux' } as const;

/** The sidebar's `px-2.5 pb-2.5` padding, which the toasts line up with (see App.tsx). */
export const SIDEBAR_INSET = 10;

export function Sidebar() {
  const { t } = useTranslation();
  const { route, navigate } = useRouter();
  const environment = useEnvironment();
  const keys = useKeys();
  const config = useConfig();
  const agent = useAgent();
  const known = useKnownHosts();
  const hostsFile = useHostsFile();
  const audit = useAudit();
  const vault = useVaultStatus();
  const vaultEntries = useVaultEntries();
  const envs = useEnvs();
  const sessions = useSessionCounts();

  const ignored = useSettings().ignoredFindings;
  // Critical findings and warnings the user hasn't set aside on the audit page.
  const findings = (audit.data?.findings ?? []).filter(
    (finding) => finding.severity !== 'info' && !ignored.includes(finding.id),
  ).length;
  const unlocked = agent.data?.identities.length ?? 0;
  const running = agent.data?.status.available ?? false;
  const update = useUpdateState();
  const updateReady = update.status === 'available' || update.status === 'downloading';
  const vaultState = vault.data?.state;
  const savedPasswords =
    vaultState === 'unlocked' ? vaultEntries.data?.filter((e) => !e.inTrash).length : undefined;

  const item = (page: Page, label: string, tone: Tone, Icon: LucideIcon, count?: number) => (
    <NavItem
      key={page}
      label={label}
      tone={tone}
      icon={Icon}
      active={route.page === page}
      count={count}
      onClick={() => navigate({ page } as Route)}
    />
  );

  const projects = useProjects().data ?? [];
  const suggestions = useSuggestions().data ?? [];
  const settings = useSettings();
  const [creating, setCreating] = useState(false);
  const mine = personal(projects, {
    hosts: config.data?.view.hosts,
    keys: keys.data?.keys,
    envs: vaultState === 'unlocked' ? envs.data : undefined,
    entries: vaultState === 'unlocked' ? vaultEntries.data : undefined,
  });
  const personalCount =
    mine.hosts.length + mine.keys.length + mine.environments.length + mine.logins.length;
  const sizeOf = (project: Project) =>
    project.hosts.length +
    project.keys.length +
    project.environments.length +
    project.folders.length +
    project.logins.length;
  const folded = (group: string, pages: Page[]) =>
    settings.foldedNav.includes(group) && !pages.includes(route.page);
  const fold = (group: string) =>
    updateSettings({
      foldedNav: settings.foldedNav.includes(group)
        ? settings.foldedNav.filter((g) => g !== group)
        : [...settings.foldedNav, group],
    });
  const LIBRARY: Page[] = ['keys', 'hosts', 'passwords', 'envs', 'known'];
  const SYSTEM: Page[] = ['terminal', 'agent', 'hostsFile', 'nearby', 'audit'];
  const lockIcon =
    vaultState === 'locked' ? (
      <LockKeyhole
        role="img"
        aria-label={t('nav.vaultLocked')}
        className="ml-auto size-3.5 text-subtle"
        strokeWidth={2}
      />
    ) : undefined;

  return (
    <aside className="relative flex w-[232px] shrink-0 flex-col border-r border-white/[0.06] bg-[radial-gradient(260px_220px_at_0%_0%,rgb(20_184_166/0.16),transparent_70%),radial-gradient(320px_280px_at_100%_100%,rgb(124_58_237/0.14),transparent_70%),rgb(17_20_30/0.97)] px-2.5 pb-2.5 shadow-[inset_-1px_0_0_rgb(0_0_0/0.4)]">
      <div
        data-tauri-drag-region
        className={platform === 'macos' ? 'h-[52px] shrink-0' : 'h-3.5 shrink-0'}
      />

      <div data-tauri-drag-region className="flex items-center gap-3 px-2 pt-1 pb-[18px]">
        <Logo size={40} />
        <div data-tauri-drag-region className="flex min-w-0 flex-col">
          <span className="text-[14px] leading-[18px] font-bold tracking-[-0.015em]">
            {t('app.name')}
          </span>
          <span className="font-mono text-[11px] leading-4 text-subtle">
            ~/.ssh · {PLATFORM_NAMES[environment.data?.platform ?? platform]}
          </span>
        </div>
      </div>

      <nav
        aria-label={t('nav.sections')}
        className="-mx-1 flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto px-1"
      >
        <NavGroup
          label={t('nav.groupProjects')}
          action={
            vaultState === 'unlocked' ? (
              <button
                type="button"
                aria-label={t('projects.newProject')}
                title={t('projects.newProject')}
                onClick={() => setCreating(true)}
                className="pressable grid size-5 place-items-center rounded-md bg-white/[0.05] text-muted outline-none hover:bg-white/10 hover:text-fg focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.6)]"
              >
                <Plus className="size-3" strokeWidth={2.4} />
              </button>
            ) : undefined
          }
        >
          <NavItem
            label={t('projects.personal')}
            tile={<PersonalTile />}
            active={route.page === 'personal'}
            count={personalCount || undefined}
            onClick={() => navigate({ page: 'personal' })}
          />
          <div
            className={cn(
              'flex flex-col gap-px',
              projects.length > 8 && 'max-h-[272px] overflow-y-auto',
            )}
          >
            {projects.map((project) => (
              <NavItem
                key={project.id}
                label={project.name}
                tile={<ProjectTile project={project} />}
                active={route.page === 'project' && route.id === project.id}
                count={sizeOf(project) || undefined}
                onClick={() => navigate({ page: 'project', id: project.id })}
              />
            ))}
          </div>
          {vaultState === 'unlocked' && suggestions.length > 0 ? (
            <NavItem
              label={t('nav.suggested', { count: suggestions.length })}
              tile={
                <span
                  aria-hidden="true"
                  className="grid size-[22px] shrink-0 place-items-center rounded-[6px] text-ok shadow-[inset_0_0_0_1px_rgb(94_234_212/0.35)]"
                >
                  <Sparkles className="size-[13px]" strokeWidth={2.2} />
                </span>
              }
              className="text-ok"
              active={route.page === 'suggestions'}
              onClick={() => navigate({ page: 'suggestions' })}
            />
          ) : null}
        </NavGroup>
        <NavGroup
          label={t('nav.groupLibrary')}
          folded={folded('library', LIBRARY)}
          onFold={() => fold('library')}
        >
          {item('keys', t('nav.keys'), 'teal', KeyRound, keys.data?.keys.length)}
          {item('hosts', t('nav.hosts'), 'blue', Server, config.data?.view.hosts.length)}
          <NavItem
            label={t('nav.passwords')}
            tone="pink"
            icon={RectangleEllipsis}
            active={route.page === 'passwords'}
            count={savedPasswords}
            trailing={lockIcon}
            onClick={() => navigate({ page: 'passwords' })}
          />
          <NavItem
            label={t('nav.envs')}
            tone="lime"
            icon={Variable}
            active={route.page === 'envs'}
            count={
              vaultState === 'unlocked'
                ? envs.data?.filter((env) => !env.inTrash).length
                : undefined
            }
            trailing={lockIcon}
            onClick={() => navigate({ page: 'envs' })}
          />
          {item('known', t('nav.known'), 'amber', Globe, known.data?.view.entries.length)}
        </NavGroup>
        <NavGroup
          label={t('nav.groupSystem')}
          folded={folded('system', SYSTEM)}
          onFold={() => fold('system')}
        >
          <NavItem
            label={t('nav.terminal')}
            tone="green"
            icon={SquareTerminal}
            active={route.page === 'terminal'}
            trailing={
              sessions.tabs > 0 ? (
                <span className="ml-auto inline-flex items-center gap-[5px] text-[12px] text-subtle tabular-nums">
                  {sessions.connected > 0 ? (
                    <span aria-hidden="true" className="size-1.5 rounded-full bg-online" />
                  ) : null}
                  <span aria-hidden="true">{sessions.tabs}</span>
                  <span className="sr-only">
                    {t('nav.sessions', { count: sessions.tabs, connected: sessions.connected })}
                  </span>
                </span>
              ) : undefined
            }
            onClick={() => navigate({ page: 'terminal' })}
          />
          {item('agent', t('nav.agent'), 'violet', Cpu, running ? unlocked : undefined)}
          {item(
            'hostsFile',
            t('nav.hostsFile'),
            'indigo',
            Network,
            hostsFile.data?.view.entries.filter((entry) => entry.enabled).length,
          )}
          {item('nearby', t('nav.nearby'), 'orange', Radar)}
          <NavItem
            label={t('nav.audit')}
            tone="rose"
            icon={ShieldCheck}
            active={route.page === 'audit'}
            badge={findings > 0 ? findings : undefined}
            badgeLabel={t('nav.findings', { count: findings })}
            onClick={() => navigate({ page: 'audit' })}
          />
        </NavGroup>
      </nav>
      <div className="-mx-1 mt-2 flex shrink-0 flex-col gap-px border-t border-white/[0.06] px-1 pt-2">
        {/* Shown once there is a tool (src/features/tools). */}
        {TOOLS.length > 0 ? item('tools', t('nav.tools'), 'cyan', Wrench) : null}
        <NavItem
          label={t('nav.settings')}
          tone="slate"
          icon={SettingsIcon}
          active={route.page === 'settings'}
          trailing={
            updateReady ? (
              <span
                role="img"
                aria-label={t('updates.available', { version: update.version })}
                className="ml-auto size-[7px] rounded-full bg-teal-300 shadow-[0_0_8px_rgb(94_234_212/0.9)]"
              />
            ) : undefined
          }
          onClick={() => navigate({ page: 'settings' })}
        />
      </div>
      <Dialog open={creating} onOpenChange={setCreating}>
        {creating ? (
          <ProjectDialog
            project={null}
            all={projects}
            onDone={(saved) => {
              setCreating(false);
              if (saved) navigate({ page: 'project', id: saved.id });
            }}
          />
        ) : null}
      </Dialog>
    </aside>
  );
}

function NavGroup({
  label,
  action,
  folded,
  onFold,
  children,
}: {
  label: string;
  /** A small button at the end of the heading, e.g. "New project". */
  action?: ReactNode;
  /** With `onFold`, the heading folds the group: a button with its state. */
  folded?: boolean;
  onFold?: () => void;
  children: ReactNode;
}) {
  const listId = useId();
  return (
    <div className="flex flex-col gap-px">
      <div className="flex items-center justify-between pr-1 pb-[5px] pl-2">
        {onFold ? (
          <button
            type="button"
            aria-expanded={!folded}
            aria-controls={listId}
            onClick={onFold}
            className="-ml-1 flex items-center gap-1 rounded-md px-1 text-[11px] font-semibold text-[#7C869A] outline-none hover:text-fg-2 focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.6)]"
          >
            {label}
            <ChevronDown
              aria-hidden="true"
              className={cn('size-3 transition-transform', folded && '-rotate-90')}
              strokeWidth={2.4}
            />
          </button>
        ) : (
          <span className="text-[11px] font-semibold text-[#7C869A]">{label}</span>
        )}
        {action}
      </div>
      <div id={listId} hidden={folded} className="flex flex-col gap-px">
        {children}
      </div>
    </div>
  );
}

interface NavItemProps {
  label: string;
  tone?: Tone;
  icon?: LucideIcon;
  /** Shown instead of the tone and icon, e.g. a project's tile. */
  tile?: ReactNode;
  className?: string;
  active: boolean;
  count?: number;
  badge?: number;
  badgeLabel?: string;
  /** Shown at the end instead of a count, e.g. a status icon. */
  trailing?: React.ReactNode;
  onClick: () => void;
}

function NavItem({
  label,
  tone = 'slate',
  icon: Icon,
  tile,
  className,
  active,
  count,
  badge,
  badgeLabel,
  trailing,
  onClick,
}: NavItemProps) {
  return (
    <button
      type="button"
      aria-current={active ? 'page' : undefined}
      onClick={onClick}
      className={cn(
        'pressable-soft flex h-8 shrink-0 items-center gap-[9px] rounded-lg px-2 text-left font-medium outline-none focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.6)]',
        active
          ? 'bg-white/10 text-white shadow-[inset_0_0_0_0.5px_rgb(255_255_255/0.1),0_1px_2px_rgb(0_0_0/0.35)]'
          : 'text-[#C3CAD6] hover:bg-white/[0.05]',
        className,
      )}
    >
      {tile ?? (
        <Tile tone={tone} size={22}>
          {Icon ? <Icon className="size-[13px]" strokeWidth={2.2} /> : null}
        </Tile>
      )}
      <span className="truncate">{label}</span>
      {badge !== undefined ? (
        <span
          title={badgeLabel}
          className="ml-auto inline-flex h-[18px] min-w-5 items-center justify-center rounded-full bg-[linear-gradient(150deg,#FB7185,#E11D48)] px-1.5 text-[11px] font-bold text-white tabular-nums shadow-[0_2px_8px_-2px_rgb(225_29_72/0.8)]"
        >
          <span aria-hidden="true">{badge}</span>
          <span className="sr-only">{badgeLabel}</span>
        </span>
      ) : count !== undefined ? (
        <span className="ml-auto text-[12px] text-subtle tabular-nums">{count}</span>
      ) : (
        (trailing ?? null)
      )}
    </button>
  );
}
