import {
  Cpu,
  Globe,
  KeyRound,
  LockKeyhole,
  type LucideIcon,
  Network,
  RectangleEllipsis,
  Server,
  Settings as SettingsIcon,
  ShieldCheck,
  Sparkle,
  SquareTerminal,
} from 'lucide-react';
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
import { Logo } from '@/components/Logo';
import { Tile, type Tone } from '@/components/ui/Tile';
import { useSessionCounts } from '@/features/terminal/TerminalProvider';
import { cn } from '@/lib/cn';
import { platform } from '@/lib/platform';
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
  const sessions = useSessionCounts();

  const findings = audit.data ? audit.data.counts.critical + audit.data.counts.warning : 0;
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

      <nav aria-label={t('nav.sections')} className="flex flex-col gap-3.5">
        <div className="flex flex-col gap-px">
          {item('overview', t('nav.overview'), 'aurora', Sparkle)}
        </div>
        <NavGroup label={t('nav.groupOpenssh')}>
          {item('keys', t('nav.keys'), 'teal', KeyRound, keys.data?.keys.length)}
          {item('hosts', t('nav.hosts'), 'blue', Server, config.data?.view.hosts.length)}
          {item('agent', t('nav.agent'), 'violet', Cpu, running ? unlocked : undefined)}
          {item('known', t('nav.known'), 'amber', Globe, known.data?.view.entries.length)}
        </NavGroup>
        <NavGroup label={t('nav.groupSystem')}>
          {item(
            'hostsFile',
            t('nav.hostsFile'),
            'indigo',
            Network,
            hostsFile.data?.view.entries.filter((entry) => entry.enabled).length,
          )}
        </NavGroup>
        <NavGroup label={t('nav.groupSecrets')}>
          <NavItem
            label={t('nav.passwords')}
            tone="pink"
            icon={RectangleEllipsis}
            active={route.page === 'passwords'}
            count={savedPasswords}
            trailing={
              vaultState === 'locked' ? (
                <LockKeyhole
                  role="img"
                  aria-label={t('nav.vaultLocked')}
                  className="ml-auto size-3.5 text-subtle"
                  strokeWidth={2}
                />
              ) : undefined
            }
            onClick={() => navigate({ page: 'passwords' })}
          />
        </NavGroup>
        <NavGroup label={t('nav.groupSessions')}>
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
        </NavGroup>
        <NavGroup label={t('nav.groupHealth')}>
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
        <div className="flex flex-col gap-px">
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
      </nav>
    </aside>
  );
}

function NavGroup({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-px">
      <span className="px-2 pb-[5px] text-[11px] font-semibold text-[#7C869A]">{label}</span>
      {children}
    </div>
  );
}

interface NavItemProps {
  label: string;
  tone: Tone;
  icon: LucideIcon;
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
  tone,
  icon: Icon,
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
        'pressable-soft flex h-8 items-center gap-[9px] rounded-lg px-2 text-left font-medium',
        active
          ? 'bg-white/10 text-white shadow-[inset_0_0_0_0.5px_rgb(255_255_255/0.1),0_1px_2px_rgb(0_0_0/0.35)]'
          : 'text-[#C3CAD6] hover:bg-white/[0.05]',
      )}
    >
      <Tile tone={tone} size={22}>
        <Icon className="size-[13px]" strokeWidth={2.2} />
      </Tile>
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
