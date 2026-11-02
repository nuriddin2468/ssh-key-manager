import { useIsFetching } from '@tanstack/react-query';
import {
  ArrowRight,
  ChevronRight,
  Clock,
  Cpu,
  Globe,
  KeyRound,
  Server,
  ShieldCheck,
} from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  invalidateAll,
  useAgent,
  useAudit,
  useConfig,
  useEnvironment,
  useKeys,
  useKnownHosts,
} from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { type Route, useRouter } from '@/app/router';
import { Logo } from '@/components/Logo';
import { Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { Tile, type Tone } from '@/components/ui/Tile';
import { formatRelative } from '@/lib/format';

const PLATFORM_NAMES = { macos: 'macOS', windows: 'Windows', linux: 'Linux' } as const;
/** The scan animation runs at least this long so it reads as a check, not a flicker. */
const MIN_CHECK_MS = 1600;

export function OverviewPage() {
  const { t, i18n } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const environment = useEnvironment();
  const keys = useKeys();
  const agent = useAgent();
  const config = useConfig();
  const known = useKnownHosts();
  const audit = useAudit();
  const fetching = useIsFetching() > 0;

  const [checking, setChecking] = useState(false);
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 30_000);
    return () => clearInterval(timer);
  }, []);

  const runCheck = async () => {
    setChecking(true);
    const started = Date.now();
    await invalidateAll();
    const rest = MIN_CHECK_MS - (Date.now() - started);
    if (rest > 0) await new Promise((resolve) => setTimeout(resolve, rest));
    setChecking(false);
  };

  const scanning = checking || (audit.isPending && fetching);
  const counts = audit.data?.counts ?? { critical: 0, warning: 0, info: 0 };
  const total = counts.critical + counts.warning + counts.info;
  const noKeys = keys.data && keys.data.keys.length === 0;

  const parts: string[] = [];
  if (counts.critical) parts.push(t('overview.critical', { count: counts.critical }));
  if (counts.warning) parts.push(t('overview.warnings', { count: counts.warning }));
  if (counts.info) parts.push(t('overview.suggestions', { count: counts.info }));
  const issues =
    parts.length > 1
      ? t('common.and', { a: parts.slice(0, -1).join(', '), b: parts.at(-1) ?? '' })
      : (parts[0] ?? '');

  const title = scanning
    ? t('overview.titleChecking')
    : noKeys
      ? t('overview.welcomeTitle')
      : counts.critical
        ? t('overview.titleCritical')
        : counts.warning
          ? t('overview.titleWarnings')
          : counts.info
            ? t('overview.titleSuggestions')
            : t('overview.titleHealthy');
  const subtitle = scanning
    ? t('overview.subtitleChecking')
    : noKeys
      ? t('overview.welcomeText')
      : total
        ? t('overview.subtitleIssues', { issues: issues.charAt(0).toUpperCase() + issues.slice(1) })
        : t('overview.subtitleHealthy');

  const keysNeedingCare = new Set(
    (audit.data?.findings ?? [])
      .filter((f) => f.severity !== 'info' && f.subject.keyId)
      .map((f) => f.subject.keyId),
  ).size;
  const brokenHosts = new Set(
    (config.data?.usage ?? []).filter((u) => u.resolved && !u.exists).map((u) => u.hostId),
  ).size;
  const running = agent.data?.status.available ?? false;

  const checkedAt = audit.dataUpdatedAt ? new Date(audit.dataUpdatedAt) : null;
  const env = environment.data;

  return (
    <>
      <Toolbar className="border-b-transparent bg-transparent">
        <Pill icon={<Clock className="size-[13px]" strokeWidth={2} />}>
          {scanning || !checkedAt
            ? t('overview.checkingNow')
            : t('overview.checked', { time: formatRelative(checkedAt, i18n.language, now) })}
        </Pill>
        {env ? (
          <Pill mono>
            {t('overview.environment', {
              platform: PLATFORM_NAMES[env.platform],
              openssh: env.opensshVersion?.replace('_', ' ') ?? t('settings.opensshMissing'),
            })}
          </Pill>
        ) : null}
      </Toolbar>

      <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
        <section
          aria-labelledby="hero-title"
          aria-busy={scanning}
          className="flex flex-1 flex-col items-center gap-1.5 px-7 pt-1 text-center"
        >
          <HeroOrb scanning={scanning} />
          <h2
            id="hero-title"
            aria-live="polite"
            className="mt-1.5 text-[34px] leading-10 font-semibold tracking-[-0.025em]"
          >
            {title}
          </h2>
          <p className="max-w-[540px] text-[14.5px] leading-[22px] text-muted">{subtitle}</p>
          <div className="mt-[18px] flex flex-wrap items-center justify-center gap-3">
            {noKeys && !scanning ? (
              <Button
                variant="primary"
                size="hero"
                icon={<KeyRound className="size-[18px]" strokeWidth={2} />}
                onClick={dialogs.generateKey}
                className="bg-[linear-gradient(135deg,#5EEAD4_0%,#2DD4BF_45%,#A78BFA_100%)]"
              >
                {t('overview.welcomeAction')}
              </Button>
            ) : (
              <Button
                variant="primary"
                size="hero"
                loading={scanning}
                icon={<ShieldCheck className="size-[18px]" strokeWidth={2} />}
                onClick={runCheck}
                className="bg-[linear-gradient(135deg,#5EEAD4_0%,#2DD4BF_45%,#A78BFA_100%)]"
              >
                {scanning ? t('overview.checking') : t('overview.checkAgain')}
              </Button>
            )}
            {!scanning && total > 0 ? (
              <Button
                size="hero"
                className="text-[14px]"
                onClick={() => navigate({ page: 'audit' })}
              >
                {t('overview.review', { count: total })}
                <ArrowRight className="size-4" strokeWidth={2} aria-hidden="true" />
              </Button>
            ) : null}
          </div>
        </section>

        <section
          aria-label={t('nav.sections')}
          className="flex flex-wrap gap-3.5 px-7 pt-[26px] pb-7"
        >
          <SummaryTile
            to={{ page: 'keys' }}
            tone="teal"
            icon={<KeyRound className="size-[17px]" strokeWidth={2} />}
            label={t('nav.keys')}
            value={keys.data ? String(keys.data.keys.length) : '–'}
            status={
              keysNeedingCare
                ? t('overview.tileKeysStatusIssues', { count: keysNeedingCare })
                : t('overview.tileKeysStatusOk')
            }
            statusColor={keysNeedingCare ? '#FFC266' : '#5EEAD4'}
            dimmed={scanning}
          />
          <SummaryTile
            to={{ page: 'agent' }}
            tone="violet"
            icon={<Cpu className="size-[17px]" strokeWidth={2} />}
            label={t('nav.agent')}
            value={t('overview.tileAgentValue', { count: agent.data?.identities.length ?? 0 })}
            status={
              running ? t('overview.tileAgentStatusRunning') : t('overview.tileAgentStatusStopped')
            }
            statusColor={running ? '#C4B5FD' : '#FFC266'}
            dimmed={scanning}
          />
          <SummaryTile
            to={{ page: 'hosts' }}
            tone="blue"
            icon={<Server className="size-[17px]" strokeWidth={2} />}
            label={t('nav.hosts')}
            value={config.data ? String(config.data.view.hosts.length) : '–'}
            status={
              brokenHosts
                ? t('overview.tileHostsStatusBroken', { count: brokenHosts })
                : t('overview.tileHostsStatusOk')
            }
            statusColor={brokenHosts ? '#FFC266' : '#5EEAD4'}
            dimmed={scanning}
          />
          <SummaryTile
            to={{ page: 'known' }}
            tone="amber"
            icon={<Globe className="size-[17px]" strokeWidth={2} />}
            label={t('nav.known')}
            value={known.data ? String(known.data.view.entries.length) : '–'}
            status={t('overview.tileKnownStatus')}
            statusColor="#5EEAD4"
            dimmed={scanning}
          />
        </section>
      </div>
    </>
  );
}

function Pill({ icon, mono, children }: { icon?: ReactNode; mono?: boolean; children: ReactNode }) {
  return (
    <span
      className={`inline-flex h-7 items-center gap-2 rounded-full border border-white/[0.08] bg-white/[0.05] px-3 text-muted ${mono ? 'font-mono text-[11.5px]' : 'text-[12px]'}`}
    >
      {icon}
      {children}
    </span>
  );
}

function HeroOrb({ scanning }: { scanning: boolean }) {
  return (
    <div aria-hidden="true" className="relative grid size-[248px] shrink-0 place-items-center">
      <div className="absolute inset-2.5 animate-glow rounded-full bg-[radial-gradient(circle,rgb(45_212_191/0.4)_0%,rgb(124_58_237/0.2)_45%,transparent_70%)]" />
      <div className="absolute inset-3.5 animate-orbit rounded-full border border-dashed border-white/[0.14]">
        <span className="absolute -top-[5px] left-1/2 -ml-[5px] size-2.5 rounded-full bg-[#5EEAD4] shadow-[0_0_14px_#5EEAD4]" />
        <span className="absolute bottom-[18%] left-[4%] size-2 rounded-full bg-[#A78BFA] shadow-[0_0_12px_#A78BFA]" />
        <span className="absolute right-[12%] bottom-[10%] size-1.5 rounded-full bg-[#7DD3FC] shadow-[0_0_10px_#7DD3FC]" />
      </div>
      <div className="absolute inset-[50px] animate-orbit-reverse rounded-full border border-white/[0.09]">
        <span className="absolute top-[12%] right-[6%] size-[7px] rounded-full bg-[#FCD34D] shadow-[0_0_10px_#FCD34D]" />
      </div>
      <svg aria-hidden="true" width="148" height="148" viewBox="0 0 120 120" className="absolute">
        <circle
          cx="60"
          cy="60"
          r="54"
          fill="none"
          stroke="rgb(255 255 255 / 0.06)"
          strokeWidth="3"
        />
        <circle
          key={scanning ? 'scan' : 'idle'}
          cx="60"
          cy="60"
          r="54"
          fill="none"
          stroke="#5EEAD4"
          strokeWidth="3"
          strokeLinecap="round"
          strokeDasharray="339"
          transform="rotate(-90 60 60)"
          style={{
            opacity: scanning ? 1 : 0.35,
            animation: scanning ? 'sweep 1.6s ease-in-out forwards' : undefined,
            filter: 'drop-shadow(0 0 6px #5EEAD4)',
          }}
        />
      </svg>
      <div className="animate-floaty">
        <Logo size={116} className="shadow-[0_34px_60px_-22px_rgb(79_70_229/0.85)]" />
      </div>
    </div>
  );
}

interface SummaryTileProps {
  to: Route;
  tone: Tone;
  icon: ReactNode;
  label: string;
  value: string;
  status: string;
  statusColor: string;
  dimmed: boolean;
}

function SummaryTile({
  to,
  tone,
  icon,
  label,
  value,
  status,
  statusColor,
  dimmed,
}: SummaryTileProps) {
  const { navigate } = useRouter();
  return (
    <button
      type="button"
      onClick={() => navigate(to)}
      className="glass flex min-w-0 flex-[1_1_200px] flex-col gap-3.5 rounded-2xl p-4 text-left shadow-[inset_0_1px_0_rgb(255_255_255/0.05),0_20px_40px_-24px_rgb(0_0_0/0.6)] pressable-soft hover:bg-white/[0.06]"
      style={{ opacity: dimmed ? 0.45 : 1 }}
    >
      <span className="flex w-full items-center gap-2.5">
        <Tile tone={tone} size={34} glow>
          {icon}
        </Tile>
        <span className="font-semibold">{label}</span>
        <ChevronRight aria-hidden="true" className="ml-auto size-4 text-subtle" strokeWidth={2} />
      </span>
      <span className="flex flex-col gap-0.5">
        <span className="text-[28px] leading-8 font-semibold tracking-[-0.02em] tabular-nums">
          {value}
        </span>
        <span className="flex items-center gap-1.5 text-[12.5px]" style={{ color: statusColor }}>
          <span
            aria-hidden="true"
            className="size-1.5 rounded-full"
            style={{ background: statusColor }}
          />
          {status}
        </span>
      </span>
    </button>
  );
}
