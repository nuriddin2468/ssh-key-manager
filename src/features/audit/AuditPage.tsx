import { useQuery } from '@tanstack/react-query';
import { Lock, RefreshCw, ShieldCheck } from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import {
  invalidateAll,
  queryClient,
  useAudit,
  useConfig,
  useEnvironment,
  useKeys,
  useVaultEntries,
  useVaultStatus,
} from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { FixAction } from '@/bindings/FixAction';
import type { Severity } from '@/bindings/Severity';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { IconButton } from '@/components/ui/IconButton';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { VaultIcon } from '@/features/keys/VaultControls';
import { cn } from '@/lib/cn';
import { displayPath } from '@/lib/format';
import { updateSettings, useSettings } from '@/lib/settings';
import { AreaCards } from './AreaCards';
import { AuditSummary } from './AuditSummary';
import { BreachCheckAction, BreachSwitch, breachKey, useBreachStatus } from './BreachCheck';
import { ChecksList } from './ChecksList';
import { FindingRow } from './FindingRow';
import { LeakRow } from './LeakRow';
import { LeakScanCard, leakKeys, useLeakStatus } from './LeakScan';
import { groupLeaks } from './leakModel';
import {
  AREAS,
  type Area,
  type AuditItem,
  automaticFixes,
  bySeverity,
  CHECKS,
  type CheckId,
  checkResults,
  findingSubject,
  findingText,
  findingTitle,
  leakItem,
  SEVERITY_ORDER,
  sshItem,
  vaultItem,
} from './model';
import { fixLabelKey, useFix } from './useFix';
import { vaultFindingTarget, vaultFindingText, vaultFindingTitle } from './vaultModel';

const FILTER_LABELS = {
  critical: 'audit.filterCritical',
  warning: 'audit.filterWarning',
  info: 'audit.filterInfo',
} as const;

/**
 * The audit of `~/.ssh`, the hosts file and the vault on one page: how things
 * stand overall, each area's checks, the open findings (by area, filtered by
 * area and severity) with their fixes, and every check that ran.
 */
export function AuditPage() {
  const { t, i18n } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const audit = useAudit();
  const keys = useKeys();
  const config = useConfig();
  const environment = useEnvironment();
  const settings = useSettings();
  const vaultState = useVaultStatus().data?.state;
  // Keyed by the state, so locking or unlocking the vault checks again.
  const vaultAudit = useQuery({
    queryKey: ['vault', 'audit', vaultState],
    queryFn: api.vaultAudit,
    enabled: vaultState !== undefined,
  });
  const entries = useVaultEntries();
  const breach = useBreachStatus();
  const leakStatus = useLeakStatus();
  // Keyed by the state too: locking drops the findings.
  const leakFindings = useQuery({
    queryKey: [...leakKeys.findings, vaultState],
    queryFn: api.leaksFindings,
    enabled: vaultState === 'unlocked',
  });
  // Reading the vault may start a breach check of new passwords.
  useEffect(() => {
    if (vaultAudit.dataUpdatedAt) void queryClient.invalidateQueries({ queryKey: breachKey });
  }, [vaultAudit.dataUpdatedAt]);
  const [area, setArea] = useState<Area | null>(null);
  const [severity, setSeverity] = useState<Severity | null>(null);
  const [showIgnored, setShowIgnored] = useState(false);
  const [checksOpen, setChecksOpen] = useState<boolean | null>(null);

  const keysById = useMemo(
    () => new Map((keys.data?.keys ?? []).map((k) => [k.id, k])),
    [keys.data],
  );
  const titles = useMemo(
    () => new Map((entries.data ?? []).map((entry) => [entry.id, entry.title])),
    [entries.data],
  );
  const { fix, pending } = useFix(keysById);

  const vault = vaultAudit.data;
  const hasVault = vault !== undefined && vault.state !== 'missing';
  const locked = vault?.state === 'locked';
  const areas = AREAS.filter((a) => (a !== 'passwords' && a !== 'leaks') || hasVault);
  const lockedAreas = new Set<Area>(locked ? ['passwords', 'leaks'] : []);
  const ignored = new Set(settings.ignoredFindings);
  const all = bySeverity([
    ...(audit.data?.findings ?? []).map(sshItem),
    ...(vault?.findings ?? []).map(vaultItem),
    ...(locked ? [] : groupLeaks(leakFindings.data ?? []).map(leakItem)),
  ]);
  const open = all.filter((item) => !ignored.has(item.ignoreId));
  const hidden = all.filter((item) => ignored.has(item.ignoreId));
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const item of open) counts[item.severity] += 1;
  const results = checkResults(open);
  const leakSettings = leakStatus?.settings;
  const leakSkipped: Record<string, boolean> = {
    leaksAi: !leakSettings?.ai,
    leaksHistory: !leakSettings?.history,
    leaksRepositories: !leakSettings?.folders.length,
    leaksFiles: !leakSettings?.folders.length,
  };
  const notRun = new Set<CheckId>(
    CHECKS.filter(
      (check) =>
        (locked && lockedAreas.has(check.area)) ||
        (check.id === 'breached' && !(breach?.enabled && breach.checkedAt)) ||
        (check.area === 'leaks' && (!leakStatus?.scannedAt || leakSkipped[check.id])),
    ).map((check) => check.id),
  );
  const ran = CHECKS.filter((check) => areas.includes(check.area) && !notRun.has(check.id));
  const passed = ran.filter((check) => (results.get(check.id)?.count ?? 0) === 0).length;
  const automatic = automaticFixes(open);

  const fixAll = useAppMutation(
    async (actions: FixAction[]) => {
      const permissions = actions.flatMap((action) =>
        action.kind === 'fixPermissions' ? [{ path: action.path, kind: action.target }] : [],
      );
      let fixed = permissions.length > 0 ? await api.fixPermissions(permissions) : 0;
      for (const action of actions) {
        if (action.kind !== 'regeneratePublic') continue;
        await api.regeneratePublic(action.keyId);
        fixed += 1;
      }
      return fixed;
    },
    { success: (fixed) => t('audit.fixedAuto', { count: fixed }) },
  );

  const setIgnored = (id: string, value: boolean) =>
    updateSettings({
      ignoredFindings: value
        ? [...settings.ignoredFindings, id]
        : settings.ignoredFindings.filter((other) => other !== id),
    });

  const scope =
    hasVault && !locked
      ? t('audit.scopeVault', {
          keys: keys.data?.keys.length ?? 0,
          hosts: config.data?.view.hosts.length ?? 0,
          passwords: entries.data?.filter((entry) => !entry.inTrash).length ?? 0,
        })
      : t('audit.scope', {
          keys: keys.data?.keys.length ?? 0,
          hosts: config.data?.view.hosts.length ?? 0,
        });
  const checkedAt = audit.dataUpdatedAt
    ? new Intl.DateTimeFormat(i18n.language, { timeStyle: 'short' }).format(audit.dataUpdatedAt)
    : '';

  const row = (item: AuditItem, muted: boolean) => {
    const ignore = muted ? undefined : () => setIgnored(item.ignoreId, true);
    const restore = muted ? () => setIgnored(item.ignoreId, false) : undefined;
    if (item.source === 'leak') {
      return (
        <LeakRow
          key={item.ignoreId}
          group={item.group}
          muted={muted}
          onIgnore={ignore}
          onRestore={restore}
        />
      );
    }
    if (item.source === 'ssh') {
      const finding = item.finding;
      return (
        <FindingRow
          key={item.ignoreId}
          severity={finding.severity}
          title={findingTitle(t, finding)}
          text={findingText(t, finding)}
          subject={findingSubject(finding, keysById, config.data?.view.hosts ?? [], (path) =>
            displayPath(path, environment.data?.paths.home),
          )}
          actionLabel={t(fixLabelKey(finding))}
          busy={pending === finding.fix}
          onAction={() => fix(finding)}
          muted={muted}
          onIgnore={ignore}
          onRestore={restore}
        />
      );
    }
    const finding = item.finding;
    const target = vaultFindingTarget(finding);
    return (
      <FindingRow
        key={item.ignoreId}
        severity={finding.severity}
        title={vaultFindingTitle(t, finding)}
        text={vaultFindingText(t, finding, titles, i18n.language)}
        subject={titles.get(finding.entryId) ?? ''}
        actionLabel={t(target.label)}
        onAction={() => navigate(target.route)}
        muted={muted}
        onIgnore={ignore}
        onRestore={restore}
      />
    );
  };

  const shownAreas = areas.filter((a) => area === null || a === area);
  const inView = open.filter(
    (item) => shownAreas.includes(item.area) && (severity === null || item.severity === severity),
  );
  const lockedRowShown = locked && shownAreas.includes('passwords') && severity === null;
  const inAreas = open.filter((item) => shownAreas.includes(item.area));
  // With nothing open, the checks are what's left to show.
  const checksShown = checksOpen ?? open.length === 0;

  return (
    <>
      <Toolbar
        title={t('audit.title')}
        meta={checkedAt ? t('audit.checked', { time: checkedAt }) : undefined}
      >
        <IconButton
          label={t('audit.checkAgain')}
          variant="secondary"
          icon={
            <RefreshCw
              className={cn(
                'size-[15px]',
                (audit.isFetching || vaultAudit.isFetching) && 'animate-spin',
              )}
              strokeWidth={1.9}
            />
          }
          onClick={() => void invalidateAll()}
        />
      </Toolbar>

      <PageBody className="gap-[18px]">
        {audit.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : (
          <>
            <AuditSummary
              counts={counts}
              scope={scope}
              passed={passed}
              total={ran.length}
              automatic={automatic.length}
              fixing={fixAll.isPending}
              onFixAll={() => fixAll.mutate(automatic)}
            />

            <AreaCards
              areas={areas}
              results={results}
              items={open}
              notRun={notRun}
              lockedAreas={lockedAreas}
              selected={area}
              onSelect={(next) => {
                setArea(next);
                setSeverity(null);
              }}
            />

            {leakStatus && areas.includes('leaks') && (area === null || area === 'leaks') ? (
              <LeakScanCard status={leakStatus} locked={locked} />
            ) : null}

            {open.length > 0 || locked || area !== null ? (
              <section aria-labelledby="audit-findings-h" className="flex flex-col gap-2.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <h2
                    id="audit-findings-h"
                    tabIndex={-1}
                    className="text-[14px] leading-5 font-semibold outline-none"
                  >
                    {area === null ? t('audit.findingsTitle') : t(`audit.areas.${area}`)}
                  </h2>
                  {inAreas.length > 0 ? (
                    <fieldset className="m-0 ml-auto flex min-w-0 flex-wrap gap-1.5 border-0 p-0">
                      <legend className="sr-only">{t('audit.filterLabel')}</legend>
                      <Chip
                        label={t('audit.filterAll')}
                        count={inAreas.length}
                        pressed={severity === null}
                        onClick={() => setSeverity(null)}
                      />
                      {SEVERITY_ORDER.map((level) => {
                        const count = inAreas.filter((item) => item.severity === level).length;
                        return count > 0 ? (
                          <Chip
                            key={level}
                            label={t(FILTER_LABELS[level])}
                            count={count}
                            pressed={severity === level}
                            onClick={() => setSeverity(severity === level ? null : level)}
                          />
                        ) : null;
                      })}
                    </fieldset>
                  ) : null}
                </div>

                {inView.length === 0 && !lockedRowShown ? (
                  <p className="flex items-center gap-2 rounded-xl border border-ok/25 bg-ok/[0.08] px-3 py-2.5 text-[12.5px] text-teal-200">
                    <ShieldCheck aria-hidden="true" className="size-4" strokeWidth={2} />
                    {t('audit.nothingHere')}
                  </p>
                ) : (
                  shownAreas.map((group) => {
                    const items = inView.filter((item) => item.area === group);
                    const lockedHere = group === 'passwords' && lockedRowShown;
                    if (items.length === 0 && !lockedHere) return null;
                    return (
                      <div key={group} className="flex flex-col gap-2">
                        {area === null ? (
                          <h3 className="pt-1 text-[11.5px] font-semibold tracking-[0.04em] text-subtle uppercase">
                            {t(`audit.areas.${group}`)}
                          </h3>
                        ) : null}
                        {lockedHere ? (
                          <div className="glass flex flex-wrap items-center gap-x-3.5 gap-y-3 rounded-2xl px-4 py-[13px]">
                            <Tile tone="slate" size={36}>
                              <VaultIcon className="size-[18px]" />
                            </Tile>
                            <span className="flex min-w-[240px] flex-1 flex-col gap-0.5">
                              <span className="font-semibold">{t('audit.vault.lockedTitle')}</span>
                              <span className="text-[12.5px] text-muted">
                                {t('audit.vault.lockedText')}
                              </span>
                            </span>
                            <Button
                              size="sm"
                              onClick={() =>
                                dialogs.unlockVault({ description: t('audit.vault.lockedText') })
                              }
                            >
                              {t('passwords.unlock')}
                            </Button>
                          </div>
                        ) : null}
                        {items.map((item) => row(item, false))}
                      </div>
                    );
                  })
                )}
              </section>
            ) : null}

            <ChecksList
              areas={areas}
              results={results}
              lockedAreas={lockedAreas}
              notRun={notRun}
              extras={{ breached: <BreachCheckAction status={breach} /> }}
              footers={{ passwords: <BreachSwitch layout="card" /> }}
              passed={passed}
              total={ran.length}
              off={hasVault && !locked && breach && !breach.enabled ? 1 : 0}
              open={checksShown}
              onToggle={() => setChecksOpen(!checksShown)}
            />

            {hidden.length > 0 ? (
              <section className="flex flex-col gap-2">
                <p className="flex items-center gap-2 text-[12.5px] text-subtle">
                  {t('audit.ignored', { count: hidden.length })}
                  <Button variant="ghost" size="sm" onClick={() => setShowIgnored((v) => !v)}>
                    {showIgnored ? t('audit.hideIgnored') : t('audit.showIgnored')}
                  </Button>
                </p>
                {showIgnored ? hidden.map((item) => row(item, true)) : null}
              </section>
            ) : null}

            <p className="mt-auto flex items-center gap-2 text-[12.5px] text-subtle">
              <Lock aria-hidden="true" className="size-[15px]" strokeWidth={1.75} />
              {breach?.enabled ? t('audit.privacyBreaches') : t('audit.privacy')}
            </p>
          </>
        )}
      </PageBody>
    </>
  );
}
