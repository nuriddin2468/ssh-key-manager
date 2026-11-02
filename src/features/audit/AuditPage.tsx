import { Lock, RefreshCw, ShieldCheck, Wrench } from 'lucide-react';
import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { invalidateAll, useAudit, useConfig, useEnvironment, useKeys } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import type { Finding } from '@/bindings/Finding';
import type { Severity } from '@/bindings/Severity';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { displayPath } from '@/lib/format';
import { updateSettings, useSettings } from '@/lib/settings';
import { FindingRow } from './FindingRow';
import {
  findingSubject,
  findingsByKey,
  findingText,
  findingTitle,
  healthyKeyCount,
  SEVERITY_COLORS,
  SEVERITY_ORDER,
} from './model';
import { fixLabelKey, useFix } from './useFix';
import { VaultAuditSection } from './VaultAuditSection';

const CIRCUMFERENCE = 2 * Math.PI * 52;

export function AuditPage() {
  const { t, i18n } = useTranslation();
  const audit = useAudit();
  const keys = useKeys();
  const config = useConfig();
  const environment = useEnvironment();
  const settings = useSettings();
  const [showIgnored, setShowIgnored] = useState(false);

  const keysById = useMemo(
    () => new Map((keys.data?.keys ?? []).map((k) => [k.id, k])),
    [keys.data],
  );
  const { fix, pending } = useFix(keysById);
  const ignored = new Set(settings.ignoredFindings);
  const all = audit.data?.findings ?? [];
  const open = all.filter((f) => !ignored.has(f.id));
  const hidden = all.filter((f) => ignored.has(f.id));
  const count = (severity: Severity) => open.filter((f) => f.severity === severity).length;
  const totalKeys = keys.data?.keys.length ?? 0;
  const healthy = healthyKeyCount(keys.data?.keys ?? [], findingsByKey(audit.data));
  const permissionFixes = open.flatMap((f) =>
    f.fix?.kind === 'fixPermissions' ? [{ path: f.fix.path, kind: f.fix.target }] : [],
  );

  const fixAll = useAppMutation(api.fixPermissions, {
    success: (fixed) => t('audit.fixedPermissions', { count: fixed }),
  });
  const setIgnored = (id: string, value: boolean) =>
    updateSettings({
      ignoredFindings: value
        ? [...settings.ignoredFindings, id]
        : settings.ignoredFindings.filter((other) => other !== id),
    });

  const subject = (finding: Finding) =>
    findingSubject(finding, keysById, config.data?.view.hosts ?? [], (path) =>
      displayPath(path, environment.data?.paths.home),
    );

  let start = 0;
  const gap = open.length > 1 ? 16 : 0;
  const segments = SEVERITY_ORDER.map((severity) => {
    const length = open.length ? (CIRCUMFERENCE * count(severity)) / open.length : 0;
    const dash = Math.max(length - gap, 0);
    const segment = { severity, dash, offset: -start };
    start += length;
    return segment;
  });

  const headline =
    totalKeys === 0
      ? t('audit.headlineNoKeys')
      : healthy === totalKeys
        ? t('audit.headlineAll', { count: totalKeys })
        : t('audit.headlinePartial', { healthy, total: totalKeys });
  const checkedAt = audit.dataUpdatedAt
    ? new Intl.DateTimeFormat(i18n.language, { timeStyle: 'short' }).format(audit.dataUpdatedAt)
    : '';

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
              className={cn('size-[15px]', audit.isFetching && 'animate-spin')}
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
            <section
              aria-labelledby="audit-title"
              className="flex flex-wrap items-center gap-[26px] rounded-[20px] border border-rose-400/20 bg-[linear-gradient(135deg,rgb(225_29_72/0.16),rgb(255_255_255/0.03)_60%)] px-[26px] py-[22px] shadow-[inset_0_1px_0_rgb(255_255_255/0.06)]"
            >
              <div className="relative grid size-[136px] shrink-0 place-items-center">
                <svg
                  role="img"
                  aria-label={t('audit.ring', {
                    total: open.length,
                    critical: count('critical'),
                    warning: count('warning'),
                    info: count('info'),
                  })}
                  width="136"
                  height="136"
                  viewBox="0 0 136 136"
                  className="absolute inset-0"
                >
                  <circle
                    cx="68"
                    cy="68"
                    r="52"
                    fill="none"
                    stroke="rgb(255 255 255 / 0.07)"
                    strokeWidth="12"
                  />
                  {segments.map((segment) =>
                    segment.dash > 0 ? (
                      <circle
                        key={segment.severity}
                        cx="68"
                        cy="68"
                        r="52"
                        fill="none"
                        stroke={SEVERITY_COLORS[segment.severity]}
                        strokeWidth="12"
                        strokeLinecap="round"
                        strokeDasharray={`${segment.dash.toFixed(2)} ${CIRCUMFERENCE.toFixed(2)}`}
                        strokeDashoffset={segment.offset.toFixed(2)}
                        transform="rotate(-90 68 68)"
                        className="transition-[stroke-dasharray,stroke-dashoffset] duration-500"
                      />
                    ) : null,
                  )}
                  {open.length === 0 ? (
                    <circle
                      cx="68"
                      cy="68"
                      r="52"
                      fill="none"
                      stroke="#5EEAD4"
                      strokeWidth="12"
                      opacity="0.8"
                    />
                  ) : null}
                </svg>
                <span className="relative flex flex-col items-center">
                  <span className="text-[34px] leading-[38px] font-semibold tracking-[-0.03em] tabular-nums">
                    {open.length}
                  </span>
                  <span className="text-[12px] text-muted">
                    {t('audit.findings', { count: open.length })}
                  </span>
                </span>
              </div>
              <div className="flex min-w-[280px] flex-1 flex-col gap-1.5">
                <span className="text-[12.5px] text-muted">
                  {t('audit.scope', {
                    keys: totalKeys,
                    hosts: config.data?.view.hosts.length ?? 0,
                  })}
                </span>
                <h2
                  id="audit-title"
                  className="text-[26px] leading-8 font-semibold tracking-[-0.02em]"
                >
                  {headline}
                </h2>
                <div className="mt-0.5 flex flex-wrap gap-3.5">
                  {SEVERITY_ORDER.map((severity) => (
                    <span
                      key={severity}
                      className="inline-flex items-center gap-[7px] text-[12.5px] text-fg-2"
                    >
                      <span
                        aria-hidden="true"
                        className="size-[9px] rounded-[3px]"
                        style={{ background: SEVERITY_COLORS[severity] }}
                      />
                      {t(
                        severity === 'critical'
                          ? 'audit.legendCritical'
                          : severity === 'warning'
                            ? 'audit.legendWarning'
                            : 'audit.legendInfo',
                        { count: count(severity) },
                      )}
                    </span>
                  ))}
                </div>
                {permissionFixes.length > 0 ? (
                  <div className="mt-2.5 flex flex-wrap gap-2.5">
                    <Button
                      variant="primary"
                      size="lg"
                      loading={fixAll.isPending}
                      icon={<Wrench className="size-4" strokeWidth={2} />}
                      onClick={() => fixAll.mutate(permissionFixes)}
                    >
                      {t('audit.fixPermissions')}
                    </Button>
                  </div>
                ) : null}
              </div>
            </section>

            {open.length === 0 ? (
              <div className="flex flex-col items-center gap-2 rounded-[20px] border border-ok/20 bg-ok/[0.06] px-4 py-11 text-center">
                <Tile tone="teal" size={52} glow>
                  <ShieldCheck className="size-[26px]" strokeWidth={2} />
                </Tile>
                <span className="text-[17px] font-semibold">{t('audit.allClearTitle')}</span>
                <span className="text-[12.5px] text-muted">{t('audit.allClearText')}</span>
              </div>
            ) : (
              <section aria-label={t('audit.title')} className="flex flex-col gap-2">
                {open.map((finding) => (
                  <FindingRow
                    key={finding.id}
                    severity={finding.severity}
                    title={findingTitle(t, finding)}
                    text={findingText(t, finding)}
                    subject={subject(finding)}
                    actionLabel={t(fixLabelKey(finding))}
                    busy={pending === finding.fix}
                    onAction={() => fix(finding)}
                    onIgnore={() => setIgnored(finding.id, true)}
                  />
                ))}
              </section>
            )}

            {hidden.length > 0 ? (
              <section className="flex flex-col gap-2">
                <p className="flex items-center gap-2 text-[12.5px] text-subtle">
                  {t('audit.ignored', { count: hidden.length })}
                  <Button variant="ghost" size="sm" onClick={() => setShowIgnored((v) => !v)}>
                    {showIgnored ? t('audit.hideIgnored') : t('audit.showIgnored')}
                  </Button>
                </p>
                {showIgnored
                  ? hidden.map((finding) => (
                      <FindingRow
                        key={finding.id}
                        severity={finding.severity}
                        title={findingTitle(t, finding)}
                        text={findingText(t, finding)}
                        subject={subject(finding)}
                        muted
                        onRestore={() => setIgnored(finding.id, false)}
                      />
                    ))
                  : null}
              </section>
            ) : null}

            <VaultAuditSection ignored={ignored} onIgnore={setIgnored} />

            <p className="mt-auto flex items-center gap-2 text-[12.5px] text-subtle">
              <Lock aria-hidden="true" className="size-[15px]" strokeWidth={1.75} />
              {t('audit.privacy')}
            </p>
          </>
        )}
      </PageBody>
    </>
  );
}
