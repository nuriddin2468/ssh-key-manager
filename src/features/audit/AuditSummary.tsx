import { ShieldCheck, Wrench } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { Severity } from '@/bindings/Severity';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/cn';
import { SEVERITY_COLORS, SEVERITY_ORDER } from './model';

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const OK_COLOR = 'var(--color-ok)';

/**
 * The hero's look follows the most serious open finding: red only for a
 * critical one, amber for warnings, teal once nothing needs fixing.
 */
const TONES = {
  critical: {
    box: 'border-critical-solid/25 bg-[linear-gradient(135deg,color-mix(in_srgb,var(--color-critical-solid)_16%,transparent),var(--color-fill-subtle)_62%)]',
  },
  warning: {
    box: 'border-warning-solid/25 bg-[linear-gradient(135deg,color-mix(in_srgb,var(--color-warning-solid)_14%,transparent),var(--color-fill-subtle)_62%)]',
  },
  clear: {
    box: 'border-ok/20 bg-[linear-gradient(135deg,color-mix(in_srgb,var(--color-ok)_12%,transparent),var(--color-fill-subtle)_62%)]',
  },
} as const;

export type SummaryTone = keyof typeof TONES;

export function summaryTone(worst: Severity | null): SummaryTone {
  return worst === 'critical' ? 'critical' : worst === 'warning' ? 'warning' : 'clear';
}

interface AuditSummaryProps {
  counts: Record<Severity, number>;
  /** What was looked at, e.g. "6 keys, 8 hosts, …". */
  scope: string;
  passed: number;
  total: number;
  /** One-click fixes that need no answer from the user. */
  automatic: number;
  fixing: boolean;
  onFixAll: () => void;
}

/** The top of the audit: how things stand overall, and the one thing to do first. */
export function AuditSummary({
  counts,
  scope,
  passed,
  total,
  automatic,
  fixing,
  onFixAll,
}: AuditSummaryProps) {
  const { t } = useTranslation();
  const open = counts.critical + counts.warning + counts.info;
  const worst = SEVERITY_ORDER.find((severity) => counts[severity] > 0) ?? null;
  const tone = summaryTone(worst);

  const headline =
    worst === 'critical'
      ? t('audit.headlineCritical', { count: counts.critical })
      : worst === 'warning'
        ? t('audit.headlineWarning', { count: counts.warning })
        : worst === 'info'
          ? t('audit.headlineInfo')
          : t('audit.headlineClear');
  const lead =
    worst === 'critical'
      ? t('audit.leadCritical')
      : worst === 'warning'
        ? t('audit.leadWarning')
        : worst === 'info'
          ? t('audit.leadInfo')
          : t('audit.leadClear');

  let start = 0;
  const gap = open > 1 ? 16 : 0;
  const segments = SEVERITY_ORDER.map((severity) => {
    const length = open ? (CIRCUMFERENCE * counts[severity]) / open : 0;
    const segment = { severity, dash: Math.max(length - gap, 0), offset: -start };
    start += length;
    return segment;
  });

  return (
    <section
      aria-labelledby="audit-title"
      data-tone={tone}
      className={cn(
        'flex flex-wrap items-center gap-[26px] rounded-[20px] border px-[26px] py-[22px] shadow-[inset_0_1px_0_var(--color-sheen)] transition-[background,border-color] duration-500',
        TONES[tone].box,
      )}
    >
      <div className="relative grid size-[136px] shrink-0 place-items-center">
        <svg
          role="img"
          aria-label={t('audit.ring', {
            total: open,
            critical: counts.critical,
            warning: counts.warning,
            info: counts.info,
          })}
          width="136"
          height="136"
          viewBox="0 0 136 136"
          className="absolute inset-0"
        >
          <circle
            cx="68"
            cy="68"
            r={RADIUS}
            fill="none"
            className="stroke-ink/[0.07]"
            strokeWidth="12"
          />
          {open === 0 ? (
            <circle
              cx="68"
              cy="68"
              r={RADIUS}
              fill="none"
              style={{ stroke: OK_COLOR }}
              strokeWidth="12"
              opacity="0.85"
            />
          ) : (
            segments.map((segment) =>
              segment.dash > 0 ? (
                <circle
                  key={segment.severity}
                  cx="68"
                  cy="68"
                  r={RADIUS}
                  fill="none"
                  style={{ stroke: SEVERITY_COLORS[segment.severity] }}
                  strokeWidth="12"
                  strokeLinecap="round"
                  strokeDasharray={`${segment.dash.toFixed(2)} ${CIRCUMFERENCE.toFixed(2)}`}
                  strokeDashoffset={segment.offset.toFixed(2)}
                  transform="rotate(-90 68 68)"
                  className="transition-[stroke-dasharray,stroke-dashoffset] duration-500"
                />
              ) : null,
            )
          )}
        </svg>
        {open === 0 ? (
          <ShieldCheck aria-hidden="true" className="relative size-11 text-ok" strokeWidth={1.75} />
        ) : (
          <span aria-hidden="true" className="relative flex flex-col items-center">
            <span className="text-[34px] leading-[38px] font-semibold tracking-[-0.03em] tabular-nums">
              {open}
            </span>
            <span className="text-[12px] text-muted">{t('audit.findings', { count: open })}</span>
          </span>
        )}
      </div>

      <div className="flex min-w-[280px] flex-1 flex-col gap-1.5">
        <span className="text-[12.5px] text-muted">{scope}</span>
        <h2 id="audit-title" className="text-[26px] leading-8 font-semibold tracking-[-0.02em]">
          {headline}
        </h2>
        <p className="text-[13px] leading-5 text-fg-2">{lead}</p>
        <div className="mt-1 flex flex-wrap items-center gap-x-3.5 gap-y-1.5">
          {SEVERITY_ORDER.filter((severity) => counts[severity] > 0).map((severity) => (
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
                { count: counts[severity] },
              )}
            </span>
          ))}
          <span className="inline-flex items-center gap-[7px] text-[12.5px] text-fg-2">
            <span aria-hidden="true" className="size-[9px] rounded-[3px] bg-ok" />
            {t('audit.checksPassed', { passed, total })}
          </span>
        </div>
        {automatic > 0 ? (
          <div className="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-1.5">
            <Button
              variant="primary"
              size="lg"
              loading={fixing}
              icon={<Wrench className="size-4" strokeWidth={2} />}
              aria-describedby="audit-fix-hint"
              onClick={onFixAll}
            >
              {t('audit.fixAuto', { count: automatic })}
            </Button>
            <span id="audit-fix-hint" className="text-[12px] text-subtle">
              {t('audit.fixAutoHint')}
            </span>
          </div>
        ) : null}
      </div>
    </section>
  );
}
