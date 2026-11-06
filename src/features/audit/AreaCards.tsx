import {
  CircleCheck,
  FileCog,
  KeyRound,
  LockKeyhole,
  type LucideIcon,
  Network,
  RectangleEllipsis,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { Severity } from '@/bindings/Severity';
import { Tile, type Tone } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { type Area, type AuditItem, CHECKS, type CheckId, SEVERITY_COLORS } from './model';

/** Each area looks like its page in the sidebar. */
export const AREA_LOOK: Record<Area, { tone: Tone; Icon: LucideIcon }> = {
  keys: { tone: 'teal', Icon: KeyRound },
  config: { tone: 'blue', Icon: FileCog },
  hostsFile: { tone: 'indigo', Icon: Network },
  passwords: { tone: 'pink', Icon: RectangleEllipsis },
};

const SEVERITY_TEXT: Record<Severity, string> = {
  critical: 'text-critical',
  warning: 'text-warning',
  info: 'text-info',
};

export type CheckResults = Map<CheckId, { count: number; worst: Severity | null }>;

interface AreaCardsProps {
  areas: Area[];
  results: CheckResults;
  /** The open findings, counted by their own severity. */
  items: readonly AuditItem[];
  /** Checks that didn't run: the vault's while it is locked, the breach check while it is off. */
  notRun: ReadonlySet<CheckId>;
  selected: Area | null;
  onSelect: (area: Area | null) => void;
}

/**
 * One card per area with how its checks went. A card filters the findings
 * below to its area; choosing it again shows them all.
 */
export function AreaCards({ areas, results, items, notRun, selected, onSelect }: AreaCardsProps) {
  const { t } = useTranslation();
  return (
    <fieldset className="m-0 grid min-w-0 grid-cols-[repeat(auto-fit,minmax(200px,1fr))] gap-2.5 border-0 p-0">
      <legend className="sr-only">{t('audit.areasLabel')}</legend>
      {areas.map((area) => {
        const { tone, Icon } = AREA_LOOK[area];
        const checks = CHECKS.filter((check) => check.area === area);
        const ran = checks.filter((check) => !notRun.has(check.id));
        // Only a locked vault keeps a whole area from running.
        const locked = ran.length === 0;
        const failing = ran
          .map((check) => results.get(check.id))
          .filter((result) => result && result.count > 0);
        const passed = ran.length - failing.length;
        const counts = { critical: 0, warning: 0, info: 0 };
        for (const item of items) if (item.area === area) counts[item.severity] += 1;
        const worst = (['critical', 'warning', 'info'] as const).find((s) => counts[s] > 0);
        const pressed = selected === area;
        return (
          <button
            key={area}
            type="button"
            aria-pressed={pressed}
            onClick={() => onSelect(pressed ? null : area)}
            className={cn(
              'pressable-soft flex min-w-0 flex-col gap-3 rounded-2xl border p-3.5 text-left',
              pressed
                ? 'border-[rgb(var(--accent-rgb)/0.45)] bg-[rgb(var(--accent-rgb)/0.1)]'
                : 'border-white/[0.08] bg-white/[0.04] shadow-[inset_0_1px_0_rgb(255_255_255/0.04)] hover:bg-white/[0.06]',
            )}
          >
            <span className="flex w-full items-center gap-2.5">
              <Tile tone={tone} size={30}>
                <Icon className="size-[15px]" strokeWidth={2} />
              </Tile>
              <span className="min-w-0 flex-1 truncate font-semibold">
                {t(`audit.areas.${area}`)}
              </span>
              {locked ? null : (
                <span className="text-[12px] text-subtle tabular-nums">
                  {passed}/{ran.length}
                </span>
              )}
            </span>
            <span
              className={cn(
                'flex items-center gap-1.5 text-[12.5px]',
                locked ? 'text-subtle' : worst ? SEVERITY_TEXT[worst] : 'text-ok',
              )}
            >
              {locked ? (
                <>
                  <LockKeyhole aria-hidden="true" className="size-3.5" strokeWidth={2} />
                  {t('audit.areaLocked')}
                </>
              ) : worst ? (
                [
                  counts.critical ? t('audit.legendCritical', { count: counts.critical }) : null,
                  counts.warning ? t('audit.legendWarning', { count: counts.warning }) : null,
                  counts.info ? t('audit.legendInfo', { count: counts.info }) : null,
                ]
                  .filter(Boolean)
                  .join(' · ')
              ) : (
                <>
                  <CircleCheck aria-hidden="true" className="size-3.5" strokeWidth={2} />
                  {t('audit.areaPassed')}
                </>
              )}
            </span>
            <span aria-hidden="true" className="flex w-full gap-1">
              {checks.map((check) => {
                const worstOfCheck = results.get(check.id)?.worst;
                return (
                  <span
                    key={check.id}
                    className="h-1 flex-1 rounded-full"
                    style={{
                      background: notRun.has(check.id)
                        ? 'rgb(255 255 255 / 0.08)'
                        : worstOfCheck
                          ? SEVERITY_COLORS[worstOfCheck]
                          : 'rgb(94 234 212 / 0.7)',
                    }}
                  />
                );
              })}
            </span>
          </button>
        );
      })}
    </fieldset>
  );
}
