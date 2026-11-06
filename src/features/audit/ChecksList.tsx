import { ChevronRight, CircleAlert, CircleCheck, CircleDashed } from 'lucide-react';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { AREA_LOOK, type CheckResults } from './AreaCards';
import { type Area, CHECKS } from './model';

const SEVERITY_TEXT = {
  critical: 'text-critical',
  warning: 'text-warning',
  info: 'text-info',
} as const;

interface ChecksListProps {
  areas: Area[];
  results: CheckResults;
  /** The vault is locked: its checks didn't run. */
  locked: boolean;
  passed: number;
  total: number;
  open: boolean;
  onToggle: () => void;
}

/**
 * Every check the audit runs, by area, and how it went: so a clean result
 * says what was looked at, and a finding where it belongs.
 */
export function ChecksList({
  areas,
  results,
  locked,
  passed,
  total,
  open,
  onToggle,
}: ChecksListProps) {
  const { t } = useTranslation();
  const listId = useId();
  return (
    <section aria-labelledby={`${listId}-h`} className="flex flex-col gap-2.5">
      <h2 id={`${listId}-h`} className="text-[14px] leading-5 font-semibold">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={listId}
          onClick={onToggle}
          className="pressable -ml-1.5 inline-flex items-center gap-1.5 rounded-lg px-1.5 py-1 hover:bg-white/[0.05]"
        >
          <ChevronRight
            aria-hidden="true"
            className={cn('size-4 text-subtle transition-transform', open && 'rotate-90')}
            strokeWidth={2}
          />
          {t('audit.checksTitle')}
          <span className="ml-1 text-[12.5px] font-normal text-subtle">
            {t('audit.checksPassed', { passed, total })}
          </span>
        </button>
      </h2>
      {open ? (
        <div id={listId} className="grid grid-cols-[repeat(auto-fit,minmax(320px,1fr))] gap-2.5">
          {areas.map((area) => {
            const { tone, Icon } = AREA_LOOK[area];
            const notRun = area === 'passwords' && locked;
            return (
              <div key={area} className="glass flex flex-col gap-1 rounded-2xl p-3">
                <h3 className="flex items-center gap-2 px-1 pb-1 text-[12.5px] font-semibold text-fg-2">
                  <Tile tone={tone} size={22}>
                    <Icon className="size-3" strokeWidth={2.25} />
                  </Tile>
                  {t(`audit.areas.${area}`)}
                  {notRun ? (
                    <span className="ml-auto text-[12px] font-normal text-subtle">
                      {t('audit.checkNotRun')}
                    </span>
                  ) : null}
                </h3>
                <ul className="flex flex-col">
                  {CHECKS.filter((check) => check.area === area).map((check) => {
                    const result = results.get(check.id);
                    const worst = notRun ? null : (result?.worst ?? null);
                    const StatusIcon = notRun ? CircleDashed : worst ? CircleAlert : CircleCheck;
                    return (
                      <li
                        key={check.id}
                        className="flex items-start gap-2.5 rounded-lg px-1 py-[5px] text-[12.5px] leading-[18px]"
                      >
                        <StatusIcon
                          aria-hidden="true"
                          className={cn(
                            'mt-px size-4 shrink-0',
                            notRun ? 'text-faint' : worst ? SEVERITY_TEXT[worst] : 'text-ok',
                          )}
                          strokeWidth={2}
                        />
                        <span className={cn('flex-1', notRun ? 'text-subtle' : 'text-fg-2')}>
                          {t(`audit.checks.${check.id}`)}
                        </span>
                        {notRun ? null : worst ? (
                          <span
                            className={cn(
                              'shrink-0 text-[12px] tabular-nums',
                              SEVERITY_TEXT[worst],
                            )}
                          >
                            {t('audit.checkFound', { count: result?.count ?? 0 })}
                          </span>
                        ) : (
                          <span className="sr-only">{t('audit.checkPassed')}</span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              </div>
            );
          })}
        </div>
      ) : null}
    </section>
  );
}
