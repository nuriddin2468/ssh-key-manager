import { AlertOctagon, AlertTriangle, Info } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { Severity } from '@/bindings/Severity';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/cn';

const SEVERITY_STYLE = {
  critical: {
    tile: 'border-critical-solid/30 bg-critical-solid/12 text-critical',
    Icon: AlertOctagon,
    label: 'audit.severityCritical',
  },
  warning: {
    tile: 'border-warning-solid/30 bg-warning-solid/11 text-warning',
    Icon: AlertTriangle,
    label: 'audit.severityWarning',
  },
  info: {
    tile: 'border-info-solid/30 bg-info-solid/11 text-info',
    Icon: Info,
    label: 'audit.severityInfo',
  },
} as const;

interface FindingRowProps {
  severity: Severity;
  title: string;
  text: string;
  /** What it is about: a key name, `Host x`, an entry title. */
  subject: string;
  /** The fix or "open" button. */
  actionLabel?: string;
  muted?: boolean;
  busy?: boolean;
  onAction?: () => void;
  onIgnore?: () => void;
  onRestore?: () => void;
}

/** One audit finding: severity, what and where, and what to do about it. */
export function FindingRow({
  severity,
  title,
  text,
  subject,
  actionLabel,
  muted,
  busy,
  onAction,
  onIgnore,
  onRestore,
}: FindingRowProps) {
  const { t } = useTranslation();
  const style = SEVERITY_STYLE[severity];
  return (
    <div
      className={cn(
        'glass flex flex-wrap items-center gap-x-3.5 gap-y-3 rounded-2xl px-4 py-[13px]',
        muted && 'opacity-60',
      )}
    >
      <span
        className={cn('grid size-9 shrink-0 place-items-center rounded-[11px] border', style.tile)}
      >
        <style.Icon aria-hidden="true" className="size-[17px]" strokeWidth={2} />
      </span>
      <span className="flex min-w-[300px] flex-1 flex-col gap-0.5">
        <span className="flex flex-wrap items-center gap-2">
          <span className="font-semibold">{title}</span>
          {subject ? (
            <span className="inline-flex h-5 items-center rounded-md border border-white/10 bg-white/[0.06] px-[7px] font-mono text-[11.5px] text-fg-2">
              {subject}
            </span>
          ) : null}
          <span className={cn('text-[11.5px] font-semibold', style.tile.split(' ').pop())}>
            {t(style.label)}
          </span>
        </span>
        <span className="text-[12.5px] text-muted">{text}</span>
      </span>
      <span className="flex shrink-0 flex-wrap gap-1.5">
        {onRestore ? (
          <Button size="sm" onClick={onRestore}>
            {t('audit.restore')}
          </Button>
        ) : (
          <>
            <Button variant="ghost" size="sm" className="text-subtle" onClick={onIgnore}>
              {t('audit.ignore')}
            </Button>
            {actionLabel ? (
              <Button size="sm" loading={busy} onClick={onAction}>
                {actionLabel}
              </Button>
            ) : null}
          </>
        )}
      </span>
    </div>
  );
}
