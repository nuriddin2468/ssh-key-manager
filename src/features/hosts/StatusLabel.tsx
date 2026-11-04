import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import type { ConnectionEvent } from '@/bindings/ConnectionEvent';
import { cn } from '@/lib/cn';
import { formatDate, formatDuration, formatRelative } from '@/lib/format';
import { type HostStatus, statusTone } from './status';

const DOT: Record<ReturnType<typeof statusTone>, string> = {
  online: 'bg-online',
  ok: 'bg-ok',
  warning: 'bg-warning-solid',
  error: 'bg-critical-solid',
  busy: 'animate-pulse-dot bg-subtle',
  none: 'border border-faint',
};

const TEXT: Record<ReturnType<typeof statusTone>, string> = {
  online: 'text-online',
  ok: 'text-ok',
  warning: 'text-warning',
  error: 'text-critical',
  busy: 'text-muted',
  none: 'text-subtle',
};

/** The status as a dot and words, and when on a line of its own. */
export function StatusLabel({ status, className }: { status: HostStatus; className?: string }) {
  const { t, i18n } = useTranslation();
  const tone = statusTone(status);
  const event = status.kind === 'last' ? status.event : null;
  const title =
    status.kind === 'last'
      ? t(`hosts.status.outcome.${status.event.outcome}`)
      : status.kind === 'missingKey'
        ? t('hosts.missingKey')
        : t(`hosts.status.${status.kind}`);
  return (
    <span
      className={cn('flex min-w-0 flex-col text-[12px] leading-[18px]', className)}
      title={event ? formatDate(event.at, i18n.language) : undefined}
    >
      <span className={cn('flex min-w-0 items-center gap-1.5 font-medium', TEXT[tone])}>
        <span aria-hidden="true" className={cn('size-[7px] shrink-0 rounded-full', DOT[tone])} />
        <span className="truncate">{title}</span>
      </span>
      {event ? (
        <span className="truncate pl-[13px] text-subtle">{eventWhen(t, i18n.language, event)}</span>
      ) : null}
    </span>
  );
}

/** "Checked 2 hours ago", "Session yesterday, 14 min". */
export function eventWhen(t: TFunction, locale: string, event: ConnectionEvent): string {
  const when = formatRelative(new Date(event.at), locale);
  if (event.via === 'check') return t('hosts.status.checked', { when });
  if (event.durationSecs === undefined) return t('hosts.status.session', { when });
  return t('hosts.status.sessionFor', {
    when,
    duration: formatDuration(event.durationSecs, locale),
  });
}
