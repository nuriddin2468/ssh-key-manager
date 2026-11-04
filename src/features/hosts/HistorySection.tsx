import { PlugZap, Terminal } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useConnectionHistory } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/cn';
import { formatDate } from '@/lib/format';
import { eventWhen } from './StatusLabel';
import { hostEvents, outcomeTone } from './status';

/** Events shown before "Show all". */
const SHOWN = 4;

const DOT = { ok: 'bg-ok', warning: 'bg-warning-solid', error: 'bg-critical-solid' } as const;

/** The host's last checks and terminal sessions, kept on this computer. */
export function HistorySection({ aliases }: { aliases: readonly string[] }) {
  const { t, i18n } = useTranslation();
  const history = useConnectionHistory();
  const [all, setAll] = useState(false);
  const events = hostEvents(history.data, aliases);
  // Success refreshes every query, the history's too.
  const clear = useAppMutation(
    async (_: undefined) => {
      for (const alias of aliases) await api.clearConnectionHistory(alias);
    },
    { success: () => t('hosts.history.cleared') },
  );
  const shown = all ? events : events.slice(0, SHOWN);

  return (
    <section aria-labelledby="host-history-title" className="flex min-w-0 flex-col">
      <div className="mb-2 flex items-center gap-2">
        <h3
          id="host-history-title"
          className="text-[12px] font-semibold tracking-[0.02em] text-subtle"
        >
          {t('hosts.history.title')}
        </h3>
        <span className="flex-1" />
        {events.length > 0 ? (
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-[12px] text-subtle"
            loading={clear.isPending}
            onClick={() => clear.mutate(undefined)}
          >
            {t('hosts.history.clear')}
          </Button>
        ) : null}
      </div>
      {events.length === 0 ? (
        <p className="rounded-xl border border-dashed border-white/[0.09] px-3 py-3 text-[12.5px] text-subtle">
          {t('hosts.history.empty')}
        </p>
      ) : (
        <ol className="flex flex-col overflow-hidden rounded-xl border border-white/[0.07]">
          {shown.map((event) => {
            const Icon = event.via === 'check' ? PlugZap : Terminal;
            return (
              <li
                key={`${event.via}-${event.at}`}
                className="flex items-center gap-2.5 border-white/[0.06] px-3 py-2 not-last:border-b"
              >
                <span
                  aria-hidden="true"
                  className={cn(
                    'size-[7px] shrink-0 rounded-full',
                    DOT[outcomeTone(event.outcome)],
                  )}
                />
                <span className="min-w-0 flex-1 truncate text-[12.5px]">
                  {t(`hosts.history.outcome.${event.outcome}`)}
                </span>
                <span
                  className="flex shrink-0 items-center gap-1.5 text-[12px] text-subtle"
                  title={formatDate(event.at, i18n.language)}
                >
                  <Icon aria-hidden="true" className="size-3.5" strokeWidth={1.9} />
                  {eventWhen(t, i18n.language, event)}
                </span>
              </li>
            );
          })}
        </ol>
      )}
      {events.length > SHOWN ? (
        <Button
          variant="ghost"
          size="sm"
          className="mt-1 self-start px-2 text-[12px] text-subtle"
          aria-expanded={all}
          onClick={() => setAll((value) => !value)}
        >
          {all
            ? t('hosts.history.showFewer')
            : t('hosts.history.showAll', { count: events.length })}
        </Button>
      ) : null}
      <p className="mt-2 text-[12px] leading-[18px] text-subtle">{t('hosts.history.privacy')}</p>
    </section>
  );
}
