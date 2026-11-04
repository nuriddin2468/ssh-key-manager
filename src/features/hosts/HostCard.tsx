import { KeyRound, LockKeyhole, PlugZap, SquareTerminal, Terminal } from 'lucide-react';
import { type MouseEvent, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { useRouter } from '@/app/router';
import type { ConnectionEvent } from '@/bindings/ConnectionEvent';
import type { HostEntry } from '@/bindings/HostEntry';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { useConnect } from '@/features/terminal/connect';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { cn } from '@/lib/cn';
import {
  gitService,
  hostLabel,
  hostMonogram,
  hostTarget,
  isConcrete,
  type SignInMethod,
} from './model';
import { StatusLabel } from './StatusLabel';
import { hostStatus, type LiveTab } from './status';
import { type CheckResult, useHostCheck } from './useHostCheck';
import { hostAliases } from './vault';

interface HostCardProps {
  host: HostEntry;
  method: SignInMethod | null;
  selected: boolean;
  broken: boolean;
  /** The host's checks and sessions, newest first. */
  events: ConnectionEvent[];
  tabs: readonly LiveTab[];
  /** Why Check and Connect can't run, if they can't. */
  blocked: string | null;
  onSelect: () => void;
}

/**
 * A host in the grid: where it stands and the actions for it. The whole card
 * opens the editor; its name is the button for that, for the keyboard.
 */
export function HostCard({
  host,
  method,
  selected,
  broken,
  events,
  tabs,
  blocked,
  onSelect,
}: HostCardProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const connectTo = useConnect();
  const terminals = useTerminals();
  const mono = hostMonogram(host);
  const label = hostLabel(host);
  const aliases = hostAliases(host);
  const concrete = isConcrete(host) && aliases.length > 0;
  const isDefaults = host.kind === 'host' && host.patterns.length === 1 && host.patterns[0] === '*';
  const git = gitService(host);

  // The editor shows the result of its own host; other cards say what failed.
  const onResult = useCallback(
    ({ run }: CheckResult) => {
      if (run.ok || selected) return;
      toast.error(t('hosts.list.checkFailed', { alias: label }), {
        action: { label: t('hosts.list.details'), onClick: onSelect },
      });
    },
    [selected, label, onSelect, t],
  );
  const check = useHostCheck(host, { onResult });
  const status = concrete
    ? hostStatus({ aliases, tabs, checking: check.running, missingKey: broken, events })
    : null;
  const live = status?.kind === 'connected' || status?.kind === 'connecting' ? status : null;

  const stop = (event: MouseEvent) => event.stopPropagation();
  const showSession = (tab: string) => {
    terminals.setActive(tab);
    navigate({ page: 'terminal' });
  };

  const target = isDefaults
    ? t('hosts.appliesToAll')
    : broken && !concrete
      ? t('hosts.missingKey')
      : hostTarget(host, (jump) => t('hosts.via', { jump }));
  const checkIcon = check.running ? (
    <Spinner className="size-3.5" />
  ) : (
    <PlugZap className="size-[15px]" strokeWidth={1.9} />
  );

  return (
    // The card is a mouse target only; its name button and actions serve the keyboard.
    // biome-ignore lint/a11y/useKeyWithClickEvents: the name button opens it from the keyboard
    <li
      onClick={onSelect}
      // Moves between the grid and the column as the editor opens and closes.
      style={{ viewTransitionName: `host-card-${host.id}` }}
      className={cn(
        // `relative`: screen-reader text inside stays in the card, so the scrolling list clips it.
        'glass pressable-soft relative flex min-w-0 flex-col gap-3 rounded-2xl p-3.5 active:bg-white/[0.06]',
        selected ? 'selected-row' : 'hover:bg-white/[0.06]',
      )}
    >
      <div className="flex items-start gap-[11px]">
        <Tile tone={mono.tone} size={36}>
          <span className="font-mono text-[12.5px] font-semibold">{mono.text}</span>
        </Tile>
        <button
          type="button"
          data-host={host.id}
          aria-current={selected ? 'true' : undefined}
          onClick={(event) => {
            stop(event);
            onSelect();
          }}
          title={target}
          className="flex min-w-0 flex-1 flex-col rounded-md text-left"
        >
          <span className="flex items-center gap-1.5">
            <span className="truncate font-mono text-[13.5px] font-medium">{label}</span>
            {isDefaults ? (
              <Badge pill className="text-fg-2">
                {t('hosts.defaults')}
              </Badge>
            ) : null}
          </span>
          <span className="truncate text-[12px] leading-[18px] text-subtle">{target}</span>
        </button>
        {method ? <MethodIcons method={method} /> : null}
      </div>

      {status ? <StatusLabel status={status} className="min-h-9" /> : null}

      {concrete ? (
        // biome-ignore lint/a11y/noStaticElementInteractions: keeps the card's click off the buttons
        // biome-ignore lint/a11y/useKeyWithClickEvents: only stops the card's click
        <div className="mt-auto flex items-center gap-1.5" onClick={stop}>
          {git ? (
            <Button
              size="sm"
              className="flex-1"
              icon={checkIcon}
              aria-busy={check.running || undefined}
              disabled={blocked !== null}
              title={blocked ?? undefined}
              onClick={check.run}
            >
              {t('hosts.list.check')}
            </Button>
          ) : (
            <>
              <IconButton
                label={t('hosts.list.checkLabel', { alias: label })}
                tooltip={blocked ?? undefined}
                variant="secondary"
                aria-busy={check.running || undefined}
                disabled={blocked !== null}
                icon={checkIcon}
                onClick={check.run}
              />
              {live ? (
                <Button
                  size="sm"
                  className="flex-1"
                  aria-label={t('hosts.list.showLabel', { alias: label })}
                  icon={<SquareTerminal className="size-3.5" strokeWidth={2} />}
                  onClick={() => showSession(live.tab)}
                >
                  {t('hosts.list.show')}
                </Button>
              ) : (
                <Button
                  size="sm"
                  className="flex-1"
                  aria-label={t('hosts.list.connectLabel', { alias: label })}
                  icon={<Terminal className="size-3.5" strokeWidth={2.2} />}
                  disabled={blocked !== null}
                  title={blocked ?? undefined}
                  onClick={() => connectTo(check.alias)}
                >
                  {t('hosts.list.connect')}
                </Button>
              )}
            </>
          )}
        </div>
      ) : null}
      {check.dialog}
    </li>
  );
}

/** The sign-in method as small icons: a key, a lock, or both. */
function MethodIcons({ method }: { method: SignInMethod }) {
  const { t } = useTranslation();
  const label = t('hosts.signIn.listLabel', { method: t(`hosts.signIn.${method}`) });
  return (
    <span title={label} className="mt-0.5 flex shrink-0 items-center gap-1 text-subtle">
      {method !== 'password' ? (
        <KeyRound aria-hidden="true" className="size-3.5" strokeWidth={1.9} />
      ) : null}
      {method !== 'key' ? (
        <LockKeyhole aria-hidden="true" className="size-3.5" strokeWidth={1.9} />
      ) : null}
      <span className="sr-only">{label}</span>
    </span>
  );
}
