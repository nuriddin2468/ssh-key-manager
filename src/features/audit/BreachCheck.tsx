import { useQuery } from '@tanstack/react-query';
import { useEffect, useId, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { queryClient, useVaultStatus } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import type { BreachStatus } from '@/bindings/BreachStatus';
import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Spinner';
import { Switch } from '@/components/ui/Switch';
import { cn } from '@/lib/cn';

export const breachKey = ['breaches'] as const;

/**
 * The breach check (Have I Been Pwned, off by default): polled while a check
 * runs, and the vault's findings are read again when it ends.
 */
export function useBreachStatus(): BreachStatus | undefined {
  const status = useQuery({
    queryKey: breachKey,
    queryFn: api.breachStatus,
    refetchInterval: (query) => (query.state.data?.running ? 1000 : false),
  });
  const running = status.data?.running ?? false;
  const wasRunning = useRef(running);
  useEffect(() => {
    if (wasRunning.current && !running) {
      void queryClient.invalidateQueries({ queryKey: ['vault', 'audit'] });
    }
    wasRunning.current = running;
  }, [running]);
  return status.data;
}

/** Turning the check on or off, and checking every password again. */
export function useBreachActions() {
  const setEnabled = useAppMutation((enabled: boolean) => api.breachSetEnabled(enabled));
  const check = useAppMutation(() => api.breachCheck());
  return { setEnabled, check };
}

/**
 * The breach check's switch, saying exactly what it sends, and while it is
 * on how the last check went. `card` fits the audit's list of checks,
 * `settings` a row of the Settings page.
 */
export function BreachSwitch({ layout }: { layout: 'card' | 'settings' }) {
  const { t } = useTranslation();
  const id = useId();
  const status = useBreachStatus();
  const { setEnabled } = useBreachActions();
  if (!status) return null;
  return (
    <div
      className={cn(
        'flex items-start gap-3',
        layout === 'settings'
          ? 'min-h-[52px] px-4 py-2.5'
          : 'mt-1.5 border-t border-line-soft px-1 pt-3 pb-0.5',
      )}
    >
      <span className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span
          id={`${id}-label`}
          className={cn('font-medium', layout === 'card' && 'text-[12.5px] text-fg')}
        >
          {t('audit.breaches.label')}
        </span>
        <span id={`${id}-hint`} className="text-[12px] text-subtle">
          {t('audit.breaches.hint')}
        </span>
        {status.enabled ? <BreachProgress status={status} /> : null}
      </span>
      <span className="flex shrink-0 items-center pt-0.5">
        <Switch
          aria-labelledby={`${id}-label`}
          aria-describedby={`${id}-hint`}
          checked={status.enabled}
          disabled={setEnabled.isPending}
          onCheckedChange={(enabled) => setEnabled.mutate(enabled)}
        />
      </span>
    </div>
  );
}

/** How the check went, with "Check now"; nothing while the vault is locked. */
function BreachProgress({ status }: { status: BreachStatus }) {
  const { t, i18n } = useTranslation();
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  const { check } = useBreachActions();
  if (!unlocked) return null;

  let text: string;
  let tone = 'text-muted';
  if (status.running) {
    text = t('audit.breaches.checking', { done: status.done, total: status.total });
  } else if (status.error) {
    tone = 'text-warning';
    text = t(`audit.breaches.errors.${status.error}`);
    if (status.done > 0) {
      text += ` ${t('audit.breaches.partial', { done: status.done, total: status.total })}`;
    }
  } else if (status.checkedAt) {
    const time = new Intl.DateTimeFormat(i18n.language, { timeStyle: 'short' }).format(
      new Date(status.checkedAt),
    );
    text = t('audit.breaches.checkedAt', { time });
  } else {
    text = t('audit.breaches.notChecked');
  }

  return (
    <span className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[12px]">
      {status.running ? <Spinner className="size-3.5 text-subtle" /> : null}
      {/* Announced when the check starts, ends or fails, not at every step. */}
      <span className={tone} aria-hidden={status.running || undefined}>
        {text}
      </span>
      <span role="status" className="sr-only">
        {status.running ? t('audit.breaches.checkingShort') : text}
      </span>
      {status.running ? null : (
        <Button
          variant="ghost"
          size="sm"
          className="-my-1 h-[26px] px-2"
          loading={check.isPending}
          onClick={() => check.mutate()}
        >
          {status.error ? t('audit.breaches.tryAgain') : t('audit.breaches.checkNow')}
        </Button>
      )}
    </span>
  );
}

/**
 * The end of the "No passwords in known breaches" row: a way to turn the
 * check on while it is off, a spinner while it runs.
 */
export function BreachCheckAction({ status }: { status: BreachStatus | undefined }) {
  const { t } = useTranslation();
  const { setEnabled } = useBreachActions();
  if (!status) return null;
  if (!status.enabled) {
    return (
      <Button
        variant="ghost"
        size="sm"
        className="-my-1 h-[26px] shrink-0 px-2"
        aria-label={t('audit.breaches.turnOnLabel')}
        loading={setEnabled.isPending}
        onClick={() => setEnabled.mutate(true)}
      >
        {t('audit.breaches.turnOn')}
      </Button>
    );
  }
  if (status.running) return <Spinner className="mt-px size-4 shrink-0 text-subtle" />;
  return null;
}
