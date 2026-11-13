import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { Switch } from '@/components/ui/Switch';
import { useShellHistoryStatus } from '@/features/hosts/shellHistory';

/**
 * Suggesting hosts from the shell history, on the Settings page: on or off,
 * and bringing back dismissed suggestions. Styled like the page's groups.
 */
export function ShellHistorySection() {
  const { t } = useTranslation();
  const titleId = useId();
  const switchId = useId();
  const status = useShellHistoryStatus().data;
  const toggle = useAppMutation((enabled: boolean) => api.shellHistorySetEnabled(enabled));
  const restore = useAppMutation(() => api.shellHistoryForgetDismissed(), {
    success: () => t('historyHosts.restored'),
  });
  if (!status) return null;

  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-2">
      <h2 id={titleId} className="px-1 text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {t('historyHosts.settingsTitle')}
      </h2>
      <div className="glass flex flex-col divide-y divide-line-soft overflow-hidden rounded-2xl">
        <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
          <span className="flex min-w-0 flex-col">
            <span id={`${switchId}-label`} className="font-medium">
              {t('historyHosts.enable')}
            </span>
            <span id={`${switchId}-hint`} className="text-[12px] text-subtle">
              {t('historyHosts.enableHint')}
            </span>
          </span>
          <span className="ml-auto flex shrink-0 items-center">
            <Switch
              aria-labelledby={`${switchId}-label`}
              aria-describedby={`${switchId}-hint`}
              checked={status.consent === 'on'}
              disabled={toggle.isPending}
              onCheckedChange={(enabled) => toggle.mutate(enabled)}
            />
          </span>
        </div>
        {status.dismissed > 0 ? (
          <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
            <span className="flex min-w-0 flex-col">
              <span className="font-medium">{t('historyHosts.dismissedTitle')}</span>
              <span className="text-[12px] text-subtle">
                {t('historyHosts.dismissedCount', { count: status.dismissed })}
              </span>
            </span>
            <Button
              size="sm"
              variant="secondary"
              className="ml-auto"
              loading={restore.isPending}
              onClick={() => restore.mutate(undefined)}
            >
              {t('historyHosts.restore')}
            </Button>
          </div>
        ) : null}
      </div>
    </section>
  );
}
