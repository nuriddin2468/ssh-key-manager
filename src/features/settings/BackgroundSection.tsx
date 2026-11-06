import { useQuery } from '@tanstack/react-query';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { Switch } from '@/components/ui/Switch';
import { platform } from '@/lib/platform';

export const backgroundKey = ['background'] as const;

const HINT = {
  macos: 'background.hintMac',
  windows: 'background.hintWindows',
  linux: 'background.hintLinux',
} as const;

/**
 * Running on with the window closed, on the Settings page: the app stays in
 * the tray (the menu bar on macOS), where browser autofill, the user's
 * devices and terminal sessions keep working. Styled like the page's groups.
 */
export function BackgroundSection() {
  const { t } = useTranslation();
  const titleId = useId();
  const switchId = useId();
  const status = useQuery({ queryKey: backgroundKey, queryFn: api.backgroundStatus }).data;
  const toggle = useAppMutation((enabled: boolean) => api.backgroundSetEnabled(enabled));
  if (!status) return null;

  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-2">
      <h2 id={titleId} className="px-1 text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {t('background.title')}
      </h2>
      <div className="glass flex flex-col divide-y divide-white/[0.06] overflow-hidden rounded-2xl">
        <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
          <span className="flex min-w-0 flex-col">
            <span id={`${switchId}-label`} className="font-medium">
              {t('background.enable')}
            </span>
            <span id={`${switchId}-hint`} className="text-[12px] text-subtle">
              {status.available ? t(HINT[platform]) : t('background.unavailable')}
            </span>
          </span>
          <span className="ml-auto flex shrink-0 items-center">
            <Switch
              aria-labelledby={`${switchId}-label`}
              aria-describedby={`${switchId}-hint`}
              checked={status.enabled}
              disabled={!status.available || toggle.isPending}
              onCheckedChange={(enabled) => toggle.mutate(enabled)}
            />
          </span>
        </div>
      </div>
    </section>
  );
}
