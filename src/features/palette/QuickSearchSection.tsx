import { useQuery } from '@tanstack/react-query';
import { type KeyboardEvent, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { Kbd } from '@/components/ui/Kbd';
import { Switch } from '@/components/ui/Switch';
import { platform } from '@/lib/platform';
import { acceleratorOf, formatAccelerator, hasCommandKey, shortcutLabel } from './shortcut';

export const quickKey = ['quick'] as const;

const NEEDS_MODIFIER = {
  macos: 'palette.settings.needsModifierMac',
  windows: 'palette.settings.needsModifierWindows',
  linux: 'palette.settings.needsModifierLinux',
} as const;

/**
 * Quick search on the Settings page: the system-wide shortcut that opens
 * it, on or off, and which keys. Styled like the page's groups.
 */
export function QuickSearchSection() {
  const { t } = useTranslation();
  const titleId = useId();
  const switchId = useId();
  const shortcutId = useId();
  const status = useQuery({ queryKey: quickKey, queryFn: api.quickStatus }).data;
  const set = useAppMutation((vars: { enabled: boolean; shortcut: string | null }) =>
    api.quickSetShortcut(vars.enabled, vars.shortcut),
  );
  const [recording, setRecording] = useState(false);
  const [needsModifier, setNeedsModifier] = useState(false);
  if (!status) return null;

  const shown = formatAccelerator(status.shortcut, platform);
  const stop = () => {
    setRecording(false);
    setNeedsModifier(false);
  };
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    // The keys are the shortcut's, not the page's or the app's.
    event.preventDefault();
    event.stopPropagation();
    const plain = !event.ctrlKey && !event.altKey && !event.metaKey && !event.shiftKey;
    if (plain && event.key === 'Escape') {
      stop();
      return;
    }
    const accelerator = acceleratorOf(event.nativeEvent);
    if (!accelerator) return;
    if (!hasCommandKey(accelerator)) {
      setNeedsModifier(true);
      return;
    }
    stop();
    if (accelerator !== status.shortcut) {
      set.mutate({ enabled: true, shortcut: accelerator });
    }
  };

  const problem = needsModifier
    ? t(NEEDS_MODIFIER[platform])
    : status.enabled && !status.registered && !recording
      ? t('palette.settings.taken', { shortcut: shown })
      : null;

  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-2">
      <h2 id={titleId} className="px-1 text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {t('palette.settings.title')}
      </h2>
      <div className="glass flex flex-col divide-y divide-line-soft overflow-hidden rounded-2xl">
        <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
          <span className="flex min-w-0 flex-col">
            <span id={`${switchId}-label`} className="font-medium">
              {t('palette.settings.enable')}
            </span>
            <span id={`${switchId}-hint`} className="text-[12px] text-subtle">
              {t('palette.settings.hint')}
              {platform === 'linux' ? ` ${t('palette.settings.wayland')}` : null}
            </span>
          </span>
          <span className="ml-auto flex shrink-0 items-center">
            <Switch
              aria-labelledby={`${switchId}-label`}
              aria-describedby={`${switchId}-hint`}
              checked={status.enabled}
              disabled={set.isPending}
              onCheckedChange={(enabled) => set.mutate({ enabled, shortcut: status.shortcut })}
            />
          </span>
        </div>
        {status.enabled ? (
          <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
            <span className="flex min-w-0 flex-col">
              <span id={`${shortcutId}-label`} className="font-medium">
                {t('palette.settings.shortcut')}
              </span>
              {problem ? (
                <span
                  id={`${shortcutId}-problem`}
                  role="alert"
                  className="text-[12px] text-critical"
                >
                  {problem}
                </span>
              ) : recording ? (
                <span id={`${shortcutId}-problem`} className="text-[12px] text-subtle">
                  {t('palette.settings.cancelRecording')}
                </span>
              ) : null}
            </span>
            <span className="ml-auto flex shrink-0 items-center gap-2">
              {status.shortcut !== status.defaultShortcut && !recording ? (
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={set.isPending}
                  onClick={() => set.mutate({ enabled: true, shortcut: null })}
                >
                  {t('palette.settings.reset')}
                </Button>
              ) : null}
              {recording ? (
                <Button
                  size="sm"
                  variant="soft"
                  // The keys pressed here become the shortcut.
                  autoFocus
                  aria-describedby={`${shortcutId}-problem`}
                  onKeyDown={onKeyDown}
                  onBlur={stop}
                  onClick={stop}
                  className="min-w-[180px] justify-center"
                >
                  {t('palette.settings.recording')}
                </Button>
              ) : (
                <>
                  <Kbd className="px-2 text-[12px] leading-[22px] text-fg-2">{shown}</Kbd>
                  <Button
                    size="sm"
                    aria-label={`${t('palette.settings.change')}: ${t('palette.settings.shortcut')} ${shown}`}
                    aria-describedby={problem ? `${shortcutId}-problem` : undefined}
                    loading={set.isPending}
                    onClick={() => setRecording(true)}
                  >
                    {t('palette.settings.change')}
                  </Button>
                </>
              )}
            </span>
          </div>
        ) : null}
      </div>
      <p className="px-1 text-[12px] text-subtle">
        {t('palette.settings.palette', { shortcut: shortcutLabel('K') })}
      </p>
    </section>
  );
}
