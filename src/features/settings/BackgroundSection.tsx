import { useQuery } from '@tanstack/react-query';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import type { AutostartStatus } from '@/bindings/AutostartStatus';
import type { BackgroundStatus } from '@/bindings/BackgroundStatus';
import { Switch } from '@/components/ui/Switch';
import { platform } from '@/lib/platform';

export const backgroundKey = ['background'] as const;
export const autostartKey = ['autostart'] as const;

const HINT = {
  macos: 'background.hintMac',
  windows: 'background.hintWindows',
  linux: 'background.hintLinux',
} as const;

const LOGIN_HINT = {
  macos: 'background.loginHintMac',
  windows: 'background.loginHintWindows',
  linux: 'background.loginHintLinux',
} as const;

/**
 * What opening at login does, or why it can't. Turning it on also keeps the
 * app running in the background, so while it's off it promises the tray;
 * only once it's on with the background turned off again (or no tray at
 * all) does the app open its window at login.
 */
function loginHint(login: AutostartStatus, background: BackgroundStatus) {
  if (login.blocker === 'mounted') return 'background.loginMounted';
  if (login.blocker === 'temporary') return 'background.loginTemporary';
  if (login.turnedOffInSettings) return 'background.loginTurnedOff';
  if (!background.available) return 'background.loginHintNoTray';
  if (login.enabled && !background.enabled) return 'background.loginHintWindow';
  return LOGIN_HINT[platform];
}

/**
 * Running on with the window closed, on the Settings page: the app stays in
 * the tray (the menu bar on macOS), where browser autofill, the user's
 * devices and terminal sessions keep working. And opening at login, straight
 * into the tray. Styled like the page's groups.
 */
export function BackgroundSection() {
  const { t } = useTranslation();
  const titleId = useId();
  const status = useQuery({ queryKey: backgroundKey, queryFn: api.backgroundStatus }).data;
  const login = useQuery({ queryKey: autostartKey, queryFn: api.autostartStatus }).data;
  const toggle = useAppMutation((enabled: boolean) => api.backgroundSetEnabled(enabled));
  const toggleLogin = useAppMutation((enabled: boolean) => api.autostartSetEnabled(enabled));
  if (!status) return null;

  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-2">
      <h2 id={titleId} className="px-1 text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {t('background.title')}
      </h2>
      <div className="glass flex flex-col divide-y divide-white/[0.06] overflow-hidden rounded-2xl">
        <SettingSwitch
          label={t('background.enable')}
          hint={status.available ? t(HINT[platform]) : t('background.unavailable')}
          checked={status.enabled}
          disabled={!status.available}
          busy={toggle.isPending}
          onCheckedChange={(enabled) => toggle.mutate(enabled)}
        />
        {login && (
          <SettingSwitch
            label={t('background.login')}
            hint={t(loginHint(login, status))}
            checked={login.enabled}
            // A copy that can't be opened at login can still turn off an
            // entry another copy left.
            disabled={login.blocker !== null && !login.enabled}
            busy={toggleLogin.isPending}
            onCheckedChange={(enabled) => toggleLogin.mutate(enabled)}
          />
        )}
      </div>
    </section>
  );
}

/**
 * A settings row with a switch. While its change is saved (`busy`) the switch
 * ignores presses but stays enabled: a disabled button would drop the
 * keyboard focus.
 */
function SettingSwitch({
  label,
  hint,
  checked,
  disabled,
  busy,
  onCheckedChange,
}: {
  label: string;
  hint: string;
  checked: boolean;
  disabled: boolean;
  busy: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  const id = useId();
  return (
    <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
      <span className="flex min-w-0 flex-col">
        <span id={`${id}-label`} className="font-medium">
          {label}
        </span>
        <span id={`${id}-hint`} className="text-[12px] text-subtle">
          {hint}
        </span>
      </span>
      <span className="ml-auto flex shrink-0 items-center">
        <Switch
          aria-labelledby={`${id}-label`}
          aria-describedby={`${id}-hint`}
          checked={checked}
          disabled={disabled}
          aria-busy={busy || undefined}
          onCheckedChange={(next) => {
            if (!busy) onCheckedChange(next);
          }}
        />
      </span>
    </div>
  );
}
