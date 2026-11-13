import { isTauri } from '@tauri-apps/api/core';
import { revealItemInDir } from '@tauri-apps/plugin-opener';
import { Clock, FolderOpen, KeyRound, Monitor, Moon, Sun } from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useEnvironment } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import { Logo } from '@/components/Logo';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { Dialog } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { Tile, type Tone } from '@/components/ui/Tile';
import { LifetimeSelect } from '@/features/agent/LifetimeSelect';
import { BreachSwitch } from '@/features/audit/BreachCheck';
import { BrowserAutofillSection } from '@/features/browser/BrowserAutofillSection';
import { QuickSearchSection } from '@/features/palette/QuickSearchSection';
import { METHOD_NAME } from '@/features/passwords/device';
import { VaultLocationSection } from '@/features/passwords/files';
import { AUTO_LOCK_MINUTES, CLIPBOARD_SECONDS } from '@/features/passwords/model';
import {
  ChangeMasterDialog,
  DeviceUnlockDialog,
  NewRecoveryKeyDialog,
} from '@/features/passwords/SecurityDialogs';
import { useVaultSettings } from '@/features/passwords/useVaultSettings';
import { useVaultMutation } from '@/features/passwords/vault';
import { shellDetail, shellName, useShells } from '@/features/terminal/shells';
import { LANGUAGE_NAMES, LANGUAGES, type Language, setLanguage, storedLanguage } from '@/i18n';
import { displayPath } from '@/lib/format';
import { fileManagerName } from '@/lib/platform';
import { showReleaseNotes } from '@/lib/releaseNotes';
import { type Settings, updateSettings, useSettings } from '@/lib/settings';
import { APPEARANCES, type Appearance } from '@/lib/theme';
import { checkForUpdates, showUpdateNotes, useUpdateState } from '@/lib/updater';
import { BackgroundSection } from './BackgroundSection';
import { ShellHistorySection } from './ShellHistorySection';

const THEME_LABEL = {
  system: 'settings.themeSystem',
  light: 'settings.themeLight',
  dark: 'settings.themeDark',
} as const satisfies Record<Appearance, string>;

const THEME_ICON: Record<Appearance, ReactNode> = {
  system: <Monitor aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />,
  light: <Sun aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />,
  dark: <Moon aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />,
};

export function SettingsPage() {
  const { t } = useTranslation();
  const settings = useSettings();
  const environment = useEnvironment();
  const env = environment.data;
  const home = env?.paths.home;

  const reveal = async (path: string) => {
    if (!isTauri()) return;
    try {
      await revealItemInDir(path);
    } catch (error) {
      toastError(t, error);
    }
  };

  const files = env
    ? [
        { label: t('settings.sshDir'), path: env.paths.dir },
        { label: t('settings.config'), path: env.paths.config },
        { label: t('settings.knownHosts'), path: env.paths.knownHosts },
        { label: t('settings.hostsFile'), path: env.hostsFile },
        { label: t('settings.backups'), path: env.backupDir },
      ]
    : [];

  return (
    <>
      <Toolbar title={t('settings.title')} />
      <PageBody>
        {/* The width cap sits inside the scroll area, so the scrollbar stays at the window's edge. */}
        <div className="flex w-full max-w-[760px] flex-col gap-5">
          <Group title={t('settings.language')}>
            <Row label={t('settings.language')}>
              <Select
                aria-label={t('settings.language')}
                size="sm"
                className="w-[220px]"
                value={storedLanguage() ?? 'system'}
                onValueChange={(next) => setLanguage(next === 'system' ? null : (next as Language))}
                options={[
                  { value: 'system', label: t('settings.languageSystem') },
                  ...LANGUAGES.map((language) => ({
                    value: language,
                    label: LANGUAGE_NAMES[language],
                    hint: language.toUpperCase(),
                  })),
                ]}
              />
            </Row>
          </Group>

          <Group title={t('settings.appearance')}>
            <Row label={t('settings.theme')}>
              <Select
                aria-label={t('settings.theme')}
                size="sm"
                className="w-[220px]"
                value={settings.appearance}
                onValueChange={(next) => updateSettings({ appearance: next as Appearance })}
                options={APPEARANCES.map((appearance) => ({
                  value: appearance,
                  label: t(THEME_LABEL[appearance]),
                  icon: THEME_ICON[appearance],
                }))}
              />
            </Row>
          </Group>

          <Group title={t('settings.defaults')}>
            <Row label={t('settings.defaultAlgorithm')}>
              <Select
                aria-label={t('settings.defaultAlgorithm')}
                size="sm"
                className="w-[220px]"
                value={settings.defaultAlgorithm}
                onValueChange={(next) =>
                  updateSettings({ defaultAlgorithm: next as Settings['defaultAlgorithm'] })
                }
                options={[
                  { value: 'ed25519', label: 'Ed25519', icon: algorithmTile('teal') },
                  { value: 'rsa', label: 'RSA', icon: algorithmTile('amber') },
                  { value: 'ecdsa', label: 'ECDSA', icon: algorithmTile('blue') },
                ]}
              />
            </Row>
            <Row label={t('settings.defaultLifetime')}>
              <div className="w-[220px]">
                <LifetimeSelect
                  size="sm"
                  value={settings.defaultLifetime}
                  onChange={(value) => updateSettings({ defaultLifetime: value })}
                />
              </div>
            </Row>
          </Group>

          <TerminalGroup />
          <ShellHistorySection />
          <PasswordsGroup />
          <VaultLocationSection />
          <BackgroundSection />
          <QuickSearchSection />
          <BrowserAutofillSection />

          <Group title={t('settings.folders')}>
            {files.map((file) => (
              <Row key={file.label} label={file.label}>
                <span className="selectable min-w-0 flex-1 truncate text-right font-mono text-[12px] text-muted">
                  {displayPath(file.path, home)}
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<FolderOpen className="size-[15px]" strokeWidth={1.75} />}
                  onClick={() => void reveal(file.path)}
                >
                  {t('keys.showIn', { app: fileManagerName })}
                </Button>
              </Row>
            ))}
          </Group>

          <Group title={t('updates.title')}>
            <Row label={t('updates.automatic')}>
              <Switch
                aria-label={t('updates.automatic')}
                checked={settings.autoUpdate}
                onCheckedChange={(autoUpdate) => updateSettings({ autoUpdate })}
              />
            </Row>
            <UpdateRow />
            <Row label={t('updates.history')}>
              <Button size="sm" onClick={() => showReleaseNotes({ kind: 'history' })}>
                {t('updates.whatsNew')}
              </Button>
            </Row>
          </Group>

          <Group title={t('settings.about')}>
            <div className="flex items-center gap-4 px-4 py-4">
              <Logo size={52} />
              <div className="flex flex-col gap-0.5">
                <span className="text-[15px] font-semibold">{t('app.name')}</span>
                <span className="text-[12.5px] text-muted">
                  {env ? t('settings.version', { version: env.appVersion }) : ''}
                  {' · '}
                  {t('settings.openssh')}: {env?.opensshVersion ?? t('settings.opensshMissing')}
                </span>
                <span className="text-[12px] text-subtle">{t('settings.license')}</span>
              </div>
            </div>
          </Group>
        </div>
      </PageBody>
    </>
  );
}

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h2 className="px-1 text-[12px] font-semibold tracking-[0.02em] text-subtle">{title}</h2>
      <div className="glass flex flex-col divide-y divide-line-soft overflow-hidden rounded-2xl">
        {children}
      </div>
    </section>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
      <span className="shrink-0 font-medium">{label}</span>
      <span className="ml-auto flex min-w-0 items-center justify-end gap-2">{children}</span>
    </div>
  );
}

/**
 * The shell local sessions open in: in the Terminal and with an
 * environment's "Run in terminal". A chosen shell that is gone shows (and
 * opens) as the system's.
 */
function TerminalGroup() {
  const { t } = useTranslation();
  const settings = useSettings();
  const shells = useShells().data;
  if (!shells || shells.length === 0) return null;
  const system = shells.find((shell) => shell.default);
  const chosen = shells.some((shell) => shell.id === settings.defaultShell)
    ? (settings.defaultShell as string)
    : 'system';

  return (
    <Group title={t('settings.terminal')}>
      <Row label={t('settings.defaultShell')}>
        <Select
          aria-label={t('settings.defaultShell')}
          size="sm"
          className="w-[220px]"
          value={chosen}
          onValueChange={(next) =>
            updateSettings({ defaultShell: next === 'system' ? null : next })
          }
          options={[
            {
              value: 'system',
              label: t('settings.shellSystem'),
              hint: system ? shellName(t, system) : undefined,
            },
            ...shells.map((shell) => ({
              value: shell.id,
              label: shellName(t, shell),
              hint: shellDetail(shell, shells) ?? undefined,
            })),
          ]}
        />
      </Row>
    </Group>
  );
}

/** The vault's preferences, its master password and recovery key, and its file. */
function PasswordsGroup() {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const { status, settings, update } = useVaultSettings();
  const [dialog, setDialog] = useState<'master' | 'recovery' | 'device' | null>(null);
  const unlockKeysId = useId();
  const deviceId = useId();
  const kind = status?.device.kind ?? null;
  const disableDevice = useVaultMutation(api.vaultDisableDevice, {
    success: () => (kind ? t('passwords.deviceOff', { method: METHOD_NAME[kind] }) : undefined),
  });
  if (!status || !settings) return null;

  const clock = <Clock aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />;
  const switches = [
    { key: 'lockOnSleep', label: t('passwords.lockOnSleep') },
    { key: 'lockOnScreenLock', label: t('passwords.lockOnScreenLock') },
    { key: 'lockOnMinimize', label: t('passwords.lockOnMinimize') },
  ] as const;

  return (
    <Group title={t('passwords.settingsTitle')}>
      <Row label={t('passwords.autoLock')}>
        <Select
          aria-label={t('passwords.autoLock')}
          size="sm"
          className="w-[220px]"
          value={String(settings.autoLockMinutes ?? 'never')}
          onValueChange={(next) =>
            update({ autoLockMinutes: next === 'never' ? null : Number(next) })
          }
          options={AUTO_LOCK_MINUTES.map((minutes) => ({
            value: String(minutes ?? 'never'),
            icon: clock,
            label:
              minutes === null
                ? t('passwords.lockNever')
                : minutes === 60
                  ? t('passwords.lockHour')
                  : t('passwords.lockMinutes', { count: minutes }),
          }))}
        />
      </Row>
      <Row label={t('passwords.clearClipboard')}>
        <Select
          aria-label={t('passwords.clearClipboard')}
          size="sm"
          className="w-[220px]"
          value={String(settings.clipboardSeconds)}
          onValueChange={(next) => update({ clipboardSeconds: Number(next) })}
          options={CLIPBOARD_SECONDS.map((seconds) => ({
            value: String(seconds),
            icon: clock,
            label:
              seconds === 0
                ? t('passwords.clearNever')
                : t('passwords.clearSeconds', { count: seconds }),
          }))}
        />
      </Row>
      {switches.map(({ key, label }) => (
        <Row key={key} label={label}>
          <Switch
            aria-label={label}
            checked={settings[key]}
            onCheckedChange={(checked) => update({ [key]: checked })}
          />
        </Row>
      ))}
      <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
        <span className="flex min-w-0 flex-col">
          <span id={`${unlockKeysId}-label`} className="font-medium">
            {t('passwords.unlockKeys')}
          </span>
          <span id={`${unlockKeysId}-hint`} className="text-[12px] text-subtle">
            {t('passwords.unlockKeysHint')}
          </span>
        </span>
        <span className="ml-auto flex shrink-0 items-center">
          <Switch
            aria-labelledby={`${unlockKeysId}-label`}
            aria-describedby={`${unlockKeysId}-hint`}
            checked={settings.unlockKeysOnOpen}
            onCheckedChange={(unlockKeysOnOpen) => update({ unlockKeysOnOpen })}
          />
        </span>
      </div>
      <BreachSwitch layout="settings" />

      {kind ? (
        <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
          <span className="flex min-w-0 flex-col">
            <span id={`${deviceId}-label`} className="font-medium">
              {t('passwords.unlockWithDevice', { method: METHOD_NAME[kind] })}
            </span>
            <span id={`${deviceId}-hint`} className="text-[12px] text-subtle">
              {t('passwords.deviceHint')}
            </span>
          </span>
          <span className="ml-auto flex shrink-0 items-center">
            <Switch
              aria-labelledby={`${deviceId}-label`}
              aria-describedby={`${deviceId}-hint`}
              checked={status.device.enabled}
              disabled={status.state !== 'unlocked' || disableDevice.isPending}
              onCheckedChange={(on) => (on ? setDialog('device') : disableDevice.mutate(undefined))}
            />
          </span>
        </div>
      ) : null}

      {status.state === 'unlocked' ? (
        <>
          <Row label={t('passwords.changeMaster')}>
            <Button size="sm" onClick={() => setDialog('master')}>
              {t('passwords.changeMasterButton')}
            </Button>
          </Row>
          <Row label={t('passwords.newRecoveryKey')}>
            <Button size="sm" onClick={() => setDialog('recovery')}>
              {t('passwords.newRecoveryButton')}
            </Button>
          </Row>
        </>
      ) : (
        <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
          <span className="min-w-0 text-[12.5px] text-muted">
            {status.state === 'locked' ? t('passwords.unlockForSecurity') : t('passwords.noVault')}
          </span>
          {status.state === 'locked' ? (
            <Button
              size="sm"
              className="ml-auto"
              onClick={() => dialogs.unlockVault({ description: t('passwords.unlockForSecurity') })}
            >
              {t('passwords.unlock')}
            </Button>
          ) : (
            <Button size="sm" className="ml-auto" onClick={() => navigate({ page: 'passwords' })}>
              {t('passwords.openPasswords')}
            </Button>
          )}
        </div>
      )}

      <Dialog open={dialog !== null} onOpenChange={(open) => (open ? undefined : setDialog(null))}>
        {dialog === 'master' ? <ChangeMasterDialog onDone={() => setDialog(null)} /> : null}
        {dialog === 'recovery' ? <NewRecoveryKeyDialog onDone={() => setDialog(null)} /> : null}
        {dialog === 'device' && kind ? (
          <DeviceUnlockDialog kind={kind} onDone={() => setDialog(null)} />
        ) : null}
      </Dialog>
    </Group>
  );
}

function UpdateRow() {
  const { t } = useTranslation();
  const update = useUpdateState();

  let status: string;
  if (update.status === 'available') status = t('updates.available', { version: update.version });
  else if (update.status === 'downloading') {
    status = t('updates.downloading', { version: update.version });
    if (update.percent !== null) status += ` ${update.percent}%`;
  } else status = t(`updates.${update.status}`);

  return (
    <Row label={status}>
      {update.status === 'available' || update.status === 'downloading' ? (
        // The update is installed from its notes, so they're read first.
        <Button
          size="sm"
          variant="primary"
          loading={update.status === 'downloading'}
          onClick={showUpdateNotes}
        >
          {t('updates.whatsNew')}
        </Button>
      ) : (
        <Button
          size="sm"
          loading={update.status === 'checking'}
          onClick={() => void checkForUpdates()}
        >
          {t('updates.checkNow')}
        </Button>
      )}
    </Row>
  );
}

function algorithmTile(tone: Tone) {
  return (
    <Tile tone={tone} size={18}>
      <KeyRound className="size-[11px]" strokeWidth={2.5} />
    </Tile>
  );
}
