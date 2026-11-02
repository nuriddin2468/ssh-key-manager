import { isTauri } from '@tauri-apps/api/core';
import { revealItemInDir } from '@tauri-apps/plugin-opener';
import { FolderOpen, KeyRound } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useEnvironment } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { Logo } from '@/components/Logo';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { Switch } from '@/components/ui/Switch';
import { Tile, type Tone } from '@/components/ui/Tile';
import { LifetimeSelect } from '@/features/agent/LifetimeSelect';
import { LANGUAGE_NAMES, LANGUAGES, type Language, setLanguage, storedLanguage } from '@/i18n';
import { displayPath } from '@/lib/format';
import { fileManagerName } from '@/lib/platform';
import { type Settings, updateSettings, useSettings } from '@/lib/settings';
import { checkForUpdates, installUpdate, useUpdateState } from '@/lib/updater';

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
      <PageBody className="max-w-[760px] gap-5">
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
      </PageBody>
    </>
  );
}

function Group({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="flex flex-col gap-2">
      <h2 className="px-1 text-[12px] font-semibold tracking-[0.02em] text-subtle">{title}</h2>
      <div className="glass flex flex-col divide-y divide-white/[0.06] overflow-hidden rounded-2xl">
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
        <Button
          size="sm"
          variant="primary"
          loading={update.status === 'downloading'}
          onClick={() => void installUpdate()}
        >
          {t('updates.install')}
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
