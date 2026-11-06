import { isTauri } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { type FormEvent, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { errorMessage } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { VaultIcon } from '@/features/keys/VaultControls';
import { DeviceIcon, METHOD_NAME } from '@/features/passwords/device';
import { useVaultUnlock } from '@/features/passwords/UnlockVaultDialog';

function close(): void {
  if (isTauri()) void getCurrentWindow().close();
}

/**
 * The master password, and Touch ID or Windows Hello where it is set up,
 * in a window of the app's own: never in the browser, where a page could
 * draw a look-alike. The app closes the window once the vault is unlocked,
 * whichever way; Escape closes it too.
 */
export function UnlockWindow() {
  const { t } = useTranslation();
  const { status, device, master, password, wrong, failure, via, busy, ...vault } = useVaultUnlock({
    onUnlocked: close,
    inline: true,
  });

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') close();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    vault.unlockWithMaster();
  };
  const problem = wrong
    ? t('passwords.wrongMaster')
    : failure
      ? errorMessage(t, failure)
      : undefined;

  return (
    <main data-section="passwords" className="flex h-full flex-col gap-4 px-5 pt-4 pb-5">
      <header className="flex items-center gap-3">
        <Tile tone="pink" size={36} glow>
          <VaultIcon className="size-[18px]" />
        </Tile>
        <div className="flex min-w-0 flex-col">
          <h1 className="text-[14px] font-semibold">{t('passwords.unlockVaultTitle')}</h1>
          <p className="text-[12px] text-subtle">{t('browser.unlockFor')}</p>
        </div>
      </header>
      {/* Until the status comes, nothing to say: not even that there is no way in. */}
      {status ? (
        <form onSubmit={submit} noValidate className="flex min-h-0 flex-1 flex-col gap-3">
          {master ? (
            <TextField
              label={t('passwords.masterPassword')}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(event) => vault.setPassword(event.target.value)}
              error={problem}
              autoFocus
            />
          ) : (
            <p className="text-[12.5px] text-muted" role={failure ? 'alert' : undefined}>
              {problem ?? (device ? null : t('browser.unlockInApp'))}
            </p>
          )}
          <div className="mt-auto flex items-center gap-2">
            {device ? (
              <Button
                variant={master ? 'secondary' : 'primary'}
                icon={<DeviceIcon kind={device} className="size-[16px]" />}
                loading={busy && via === 'device'}
                disabled={busy}
                onClick={vault.unlockWithDevice}
              >
                {METHOD_NAME[device]}
              </Button>
            ) : null}
            {master ? (
              <Button
                type="submit"
                variant="primary"
                className="ml-auto"
                loading={busy && via === 'master'}
                disabled={!password || busy}
              >
                {t('passwords.unlock')}
              </Button>
            ) : null}
          </div>
        </form>
      ) : null}
    </main>
  );
}
