import { type FormEvent, type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { useRouter } from '@/app/router';
import { Button } from '@/components/ui/Button';
import {
  DialogBody,
  DialogClose,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { VaultIcon } from '@/features/keys/VaultControls';
import type { AppError } from '@/lib/ipc';
import { DeviceIcon, METHOD_NAME } from './device';
import { useVaultMutation } from './vault';

interface VaultUnlockFormProps {
  title: string;
  description?: string;
  submitLabel: string;
  onUnlocked: () => void;
  /** Work that follows the unlock (a check, say): the buttons stay busy meanwhile. */
  pending?: boolean;
  /** Under the fields: another way to go on. */
  extra?: ReactNode;
}

/**
 * The ways into the vault this computer offers, and unlocking with each:
 * Touch ID or Windows Hello where it is set up, the master password where
 * this computer has one. A wrong password shows in `wrong`; dismissing the
 * system prompt is a choice, not an error. Other failures are toasts, or
 * with `inline` kept in `failure` for a window without toasts.
 */
export function useVaultUnlock({
  onUnlocked,
  inline = false,
}: {
  onUnlocked: () => void;
  inline?: boolean;
}) {
  const status = useVaultStatus().data;
  const device = status?.device.enabled ? status.device.kind : null;
  const master = Boolean(status?.files.hasMasterPassword);
  const [password, setPassword] = useState('');
  const [wrong, setWrong] = useState(false);
  const [failure, setFailure] = useState<AppError | null>(null);
  // Which way in is busy, for its button's spinner.
  const [via, setVia] = useState<'device' | 'master'>('master');

  const keep = (error: AppError) => {
    if (!inline) return false;
    setFailure(error);
    return true;
  };
  const unlock = useVaultMutation(api.vaultUnlock, {
    onSuccess: onUnlocked,
    onError: (error) => {
      if (error.code !== 'wrong_passphrase') return keep(error);
      setWrong(true);
      return true;
    },
  });
  const unlockDevice = useVaultMutation(api.vaultUnlockDevice, {
    onSuccess: onUnlocked,
    onError: (error) => error.code === 'cancelled' || keep(error),
  });
  const busy = unlock.isPending || unlockDevice.isPending;

  return {
    status,
    device,
    master,
    password,
    wrong,
    failure,
    via,
    busy,
    setPassword: (value: string) => {
      setPassword(value);
      setWrong(false);
      setFailure(null);
    },
    unlockWithMaster: () => {
      if (!password || busy) return;
      setVia('master');
      setFailure(null);
      unlock.mutate(password);
    },
    unlockWithDevice: () => {
      if (busy) return;
      setVia('device');
      setFailure(null);
      unlockDevice.mutate();
    },
  };
}

/**
 * Opens the vault inside a dialog, with Touch ID or Windows Hello where it is
 * set up and the master password where this computer has one, so a screen
 * that needs a saved secret doesn't send the user to Passwords.
 */
export function VaultUnlockForm({
  title,
  description,
  submitLabel,
  onUnlocked,
  pending = false,
  extra,
}: VaultUnlockFormProps) {
  const { t } = useTranslation();
  const { device, master, password, wrong, via, ...vault } = useVaultUnlock({ onUnlocked });
  const busy = vault.busy || pending;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!pending) vault.unlockWithMaster();
  };

  return (
    <form onSubmit={submit} noValidate className="flex min-h-0 flex-col">
      <DialogHeader
        icon={
          <Tile tone="pink" size={40} glow>
            <VaultIcon className="size-5" />
          </Tile>
        }
        title={title}
        description={description}
      />
      <DialogBody>
        {device ? (
          <Button
            variant="primary"
            size="lg"
            className="w-full"
            icon={<DeviceIcon kind={device} className="size-[18px]" />}
            loading={busy && via === 'device'}
            disabled={busy}
            onClick={() => {
              if (!pending) vault.unlockWithDevice();
            }}
            autoFocus
          >
            {t('passwords.unlockWithDevice', { method: METHOD_NAME[device] })}
          </Button>
        ) : null}
        {master ? (
          <TextField
            label={device ? t('passwords.orMaster') : t('passwords.masterPassword')}
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => vault.setPassword(event.target.value)}
            error={wrong ? t('passwords.wrongMaster') : undefined}
            autoFocus={!device}
          />
        ) : null}
        {extra}
      </DialogBody>
      <DialogFooter>
        <DialogClose asChild>
          <Button size="lg">{t('common.cancel')}</Button>
        </DialogClose>
        {master ? (
          <Button
            type="submit"
            variant={device ? 'secondary' : 'primary'}
            size="lg"
            loading={busy && via === 'master'}
            disabled={!password || busy}
          >
            {submitLabel}
          </Button>
        ) : null}
      </DialogFooter>
    </form>
  );
}

interface UnlockVaultDialogProps {
  /** What the vault is opened for, under the title. */
  description?: string;
  onUnlocked?: () => void;
  onDone: () => void;
}

/**
 * "Unlock the vault" as a dialog. A vault this computer can open only with
 * the recovery key goes to the Passwords lock screen, which handles that.
 */
export function UnlockVaultDialog({ description, onUnlocked, onDone }: UnlockVaultDialogProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const status = useVaultStatus().data;
  if (!status) return null;
  const inPlace = status.device.enabled || status.files.hasMasterPassword;
  return (
    <DialogContent section="passwords" className="max-w-[440px]">
      {inPlace ? (
        <VaultUnlockForm
          title={t('passwords.unlockVaultTitle')}
          description={description}
          submitLabel={t('passwords.unlock')}
          onUnlocked={() => {
            onDone();
            onUnlocked?.();
          }}
        />
      ) : (
        <>
          <DialogHeader
            icon={
              <Tile tone="pink" size={40} glow>
                <VaultIcon className="size-5" />
              </Tile>
            }
            title={t('passwords.unlockVaultTitle')}
            description={t('passwords.unlockNeedsRecovery')}
          />
          <DialogFooter>
            <DialogClose asChild>
              <Button size="lg">{t('common.cancel')}</Button>
            </DialogClose>
            <Button
              variant="primary"
              size="lg"
              onClick={() => {
                onDone();
                navigate({ page: 'passwords' });
              }}
            >
              {t('passwords.openPasswords')}
            </Button>
          </DialogFooter>
        </>
      )}
    </DialogContent>
  );
}
