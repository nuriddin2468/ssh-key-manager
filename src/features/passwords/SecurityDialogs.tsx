import { FileKey, LockKeyhole } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { AppError } from '@/lib/ipc';
import { platform } from '@/lib/platform';
import { MasterPasswordFields, masterReady } from './MasterPasswordFields';
import { RecoveryKeyPanel } from './RecoveryKeyPanel';
import { toastVaultError, useSecretCall, useVaultMutation } from './vault';

/** Current master password, then a new one twice. */
export function ChangeMasterDialog({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [wrong, setWrong] = useState(false);

  const change = useVaultMutation(
    (vars: { current: string; next: string }) => api.vaultChangeMaster(vars.current, vars.next),
    {
      success: () => t('passwords.masterChanged'),
      onSuccess: onDone,
      onError: (error) => {
        if (error.code !== 'wrong_passphrase') return false;
        setWrong(true);
        return true;
      },
    },
  );

  const ready = current.length > 0 && masterReady(next, repeat);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!ready || change.isPending) return;
    change.mutate({ current, next });
  };

  return (
    <DialogContent section="passwords" className="max-w-[460px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="indigo" size={44} glow>
              <LockKeyhole className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('passwords.changeMasterTitle')}
          description={t('passwords.changeMasterText')}
        />
        <DialogBody>
          <TextField
            label={t('passwords.currentMaster')}
            type="password"
            autoComplete="current-password"
            value={current}
            onChange={(event) => {
              setCurrent(event.target.value);
              setWrong(false);
            }}
            error={wrong ? t('passwords.wrongMaster') : undefined}
          />
          <MasterPasswordFields
            value={next}
            repeat={repeat}
            onChange={setNext}
            onRepeatChange={setRepeat}
            replacing
          />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={change.isPending}
            disabled={!ready}
          >
            {t('passwords.changeMasterTitle')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

const DEVICE_UNLOCK = { macos: 'Touch ID', windows: 'Windows Hello', linux: null } as const;

/**
 * Replaces the recovery key: the master password first, then the new key
 * shown once. The second step can't be dismissed until the key is saved.
 */
export function NewRecoveryKeyDialog({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [master, setMaster] = useState('');
  const [wrong, setWrong] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const device = DEVICE_UNLOCK[platform];

  // The new key stays out of TanStack's caches and is shown before anything refreshes.
  const create = useSecretCall(api.vaultNewRecoveryKey);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!master || create.pending) return;
    try {
      setRecoveryKey(await create.call(master));
      setMaster('');
      void invalidateAll();
    } catch (error) {
      if (AppError.from(error).code === 'wrong_passphrase') setWrong(true);
      else toastVaultError(t, error);
    }
  };

  if (recoveryKey) {
    return (
      <DialogContent section="passwords" className="max-w-[500px]" dismissible={false}>
        <DialogHeader
          closable={false}
          icon={
            <Tile tone="indigo" size={44} glow>
              <FileKey className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('passwords.recoveryTitle')}
          description={t('passwords.recoveryText')}
        />
        <DialogBody>
          <RecoveryKeyPanel recoveryKey={recoveryKey} saved={saved} onSavedChange={setSaved} />
        </DialogBody>
        <DialogFooter>
          <Button variant="primary" size="lg" disabled={!saved} onClick={onDone}>
            {t('passwords.newRecoveryDone')}
          </Button>
        </DialogFooter>
      </DialogContent>
    );
  }

  return (
    <DialogContent section="passwords" className="max-w-[460px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="indigo" size={44} glow>
              <FileKey className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('passwords.newRecoveryTitle')}
          description={t('passwords.newRecoveryText')}
        />
        <DialogBody>
          <TextField
            label={t('passwords.masterPassword')}
            type="password"
            autoComplete="current-password"
            value={master}
            onChange={(event) => {
              setMaster(event.target.value);
              setWrong(false);
            }}
            error={wrong ? t('passwords.wrongMaster') : undefined}
            hint={device ? t('passwords.newRecoveryDevice', { method: device }) : undefined}
          />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={create.pending}
            disabled={!master}
          >
            {t('passwords.newRecoverySubmit')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
