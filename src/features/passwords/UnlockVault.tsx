import { FileKey, LockKeyhole } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import type { BiometricKind } from '@/bindings/BiometricKind';
import type { DeviceUnlockStatus } from '@/bindings/DeviceUnlockStatus';
import type { VaultFiles } from '@/bindings/VaultFiles';
import { Button } from '@/components/ui/Button';
import { TextField } from '@/components/ui/TextField';
import { DeviceIcon, METHOD_NAME } from './device';
import { MasterPasswordFields, masterReady } from './MasterPasswordFields';
import { VaultCard } from './VaultCard';
import { requestSearchFocus, takeSearchFocusRequest, useVaultMutation } from './vault';

/**
 * The lock screen: the master password, or the recovery key and a new master
 * password. A KeePass file without a master password on this computer opens
 * with the recovery key or the file's own password.
 */
export function UnlockVault({ files, device }: { files: VaultFiles; device: DeviceUnlockStatus }) {
  const [recovering, setRecovering] = useState(!files.hasMasterPassword);
  return recovering || !files.hasMasterPassword ? (
    <RecoverForm
      setup={!files.hasMasterPassword}
      onBack={files.hasMasterPassword ? () => setRecovering(false) : undefined}
    />
  ) : (
    <UnlockForm
      deviceKind={device.enabled ? device.kind : null}
      onForgot={() => setRecovering(true)}
    />
  );
}

function UnlockForm({
  deviceKind,
  onForgot,
}: {
  deviceKind: BiometricKind | null;
  onForgot: () => void;
}) {
  const { t } = useTranslation();
  const [master, setMaster] = useState('');
  const [wrong, setWrong] = useState(false);

  const unlock = useVaultMutation(api.vaultUnlock, {
    onError: (error) => {
      takeSearchFocusRequest();
      if (error.code !== 'wrong_passphrase') return false;
      setWrong(true);
      return true;
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!master || unlock.isPending) return;
    requestSearchFocus();
    unlock.mutate(master);
  };

  return (
    <VaultCard
      icon={<LockKeyhole className="size-[26px]" strokeWidth={1.9} />}
      title={t('passwords.lockedTitle')}
      text={t('passwords.lockedText')}
    >
      {deviceKind ? (
        <>
          <DeviceUnlock kind={deviceKind} />
          <div className="flex items-center gap-3 text-[12px] text-subtle">
            <span aria-hidden="true" className="h-px flex-1 bg-white/[0.08]" />
            {t('passwords.orMaster')}
            <span aria-hidden="true" className="h-px flex-1 bg-white/[0.08]" />
          </div>
        </>
      ) : null}
      <form onSubmit={submit} className="flex flex-col gap-4">
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
          autoFocus={!deviceKind}
        />
        <Button
          type="submit"
          variant={deviceKind ? 'secondary' : 'primary'}
          size="lg"
          className="w-full"
          loading={unlock.isPending}
          disabled={!master}
        >
          {t('passwords.unlock')}
        </Button>
      </form>
      <Button variant="ghost" size="sm" className="self-center" onClick={onForgot}>
        {t('passwords.forgot')}
      </Button>
    </VaultCard>
  );
}

/** The primary way in when Touch ID / Windows Hello is set up here. */
function DeviceUnlock({ kind }: { kind: BiometricKind }) {
  const { t } = useTranslation();
  const method = METHOD_NAME[kind];
  const [problem, setProblem] = useState<string | null>(null);

  const unlock = useVaultMutation(api.vaultUnlockDevice, {
    onError: (error) => {
      takeSearchFocusRequest();
      // Dismissing the system prompt is a choice, not an error.
      if (error.code === 'cancelled') return true;
      if (error.code === 'not_found') {
        setProblem(t('passwords.deviceGone', { method }));
        void invalidateAll();
        return true;
      }
      if (error.code === 'unsupported') {
        setProblem(t('passwords.deviceUnavailable', { method }));
        return true;
      }
      return false;
    },
  });

  return (
    <div className="flex flex-col gap-2">
      <Button
        variant="primary"
        size="lg"
        className="w-full"
        icon={<DeviceIcon kind={kind} className="size-[18px]" />}
        loading={unlock.isPending}
        onClick={() => {
          setProblem(null);
          requestSearchFocus();
          unlock.mutate();
        }}
        autoFocus
      >
        {t('passwords.unlockWithDevice', { method })}
      </Button>
      {problem ? (
        <p role="alert" className="text-[12.5px] text-warning">
          {problem}
        </p>
      ) : null}
    </div>
  );
}

function RecoverForm({ setup, onBack }: { setup: boolean; onBack?: () => void }) {
  const { t } = useTranslation();
  const [recoveryKey, setRecoveryKey] = useState('');
  const [master, setMaster] = useState('');
  const [repeat, setRepeat] = useState('');
  const [wrong, setWrong] = useState(false);

  const recover = useVaultMutation(
    (vars: { recoveryKey: string; master: string }) =>
      api.vaultRecover(vars.recoveryKey, vars.master),
    {
      onError: (error) => {
        takeSearchFocusRequest();
        if (error.code !== 'wrong_passphrase') return false;
        setWrong(true);
        return true;
      },
    },
  );

  const ready = recoveryKey.trim().length > 0 && masterReady(master, repeat);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!ready || recover.isPending) return;
    requestSearchFocus();
    recover.mutate({ recoveryKey, master });
  };

  return (
    <VaultCard
      icon={<FileKey className="size-[26px]" strokeWidth={1.9} />}
      title={setup ? t('passwords.setupTitle') : t('passwords.recoverTitle')}
      text={setup ? t('passwords.setupText') : t('passwords.recoverText')}
    >
      <form onSubmit={submit} className="flex flex-col gap-4">
        <TextField
          label={setup ? t('passwords.recoveryOrPassword') : t('passwords.recoveryKey')}
          // A KeePass password may be anything; a recovery key is shown as text to check it.
          type={setup ? 'password' : 'text'}
          mono={!setup}
          autoComplete="off"
          autoCapitalize="characters"
          placeholder={setup ? undefined : t('passwords.recoveryPlaceholder')}
          value={recoveryKey}
          onChange={(event) => {
            setRecoveryKey(event.target.value);
            setWrong(false);
          }}
          error={
            wrong
              ? setup
                ? t('passwords.wrongRecoveryOrPassword')
                : t('passwords.wrongRecovery')
              : undefined
          }
          autoFocus
        />
        <MasterPasswordFields
          value={master}
          repeat={repeat}
          onChange={setMaster}
          onRepeatChange={setRepeat}
          replacing={!setup}
        />
        <Button
          type="submit"
          variant="primary"
          size="lg"
          className="w-full"
          loading={recover.isPending}
          disabled={!ready}
        >
          {t('passwords.recover')}
        </Button>
      </form>
      {onBack ? (
        <Button variant="ghost" size="sm" className="self-center" onClick={onBack}>
          {t('passwords.backToUnlock')}
        </Button>
      ) : null}
    </VaultCard>
  );
}
