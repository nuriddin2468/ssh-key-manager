import { FileKey, LockKeyhole } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { VaultFiles } from '@/bindings/VaultFiles';
import { Button } from '@/components/ui/Button';
import { TextField } from '@/components/ui/TextField';
import { MasterPasswordFields, masterReady } from './MasterPasswordFields';
import { VaultCard } from './VaultCard';
import { requestSearchFocus, takeSearchFocusRequest, useVaultMutation } from './vault';

/**
 * The lock screen: the master password, or the recovery key and a new master
 * password. A KeePass file without a master password on this computer opens
 * with the recovery key or the file's own password.
 */
export function UnlockVault({ files }: { files: VaultFiles }) {
  const [recovering, setRecovering] = useState(!files.hasMasterPassword);
  return recovering || !files.hasMasterPassword ? (
    <RecoverForm
      setup={!files.hasMasterPassword}
      onBack={files.hasMasterPassword ? () => setRecovering(false) : undefined}
    />
  ) : (
    <UnlockForm onForgot={() => setRecovering(true)} />
  );
}

function UnlockForm({ onForgot }: { onForgot: () => void }) {
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
      {/* Unlock with Touch ID / Windows Hello goes here, above the password. */}
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
          autoFocus
        />
        <Button
          type="submit"
          variant="primary"
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
