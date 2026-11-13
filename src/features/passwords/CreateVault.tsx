import { CloudOff, Download, FileKey, HardDrive, RectangleEllipsis } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import { Button } from '@/components/ui/Button';
import { setStatus } from '@/features/nearby/queries';
import { OpenExistingVaultButton } from './files';
import { MasterPasswordFields, masterReady } from './MasterPasswordFields';
import { RecoveryKeyPanel } from './RecoveryKeyPanel';
import { VaultCard } from './VaultCard';
import {
  dismissUnsavedRecoveryKey,
  recoveryKeySaved,
  requestSearchFocus,
  setPendingRecoveryKey,
  showUnsavedRecoveryKey,
  toastVaultError,
  useSecretCall,
} from './vault';

/** No vault yet: what it is, and a master password to create one. */
export function CreateVault() {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const [master, setMaster] = useState('');
  const [repeat, setRepeat] = useState('');
  // Or the vault of the user's other computer, over the local network.
  const join = useAppMutation(() => api.nearbyJoin(true), {
    onSuccess: (status) => {
      setStatus(status);
      navigate({ page: 'nearby' });
    },
  });

  // The recovery key stays out of TanStack's caches, and must be in place
  // before the status refresh shows the unlocked vault.
  const create = useSecretCall(api.vaultCreate);

  const ready = masterReady(master, repeat);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!ready || create.pending) return;
    try {
      setPendingRecoveryKey(await create.call(master));
      setMaster('');
      setRepeat('');
      await invalidateAll();
    } catch (error) {
      toastVaultError(t, error);
    }
  };

  const points = [
    { icon: HardDrive, text: t('passwords.pointFile') },
    { icon: CloudOff, text: t('passwords.pointLocal') },
    { icon: FileKey, text: t('passwords.pointKeepass') },
  ];

  return (
    <VaultCard
      icon={<RectangleEllipsis className="size-[26px]" strokeWidth={1.9} />}
      title={t('passwords.createTitle')}
      text={t('passwords.createText')}
    >
      <ul className="flex flex-col gap-2 border-b border-ink/[0.07] pb-4">
        {points.map(({ icon: Icon, text }) => (
          <li key={text} className="flex items-center gap-2.5 text-[12.5px] text-fg-2">
            <Icon
              aria-hidden="true"
              className="size-4 shrink-0 text-[var(--accent-text)]"
              strokeWidth={1.9}
            />
            {text}
          </li>
        ))}
      </ul>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <MasterPasswordFields
          value={master}
          repeat={repeat}
          onChange={setMaster}
          onRepeatChange={setRepeat}
          autoFocus
        />
        <Button
          type="submit"
          variant="primary"
          size="lg"
          className="w-full"
          loading={create.pending}
          disabled={!ready}
        >
          {t('passwords.create')}
        </Button>
      </form>
      <div className="flex flex-wrap justify-center gap-1">
        <OpenExistingVaultButton variant="ghost" size="sm" />
        <Button
          variant="ghost"
          size="sm"
          loading={join.isPending}
          icon={<Download aria-hidden="true" className="size-3.5" strokeWidth={2} />}
          title={t('nearby.join.hint')}
          onClick={() => join.mutate(undefined)}
        >
          {t('nearby.getVault')}
        </Button>
      </div>
    </VaultCard>
  );
}

/**
 * Right after creating the vault or a new recovery key: the key, shown until
 * it is confirmed as saved (again after an unlock, if the vault locked first).
 */
export function RecoveryKeyScreen({ recoveryKey }: { recoveryKey: string }) {
  const { t } = useTranslation();
  const [saved, setSaved] = useState(false);
  return (
    <VaultCard
      icon={<FileKey className="size-[26px]" strokeWidth={1.9} />}
      title={t('passwords.recoveryTitle')}
      text={t('passwords.recoveryText')}
      focusTitle
    >
      <RecoveryKeyPanel recoveryKey={recoveryKey} saved={saved} onSavedChange={setSaved} />
      <Button
        variant="primary"
        size="lg"
        className="w-full"
        disabled={!saved}
        onClick={() => {
          requestSearchFocus();
          recoveryKeySaved();
        }}
      >
        {t('passwords.continue')}
      </Button>
    </VaultCard>
  );
}

/**
 * After an unlock, when a lock took a new recovery key off the screen before
 * it was confirmed as saved. "Show key" asks in a native dialog first; the
 * key is never fetched without the user asking.
 */
export function UnsavedRecoveryKey() {
  const { t } = useTranslation();
  const [pending, setPending] = useState(false);
  const show = async () => {
    setPending(true);
    try {
      await showUnsavedRecoveryKey();
    } catch (error) {
      toastVaultError(t, error);
    } finally {
      setPending(false);
    }
  };
  return (
    <VaultCard
      icon={<FileKey className="size-[26px]" strokeWidth={1.9} />}
      title={t('passwords.unsavedKeyTitle')}
      text={t('passwords.unsavedKeyCardText')}
      focusTitle
    >
      <Button variant="primary" size="lg" className="w-full" loading={pending} onClick={show}>
        {t('passwords.unsavedKeyShow')}
      </Button>
      <Button variant="ghost" size="sm" className="self-center" onClick={dismissUnsavedRecoveryKey}>
        {t('passwords.unsavedKeyLater')}
      </Button>
    </VaultCard>
  );
}
