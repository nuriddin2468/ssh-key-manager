import { CloudOff, FileKey, HardDrive, RectangleEllipsis } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { Button } from '@/components/ui/Button';
import { OpenExistingVaultButton } from './files';
import { MasterPasswordFields, masterReady } from './MasterPasswordFields';
import { RecoveryKeyPanel } from './RecoveryKeyPanel';
import { VaultCard } from './VaultCard';
import { requestSearchFocus, setPendingRecoveryKey, toastVaultError, useSecretCall } from './vault';

/** No vault yet: what it is, and a master password to create one. */
export function CreateVault() {
  const { t } = useTranslation();
  const [master, setMaster] = useState('');
  const [repeat, setRepeat] = useState('');

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
      <ul className="flex flex-col gap-2 border-b border-white/[0.07] pb-4">
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
      <OpenExistingVaultButton variant="ghost" size="sm" className="self-center" />
    </VaultCard>
  );
}

/** Right after creating the vault: its recovery key, shown this once. */
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
          setPendingRecoveryKey(null);
        }}
      >
        {t('passwords.continue')}
      </Button>
    </VaultCard>
  );
}
