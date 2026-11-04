import { LockOpen } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { VaultCallout } from '@/features/keys/VaultControls';
import { useVaultKey } from '@/features/keys/vaultKey';
import { LifetimeSelect } from './LifetimeSelect';

/** Why the saved passphrase did not work, by error code. */
const SAVED_ERRORS = {
  wrong_passphrase: 'agent.savedOutdated',
  not_found: 'agent.savedGone',
  vault_locked: 'agent.savedLocked',
} as const;

interface UnlockDialogProps {
  keyView: KeyView;
  lifetime: number | null;
  onDone: () => void;
  /** After the key was added, once the dialog is done. */
  onUnlocked?: () => void;
}

/**
 * Adds a key to ssh-agent with its passphrase: the one saved in the vault,
 * which stays in the backend, or one the user types.
 */
export function UnlockDialog({
  keyView,
  lifetime: initialLifetime,
  onDone,
  onUnlocked,
}: UnlockDialogProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const vault = useVaultKey(keyView.fingerprint);
  const saved = vault.vault === 'unlocked' ? vault.entry : undefined;
  const [passphrase, setPassphrase] = useState('');
  const [lifetime, setLifetime] = useState(initialLifetime);
  const [wrong, setWrong] = useState(false);
  const [savedError, setSavedError] = useState<keyof typeof SAVED_ERRORS | null>(null);

  const unlocked = () => {
    onDone();
    onUnlocked?.();
  };

  const unlockSaved = useAppMutation(
    (vars: { lifetime: number | null }) => api.agentAddFromVault(keyView.id, vars.lifetime),
    {
      success: () => t('keys.unlocked', { name: keyView.name }),
      onSuccess: unlocked,
      onError: (error) => {
        if (!(error.code in SAVED_ERRORS)) return false;
        setSavedError(error.code as keyof typeof SAVED_ERRORS);
        return true;
      },
    },
  );
  const openVault = () => {
    onDone();
    navigate({ page: 'passwords' });
  };

  const unlock = useAppMutation(
    (vars: { passphrase: string; lifetime: number | null }) =>
      api.agentAdd(keyView.id, vars.passphrase, vars.lifetime),
    {
      success: () => t('keys.unlocked', { name: keyView.name }),
      onSuccess: unlocked,
      onError: (error) => {
        if (error.code !== 'wrong_passphrase') return false;
        setWrong(true);
        return true;
      },
    },
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!passphrase || unlock.isPending) return;
    unlock.mutate({ passphrase, lifetime });
  };

  return (
    <DialogContent section="agent" className="max-w-[440px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="violet" size={44} glow>
              <LockOpen className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('agent.unlockTitle', { name: keyView.name })}
          description={t('agent.unlockDescription')}
        />
        <DialogBody>
          {saved ? (
            <div className="flex flex-col gap-1.5">
              <VaultCallout
                action={
                  <Button
                    variant="soft"
                    size="sm"
                    loading={unlockSaved.isPending}
                    disabled={unlock.isPending}
                    onClick={() => {
                      setSavedError(null);
                      unlockSaved.mutate({ lifetime });
                    }}
                  >
                    {t('agent.savedUse')}
                  </Button>
                }
              >
                {t('agent.savedTitle')}
              </VaultCallout>
              {savedError ? (
                <p role="alert" className="text-[12px] text-critical">
                  {t(SAVED_ERRORS[savedError])}
                </p>
              ) : null}
            </div>
          ) : vault.vault === 'locked' && vault.saved ? (
            <VaultCallout
              action={
                <Button size="sm" onClick={openVault}>
                  {t('agent.openVault')}
                </Button>
              }
            >
              {t('agent.savedLocked')}
            </VaultCallout>
          ) : null}
          <TextField
            label={saved ? t('agent.orType') : t('agent.unlockPassphrase')}
            type="password"
            autoComplete="current-password"
            value={passphrase}
            onChange={(event) => {
              setPassphrase(event.target.value);
              setWrong(false);
            }}
            error={wrong ? t('errors.wrong_passphrase') : undefined}
            autoFocus
          />
          <LifetimeSelect value={lifetime} onChange={setLifetime} withLabel />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={unlock.isPending}
            disabled={!passphrase || unlockSaved.isPending}
          >
            {t('agent.unlock')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
