import { Eye, EyeOff, KeyRound } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import {
  DialogBody,
  DialogClose,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { savePassphrase } from '@/features/keys/VaultControls';
import { useVaultKey, type VaultKey } from '@/features/keys/vaultKey';
import { VaultUnlockForm } from '@/features/passwords/UnlockVaultDialog';

interface KeyCheckDialogProps {
  alias: string;
  /** The host's key: it has a passphrase, and ssh-agent does not hold it. */
  keyView: KeyView;
  onChecked: (run: ConnectionTest) => void;
  onDone: () => void;
}

/**
 * Before "Check" runs `ssh` with a key it cannot open by itself: opens the
 * vault that holds the key's passphrase (Touch ID or the master password),
 * or asks for the passphrase, then checks. A typed passphrase goes to `ssh`
 * for this check only, unless the user saves it in the vault.
 */
export function KeyCheckDialog({ alias, keyView, onChecked, onDone }: KeyCheckDialogProps) {
  const vault = useVaultKey(keyView.fingerprint);
  const status = useVaultStatus().data;
  const device = status?.device.enabled ? status.device.kind : null;
  const master = Boolean(status?.files.hasMasterPassword);
  // Chosen once the vault's state is known, and kept: opening the vault
  // changes it while the check runs.
  const [mode, setMode] = useState<'vault' | 'type' | null>(null);
  if (mode === null && status && vault.vault !== 'unknown') {
    setMode(vault.vault === 'locked' && vault.saved && (device || master) ? 'vault' : 'type');
  }
  const done = (run: ConnectionTest) => {
    onChecked(run);
    onDone();
  };

  if (mode === null) return null;
  return (
    <DialogContent section="hosts" className="max-w-[460px]">
      {mode === 'type' ? (
        <PassphraseForm alias={alias} keyView={keyView} vault={vault} onChecked={done} />
      ) : (
        <VaultForm
          alias={alias}
          keyView={keyView}
          onChecked={done}
          onType={() => setMode('type')}
        />
      )}
    </DialogContent>
  );
}

function PassphraseForm({
  alias,
  keyView,
  vault,
  onChecked,
}: {
  alias: string;
  keyView: KeyView;
  vault: VaultKey;
  onChecked: (run: ConnectionTest) => void;
}) {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState('');
  const [visible, setVisible] = useState(false);
  const [wrong, setWrong] = useState(false);
  const canSave = vault.vault === 'unlocked' && Boolean(keyView.fingerprint);
  const [save, setSave] = useState(true);

  const check = useAppMutation(
    async (typed: string) => {
      const args = { keyId: keyView.id, passphrase: typed };
      // An open vault also has the host's password and 2FA code.
      const run =
        vault.vault === 'unlocked'
          ? await api.vaultTestConnection(alias, args)
          : await api.testConnection(alias, args);
      // The backend checked that the passphrase opens the key.
      if (canSave && save && keyView.fingerprint) {
        try {
          await savePassphrase({ name: keyView.name, fingerprint: keyView.fingerprint }, typed);
        } catch (error) {
          toastError(t, error);
        }
      }
      return run;
    },
    {
      onSuccess: onChecked,
      onError: (error) => {
        if (error.code !== 'wrong_passphrase') return false;
        setWrong(true);
        return true;
      },
    },
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!passphrase || check.isPending) return;
    check.mutate(passphrase);
  };

  return (
    <form onSubmit={submit} noValidate className="flex min-h-0 flex-col">
      <DialogHeader
        icon={
          <Tile tone="teal" size={40} glow>
            <KeyRound className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('terminal.prompt.passphraseTitle', { key: keyView.name })}
        description={t('terminal.prompt.passphraseAsked')}
      />
      <DialogBody>
        <TextField
          label={t('terminal.prompt.passphrase')}
          type={visible ? 'text' : 'password'}
          value={passphrase}
          onChange={(event) => {
            setPassphrase(event.target.value);
            setWrong(false);
          }}
          autoComplete="off"
          mono
          error={wrong ? t('errors.wrong_passphrase') : undefined}
          autoFocus
          suffix={
            <IconButton
              label={visible ? t('terminal.prompt.hide') : t('terminal.prompt.show')}
              icon={
                visible ? (
                  <EyeOff className="size-[15px]" strokeWidth={1.75} />
                ) : (
                  <Eye className="size-[15px]" strokeWidth={1.75} />
                )
              }
              onClick={() => setVisible((shown) => !shown)}
            />
          }
        />
        {canSave ? (
          <Checkbox
            checked={save}
            onCheckedChange={setSave}
            label={t('terminal.prompt.savePassphrase')}
          />
        ) : vault.vault === 'locked' && !vault.saved ? (
          <p className="text-[12px] text-muted">{t('terminal.prompt.saveLocked')}</p>
        ) : vault.vault === 'missing' ? (
          <p className="text-[12px] text-muted">{t('terminal.prompt.saveNoVault')}</p>
        ) : null}
      </DialogBody>
      <DialogFooter>
        <DialogCancel />
        <Button
          type="submit"
          variant="primary"
          size="lg"
          loading={check.isPending}
          disabled={!passphrase}
        >
          {t('hosts.editor.check')}
        </Button>
      </DialogFooter>
    </form>
  );
}

function VaultForm({
  alias,
  keyView,
  onChecked,
  onType,
}: {
  alias: string;
  keyView: KeyView;
  onChecked: (run: ConnectionTest) => void;
  onType: () => void;
}) {
  const { t } = useTranslation();
  // The vault is open now: the check takes the passphrase from it.
  const check = useAppMutation(() => api.vaultTestConnection(alias), { onSuccess: onChecked });
  return (
    <VaultUnlockForm
      title={t('hosts.keyCheck.vaultTitle', { alias })}
      description={t('hosts.keyCheck.vaultText', { key: keyView.name })}
      submitLabel={t('hosts.keyCheck.unlockAndCheck')}
      onUnlocked={() => check.mutate()}
      pending={check.isPending}
      extra={
        <Button
          variant="ghost"
          size="sm"
          className="self-start"
          disabled={check.isPending}
          onClick={onType}
        >
          {t('hosts.keyCheck.typeInstead')}
        </Button>
      }
    />
  );
}

function DialogCancel() {
  const { t } = useTranslation();
  return (
    <DialogClose asChild>
      <Button size="lg">{t('common.cancel')}</Button>
    </DialogClose>
  );
}
