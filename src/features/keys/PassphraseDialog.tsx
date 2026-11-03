import { Lock } from 'lucide-react';
import { type FormEvent, useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { errorMessage, toastError, useAppMutation } from '@/api/useAppMutation';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { PassphraseFields } from '@/components/ui/PassphraseFields';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import {
  GeneratePassphraseButton,
  generatePassphrase,
  savePassphrase,
  VaultSaveRow,
} from './VaultControls';
import { useVaultKey } from './vaultKey';

interface PassphraseDialogProps {
  keyView: KeyView;
  /** Start with a generated passphrase (the audit's fix for a key without one). */
  suggest?: boolean;
  onDone: () => void;
}

interface Change {
  old: string | null;
  next: string | null;
  /** Save `next` in the vault, updating `entry` if there is one. */
  save: boolean;
  /** Move `entry` to the vault's recycle bin (the passphrase is removed). */
  trash: boolean;
  entry: EntrySummary | undefined;
}

/**
 * Adds, changes or removes a key's passphrase, and keeps the vault entry that
 * holds it in step.
 */
export function PassphraseDialog({ keyView, suggest = false, onDone }: PassphraseDialogProps) {
  const { t } = useTranslation();
  const hasOld = keyView.encrypted === true;
  const vault = useVaultKey(keyView.fingerprint);
  const entry = vault.vault === 'unlocked' ? vault.entry : undefined;
  const [old, setOld] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [visible, setVisible] = useState(false);
  const [wrong, setWrong] = useState(false);
  const [save, setSave] = useState(true);
  const [trash, setTrash] = useState(true);

  const fill = useCallback((value: string) => {
    setNext(value);
    setRepeat(value);
    setVisible(true);
  }, []);

  useEffect(() => {
    if (!suggest) return;
    let live = true;
    generatePassphrase().then(
      (value) => {
        if (live) fill(value);
      },
      (error: unknown) => toastError(t, error),
    );
    return () => {
      live = false;
    };
  }, [suggest, fill, t]);

  const change = useAppMutation(
    async (vars: Change) => {
      const updated = await api.changePassphrase(keyView.id, vars.old, vars.next);
      if (vars.save && vars.next && updated.fingerprint) {
        try {
          const key = { name: updated.name, fingerprint: updated.fingerprint };
          await savePassphrase(key, vars.next, vars.entry);
          return 'saved' as const;
        } catch (error) {
          toast.error(t('keys.vaultSaveFailed'), { description: errorMessage(t, error) });
        }
      } else if (vars.trash && vars.entry) {
        try {
          await api.vaultTrash(vars.entry.id);
          return 'trashed' as const;
        } catch (error) {
          toastError(t, error);
        }
      }
      return null;
    },
    {
      success: (vaulted) =>
        vaulted === 'saved'
          ? t('keys.passphraseSavedVault')
          : vaulted === 'trashed'
            ? t('keys.passphraseRemovedVault')
            : t('keys.passphraseSaved'),
      onSuccess: onDone,
      onError: (error) => {
        if (error.code !== 'wrong_passphrase') return false;
        setWrong(true);
        return true;
      },
    },
  );

  const mismatch = next !== repeat;
  const canSave = vault.vault === 'unlocked' && Boolean(keyView.fingerprint);
  const showSave = next !== '' && Boolean(keyView.fingerprint) && vault.vault !== 'unknown';
  const showTrash = hasOld && next === '' && entry !== undefined;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (mismatch || (hasOld && !old) || change.isPending) return;
    change.mutate({
      old: hasOld ? old : null,
      next: next || null,
      save: canSave && save,
      trash: showTrash && trash,
      entry,
    });
  };

  return (
    <DialogContent section="keys" className="max-w-[480px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="teal" size={44} glow>
              <Lock className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={hasOld ? t('keys.changePassphraseTitle') : t('keys.addPassphraseTitle')}
          description={<span className="font-mono">{keyView.name}</span>}
        />
        <DialogBody>
          {hasOld ? (
            <TextField
              label={t('agent.unlockPassphrase')}
              type="password"
              autoComplete="current-password"
              value={old}
              onChange={(event) => {
                setOld(event.target.value);
                setWrong(false);
              }}
              error={wrong ? t('errors.wrong_passphrase') : undefined}
              autoFocus
            />
          ) : null}
          <div className="flex flex-col gap-2.5">
            <PassphraseFields
              value={next}
              repeat={repeat}
              onChange={setNext}
              onRepeatChange={setRepeat}
              autoFocus={!hasOld && !suggest}
              visible={visible}
            />
            <GeneratePassphraseButton onGenerated={fill} />
          </div>
          {next === '' ? (
            <p className="text-[12px] text-warning">{t('generate.noPassphrase')}</p>
          ) : null}
          {showSave || showTrash ? (
            <SwitchGroup>
              {showSave ? (
                <VaultSaveRow
                  vault={vault}
                  checked={save}
                  onCheckedChange={setSave}
                  onLeave={onDone}
                />
              ) : null}
              {showTrash ? (
                <SwitchRow
                  label={t('keys.vaultTrash')}
                  hint={t('keys.vaultTrashHint')}
                  checked={trash}
                  onCheckedChange={setTrash}
                />
              ) : null}
            </SwitchGroup>
          ) : null}
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
            disabled={mismatch || (hasOld && !old) || (!hasOld && !next)}
          >
            {t('common.save')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
