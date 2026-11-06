import { KeyRound } from 'lucide-react';
import { type FormEvent, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useAgent, useEnvironment } from '@/api/queries';
import { errorMessage, useAppMutation } from '@/api/useAppMutation';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { PassphraseFields } from '@/components/ui/PassphraseFields';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { OkBox, Text } from '@/features/hosts/Feedback';
import { useSettings } from '@/lib/settings';
import { FILE_NAME_PATTERN, suggestFileName } from '../model';
import { GeneratePassphraseButton, savePassphrase, VaultSaveRow } from '../VaultControls';
import { useVaultKey } from '../vaultKey';
import { newProgress } from './plan';
import type { StepProps } from './RotateKeyDialog';
import { type Rotation, updateRotation } from './store';

interface NewKeyStepProps extends StepProps {
  rotation: Rotation | null;
  /** The new key, if it is made already. */
  newKey: KeyView | undefined;
  keys: KeyView[];
  /** Closes the wizard, e.g. to set up a vault on the Passwords page. */
  onClose: () => void;
}

/** File names in `~/.ssh` a new key cannot take. */
function takenNames(keys: readonly KeyView[]): Set<string> {
  const names = new Set<string>();
  for (const key of keys) {
    names.add(key.name);
    for (const path of [key.privatePath, key.publicPath]) {
      const file = path?.split(/[\\/]/).pop();
      if (file) names.add(file.replace(/\.pub$/, ''));
    }
  }
  return names;
}

/**
 * Step 2: the new Ed25519 key, made as the generate dialog makes one: a
 * passphrase, saved in the vault if wanted, and added to the agent so the
 * check can sign in with it.
 */
export function NewKeyStep({
  progress,
  oldKey,
  go,
  rotation,
  newKey,
  keys,
  onClose,
}: NewKeyStepProps) {
  const { t } = useTranslation();
  const settings = useSettings();
  const environment = useEnvironment();
  const agent = useAgent();
  const taken = useMemo(() => takenNames(keys), [keys]);
  const [customName, setCustomName] = useState<string | null>(null);
  const [comment, setComment] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [repeat, setRepeat] = useState('');
  const [showPassphrase, setShowPassphrase] = useState(false);
  const vault = useVaultKey(null);
  const [saveToVault, setSaveToVault] = useState(true);
  const [addToAgent, setAddToAgent] = useState(true);

  const fileName = customName ?? suggestFileName('id_ed25519', taken);
  const commentValue = comment ?? (oldKey.comment || environment.data?.defaultComment || '');
  const agentAvailable = agent.data?.status.available ?? false;
  const nameError = !FILE_NAME_PATTERN.test(fileName)
    ? t('generate.fileNameInvalid')
    : taken.has(fileName)
      ? t('generate.fileNameTaken')
      : undefined;
  const mismatch = passphrase !== repeat;

  const create = useAppMutation(
    async () => {
      const key = await api.generateKey({
        key: {
          algorithm: { kind: 'ed25519' },
          fileName,
          comment: commentValue.trim(),
          passphrase: passphrase || null,
        },
        addToAgent: addToAgent && agentAvailable,
        agentLifetimeSecs: settings.defaultLifetime,
        host: null,
      });
      let saved = false;
      if (saveToVault && vault.vault === 'unlocked' && passphrase && key.fingerprint) {
        try {
          await savePassphrase({ name: key.name, fingerprint: key.fingerprint }, passphrase);
          saved = true;
        } catch (error) {
          toast.error(t('keys.vaultSaveFailed'), { description: errorMessage(t, error) });
        }
      }
      return { key, saved };
    },
    {
      success: ({ key, saved }) =>
        t(saved ? 'generate.createdSaved' : 'generate.created', { name: key.name }),
      onSuccess: ({ key }) => {
        updateRotation(oldKey.id, (current) => ({
          ...current,
          newKeyId: key.id,
          // A new key replacing one that was deleted: every host starts over.
          hosts: current.newKeyId
            ? current.hosts.map((host) => newProgress(host.alias))
            : current.hosts,
        }));
        go('move');
      },
    },
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (nameError || mismatch || create.isPending) return;
    create.mutate(undefined);
  };

  if (newKey) {
    return (
      <>
        <DialogBody>
          {progress}
          <OkBox>{t('rotation.key.ready', { name: newKey.name })}</OkBox>
        </DialogBody>
        <DialogFooter>
          <Button size="lg" variant="ghost" className="mr-auto" onClick={() => go('hosts')}>
            {t('rotation.back')}
          </Button>
          <Button variant="primary" size="lg" onClick={() => go('move')}>
            {t('rotation.continue')}
          </Button>
        </DialogFooter>
      </>
    );
  }

  return (
    <form onSubmit={submit} className="flex min-h-0 flex-col">
      <DialogBody>
        {progress}
        <Text>
          {rotation?.newKeyId
            ? t('rotation.key.lost', { name: oldKey.name })
            : t('rotation.key.text', { name: oldKey.name })}
        </Text>
        <div className="grid grid-cols-2 gap-3.5">
          <TextField
            label={t('generate.fileName')}
            prefix="~/.ssh/"
            mono
            value={fileName}
            onChange={(event) => setCustomName(event.target.value)}
            error={nameError}
            hint={t('generate.fileNameHint', { name: fileName })}
          />
          <TextField
            label={t('generate.comment')}
            value={commentValue}
            onChange={(event) => setComment(event.target.value)}
            hint={t('generate.commentHint')}
          />
          <PassphraseFields
            value={passphrase}
            repeat={repeat}
            onChange={setPassphrase}
            onRepeatChange={setRepeat}
            visible={showPassphrase}
          />
        </div>
        <div className="-mt-2 flex flex-col gap-1.5">
          {passphrase === '' ? (
            <p className="text-[12px] text-warning">{t('generate.noPassphrase')}</p>
          ) : null}
          <GeneratePassphraseButton
            onGenerated={(value) => {
              setPassphrase(value);
              setRepeat(value);
              setShowPassphrase(true);
            }}
          />
        </div>
        <fieldset className="flex flex-col">
          <legend className="mb-2 text-[12px] font-semibold tracking-[0.02em] text-subtle">
            {t('generate.afterCreating')}
          </legend>
          <SwitchGroup>
            <VaultSaveRow
              vault={vault}
              checked={saveToVault}
              onCheckedChange={setSaveToVault}
              disabled={passphrase === ''}
              onLeave={onClose}
            />
            <SwitchRow
              label={t('generate.addToAgent')}
              hint={agentAvailable ? t('rotation.key.agentHint') : t('agent.stoppedTitle')}
              checked={addToAgent && agentAvailable}
              disabled={!agentAvailable}
              onCheckedChange={setAddToAgent}
            />
          </SwitchGroup>
        </fieldset>
      </DialogBody>
      <DialogFooter>
        <Button size="lg" variant="ghost" className="mr-auto" onClick={() => go('hosts')}>
          {t('rotation.back')}
        </Button>
        <Button
          type="submit"
          variant="primary"
          size="lg"
          loading={create.isPending}
          disabled={Boolean(nameError) || mismatch}
          icon={<KeyRound className="size-4" strokeWidth={2} />}
        >
          {t('rotation.key.create')}
        </Button>
      </DialogFooter>
    </form>
  );
}
