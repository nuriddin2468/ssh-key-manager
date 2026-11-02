import { LockOpen } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { LifetimeSelect } from './LifetimeSelect';

interface UnlockDialogProps {
  keyView: KeyView;
  lifetime: number | null;
  onDone: () => void;
}

/** Asks for a key's passphrase and adds it to ssh-agent. */
export function UnlockDialog({ keyView, lifetime: initialLifetime, onDone }: UnlockDialogProps) {
  const { t } = useTranslation();
  const [passphrase, setPassphrase] = useState('');
  const [lifetime, setLifetime] = useState(initialLifetime);
  const [wrong, setWrong] = useState(false);

  const unlock = useAppMutation(
    (vars: { passphrase: string; lifetime: number | null }) =>
      api.agentAdd(keyView.id, vars.passphrase, vars.lifetime),
    {
      success: () => t('keys.unlocked', { name: keyView.name }),
      onSuccess: onDone,
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
          <TextField
            label={t('agent.unlockPassphrase')}
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
            disabled={!passphrase}
          >
            {t('agent.unlock')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
