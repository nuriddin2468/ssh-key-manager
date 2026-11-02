import { Lock } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { PassphraseFields } from '@/components/ui/PassphraseFields';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';

/** Adds, changes or removes a key's passphrase. */
export function PassphraseDialog({ keyView, onDone }: { keyView: KeyView; onDone: () => void }) {
  const { t } = useTranslation();
  const hasOld = keyView.encrypted === true;
  const [old, setOld] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [wrong, setWrong] = useState(false);

  const change = useAppMutation(
    (vars: { old: string | null; next: string | null }) =>
      api.changePassphrase(keyView.id, vars.old, vars.next),
    {
      success: () => t('keys.passphraseSaved'),
      onSuccess: onDone,
      onError: (error) => {
        if (error.code !== 'wrong_passphrase') return false;
        setWrong(true);
        return true;
      },
    },
  );

  const mismatch = next !== repeat;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (mismatch || (hasOld && !old) || change.isPending) return;
    change.mutate({ old: hasOld ? old : null, next: next || null });
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
          <PassphraseFields
            value={next}
            repeat={repeat}
            onChange={setNext}
            onRepeatChange={setRepeat}
            autoFocus={!hasOld}
          />
          {next === '' ? (
            <p className="text-[12px] text-warning">{t('generate.noPassphrase')}</p>
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
