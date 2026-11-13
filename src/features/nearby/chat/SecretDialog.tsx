import { KeyRound } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { TERMS, useChatAction } from './model';

interface SecretDialogProps {
  peer: { key: string; name: string };
  onDone: () => void;
}

/**
 * A secret the user types for one contact: hidden on both computers and
 * wiped from both chats when its term ends. The dialog says the receiver
 * can copy it before then.
 */
export function SecretDialog({ peer, onDone }: SecretDialogProps) {
  const { t } = useTranslation();
  const [label, setLabel] = useState('');
  const [value, setValue] = useState('');
  const [term, setTerm] = useState<string>(String(TERMS[0].seconds));
  const send = useChatAction(
    () => api.chatSendSecret(peer.key, label.trim(), value, Number(term)),
    onDone,
  );
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (value) send.mutate(undefined);
  };
  return (
    <DialogContent section="nearby" className="max-w-[460px]">
      <form onSubmit={submit} className="contents">
        <DialogHeader
          icon={
            <Tile tone="pink" size={44} glow>
              <KeyRound className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('nearby.chat.secretDialog.title', { name: peer.name })}
          description={t('nearby.chat.secretDialog.note', { name: peer.name })}
        />
        <DialogBody>
          <TextField
            label={t('nearby.chat.secretDialog.labelLabel')}
            placeholder={t('nearby.chat.secretDialog.labelPlaceholder')}
            value={label}
            maxLength={64}
            onChange={(event) => setLabel(event.target.value)}
          />
          <TextField
            label={t('nearby.chat.secretDialog.value')}
            type="password"
            autoComplete="off"
            spellCheck={false}
            mono
            required
            value={value}
            onChange={(event) => setValue(event.target.value)}
          />
          <ChoiceCards
            legend={t('nearby.chat.secretDialog.term')}
            value={term}
            onValueChange={setTerm}
            columns={3}
            layout="row"
            options={TERMS.map((choice) => ({
              value: String(choice.seconds),
              title: t(choice.label),
            }))}
          />
        </DialogBody>
        <DialogFooter>
          <Button type="button" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" disabled={!value} loading={send.isPending}>
            {t('nearby.chat.secretDialog.send')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
