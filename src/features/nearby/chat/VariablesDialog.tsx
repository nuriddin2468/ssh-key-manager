import { Variable } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { Tile } from '@/components/ui/Tile';
import { useEnv, useEnvs } from '@/features/envs/queries';
import { TERMS, useChatAction } from './model';

interface VariablesDialogProps {
  peer: { key: string; name: string };
  onDone: () => void;
}

/**
 * Variables of one of the user's environments for a contact. The page
 * names them; the backend reads their values from the vault.
 */
export function VariablesDialog({ peer, onDone }: VariablesDialogProps) {
  const { t } = useTranslation();
  const envs = (useEnvs().data ?? []).filter((env) => !env.inTrash);
  const [envId, setEnvId] = useState<string>('');
  const chosen = envId || envs[0]?.id || '';
  const env = useEnv(chosen || undefined);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [term, setTerm] = useState<string>(String(TERMS[0].seconds));
  const names = env.data?.variables.map((variable) => variable.name) ?? [];
  const send = useChatAction(
    () =>
      api.chatSendVariables(
        peer.key,
        chosen,
        names.filter((name) => picked.has(name)),
        Number(term),
      ),
    onDone,
  );
  const count = names.filter((name) => picked.has(name)).length;
  const toggle = (name: string, on: boolean) =>
    setPicked((before) => {
      const next = new Set(before);
      if (on) next.add(name);
      else next.delete(name);
      return next;
    });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (count > 0) send.mutate(undefined);
  };
  return (
    <DialogContent section="nearby" className="max-w-[500px]">
      <form onSubmit={submit} className="contents">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <Variable className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('nearby.chat.variablesDialog.title', { name: peer.name })}
          description={t('nearby.chat.variablesDialog.note', { name: peer.name })}
        />
        <DialogBody>
          <Select
            label={t('nearby.chat.variablesDialog.environment')}
            value={chosen}
            onValueChange={(next) => {
              setEnvId(next);
              setPicked(new Set());
            }}
            options={envs.map((item) => ({
              value: item.id,
              label: [item.group, item.name].filter(Boolean).join(' · '),
            }))}
          />
          <fieldset className="flex flex-col gap-1.5">
            <legend className="mb-1.5 text-[12px] font-semibold tracking-[0.02em] text-subtle">
              {t('nearby.chat.variablesDialog.pick')}
            </legend>
            {names.length === 0 ? (
              <p className="text-[12.5px] text-subtle">{t('nearby.chat.variablesDialog.none')}</p>
            ) : (
              <ul className="glass flex max-h-[220px] flex-col gap-0.5 overflow-y-auto rounded-xl p-1.5">
                {env.data?.variables.map((variable) => (
                  <li key={variable.name}>
                    <Checkbox
                      checked={picked.has(variable.name)}
                      onCheckedChange={(on) => toggle(variable.name, on)}
                      label={<span className="font-mono text-[12.5px]">{variable.name}</span>}
                    />
                  </li>
                ))}
              </ul>
            )}
          </fieldset>
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
          <Button type="submit" variant="primary" disabled={count === 0} loading={send.isPending}>
            {t('nearby.chat.variablesDialog.send', { count: Math.max(count, 1) })}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
