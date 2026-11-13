import { useQuery } from '@tanstack/react-query';
import { ShieldAlert, Variable } from 'lucide-react';
import { type FormEvent, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { useEnvs } from '@/features/envs/queries';
import { useChatAction } from './model';

/** The value the target select gives a new environment (a select value is never empty). */
const NEW = 'new';

interface AddVariablesDialogProps {
  peer: { key: string; name: string };
  /** The received variables message. */
  id: string;
  onDone: () => void;
}

/**
 * Received variables, reviewed before they go into one of the user's
 * environments: what each would add or replace. New names are ticked;
 * replacing a value and names that change how programs start never are.
 * Nothing is saved until the user clicks Add.
 */
export function AddVariablesDialog({ peer, id, onDone }: AddVariablesDialogProps) {
  const { t } = useTranslation();
  const envs = (useEnvs().data ?? []).filter((env) => !env.inTrash);
  const [target, setTarget] = useState<string>(NEW);
  const [newName, setNewName] = useState(peer.name);
  const review = useQuery({
    queryKey: ['chats', 'review', peer.key, id, target],
    queryFn: () => api.chatReviewVariables(peer.key, id, target === NEW ? null : target),
    gcTime: 0,
  });
  const [picked, setPicked] = useState<Set<string>>(new Set());
  // A new review ticks what is safe to add: new names that start nothing.
  useEffect(() => {
    setPicked(
      new Set(
        (review.data ?? [])
          .filter((variable) => variable.change === 'new' && !variable.risky)
          .map((variable) => variable.name),
      ),
    );
  }, [review.data]);
  const count = picked.size;
  const add = useChatAction(
    () =>
      api.chatAddVariables(
        peer.key,
        id,
        target === NEW
          ? { type: 'new', name: newName.trim() }
          : { type: 'existing', envId: target },
        [...picked],
      ),
    () => {
      const env = envs.find((item) => item.id === target)?.name ?? newName.trim();
      toast.success(t('nearby.chat.addDialog.added', { env }));
      void invalidateAll();
      onDone();
    },
  );
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (count > 0 && (target !== NEW || newName.trim())) add.mutate(undefined);
  };
  const toggle = (name: string, on: boolean) =>
    setPicked((before) => {
      const next = new Set(before);
      if (on) next.add(name);
      else next.delete(name);
      return next;
    });
  return (
    <DialogContent section="nearby" className="max-w-[520px]">
      <form onSubmit={submit} className="contents">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <Variable className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('nearby.chat.addDialog.title', { name: peer.name })}
          description={t('nearby.chat.addDialog.note')}
        />
        <DialogBody>
          <Select
            label={t('nearby.chat.addDialog.to')}
            value={target}
            onValueChange={setTarget}
            options={[
              { value: NEW, label: t('nearby.chat.addDialog.newEnv') },
              ...envs.map((item) => ({
                value: item.id,
                label: [item.group, item.name].filter(Boolean).join(' · '),
              })),
            ]}
          />
          {target === NEW ? (
            <TextField
              label={t('nearby.chat.addDialog.newName')}
              value={newName}
              maxLength={64}
              required
              onChange={(event) => setNewName(event.target.value)}
            />
          ) : null}
          <ul className="glass flex max-h-[260px] flex-col gap-0.5 overflow-y-auto rounded-xl p-1.5">
            {(review.data ?? []).map((variable) => (
              <li key={variable.name} className="flex items-center gap-2 pr-1">
                <Checkbox
                  className="min-w-0 flex-1"
                  checked={picked.has(variable.name)}
                  disabled={variable.change === 'same'}
                  onCheckedChange={(on) => toggle(variable.name, on)}
                  label={
                    // A name may be long (255 characters): cut, whole in the title.
                    <span title={variable.name} className="block truncate font-mono text-[12.5px]">
                      {variable.name}
                    </span>
                  }
                />
                {variable.risky ? (
                  <Badge tone="warning">
                    <ShieldAlert aria-hidden="true" className="mr-1 size-3" strokeWidth={2} />
                    {t('nearby.chat.addDialog.risky')}
                  </Badge>
                ) : null}
                <Badge
                  tone={
                    variable.change === 'replaces'
                      ? 'warning'
                      : variable.change === 'new'
                        ? 'accent'
                        : 'neutral'
                  }
                >
                  {t(`nearby.chat.addDialog.${variable.change}`)}
                </Badge>
              </li>
            ))}
          </ul>
        </DialogBody>
        <DialogFooter>
          <Button type="button" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            disabled={count === 0 || (target === NEW && !newName.trim())}
            loading={add.isPending}
          >
            {t('nearby.chat.addDialog.add', { count: Math.max(count, 1) })}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
