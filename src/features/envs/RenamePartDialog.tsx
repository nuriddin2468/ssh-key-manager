import { PencilLine } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { labelProblem } from './model';

/**
 * Renames a part: every stage in it takes the new name. For a project whose
 * parts are old groups' names (it had two before projects).
 */
export function RenamePartDialog({
  env,
  all,
  onDone,
}: {
  env: EnvSummary;
  all: readonly EnvSummary[];
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState(env.part);
  const [touched, setTouched] = useState(false);
  const ids = all
    .filter(
      (other) =>
        !other.inTrash &&
        other.project === env.project &&
        other.part.toLowerCase() === env.part.toLowerCase(),
    )
    .map((other) => other.id);
  const rename = useVaultMutation(() => api.envsSetPart(ids, name.trim()), {
    success: () => t('envs.renamePart.done', { part: env.part, name: name.trim() }),
    onSuccess: () => onDone(),
  });
  const problem = labelProblem(name);
  const unchanged = name.trim() === env.part;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (problem || unchanged || rename.isPending) return;
    rename.mutate(undefined);
  };

  return (
    <DialogContent section="envs" className="max-w-[440px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              <PencilLine className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('envs.renamePart.title', { part: env.part })}
          description={t('envs.renamePart.text', { part: env.part })}
        />
        <DialogBody>
          <TextField
            label={t('envs.renamePart.label')}
            value={name}
            onChange={(event) => setName(event.target.value)}
            error={touched && problem ? t(`envs.form.${problem}`) : undefined}
            autoFocus
          />
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            disabled={unchanged}
            loading={rename.isPending}
          >
            {t('envs.renamePart.go')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
