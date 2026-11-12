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
import { labelProblem, partsOf, stagesTaken, whereLabel } from './model';
import { useProjectNames } from './useProjectNames';

/**
 * Renames a part: every stage in it takes the new name, those in the
 * recycle bin too. A name the project has for another part joins the two,
 * unless both have a stage of one name.
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
  const names = useProjectNames();
  const [name, setName] = useState(env.part);
  const [touched, setTouched] = useState(false);
  // The backend found a stage there, perhaps since the list was fetched.
  const [serverTaken, setServerTaken] = useState(false);
  const ids = all
    .filter(
      (other) =>
        other.project === env.project && other.part.toLowerCase() === env.part.toLowerCase(),
    )
    .map((other) => other.id);
  const rename = useVaultMutation(() => api.envsSetPart(ids, name.trim()), {
    success: () => t('envs.renamePart.done', { part: env.part, name: name.trim() }),
    onSuccess: () => onDone(),
    onError: (error) => {
      if (error.code !== 'already_exists') return false;
      setTouched(true);
      setServerTaken(true);
      return true;
    },
  });
  const problem = labelProblem(name);
  const unchanged = name.trim() === env.part;
  const project = env.project ? (names.get(env.project) ?? '') : t('projects.personal');
  const where = whereLabel(project, name.trim());
  const taken = problem ? [] : stagesTaken(all, env.project, ids, name);
  // Another part of the project has this name: the two become one.
  const joins =
    !problem &&
    name.trim().toLowerCase() !== env.part.toLowerCase() &&
    partsOf(all, env.project).some((part) => part.toLowerCase() === name.trim().toLowerCase());
  const error = !touched
    ? undefined
    : problem
      ? t(`envs.form.${problem}`)
      : taken[0] !== undefined
        ? t('envs.form.taken', { where, stage: taken[0] })
        : serverTaken
          ? t('envs.renamePart.taken', { where })
          : undefined;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (problem || unchanged || taken.length > 0 || rename.isPending) return;
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
            onChange={(event) => {
              setName(event.target.value);
              setServerTaken(false);
            }}
            hint={joins ? t('envs.renamePart.joins', { part: name.trim() }) : undefined}
            error={error}
            autoFocus
          />
          {/* Said when it appears: the focus is on the button pressed. */}
          <p role="alert" className="sr-only">
            {error}
          </p>
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
