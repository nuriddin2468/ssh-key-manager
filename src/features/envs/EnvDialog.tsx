import { Pencil, Plus } from 'lucide-react';
import { type FormEvent, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { cn } from '@/lib/cn';
import { labelProblem, nameTaken, projects } from './model';

/** Names most projects use, offered as one-click fills. */
const STAGES = ['dev', 'staging', 'prod'] as const;

interface EnvDialogProps {
  /** The environment to rename; `null` makes a new one. */
  env: EnvDetail | null;
  all: EnvSummary[];
  /** The project a new environment starts in. */
  defaultProject?: string;
  /** Closes the dialog, with the environment's id when it was saved. */
  onDone: (id?: string) => void;
}

/** A new environment, or a new name, project or notes for one. */
export function EnvDialog({ env, all, defaultProject, onDone }: EnvDialogProps) {
  const { t } = useTranslation();
  const listId = useId();
  const notesId = useId();
  const [project, setProject] = useState(env?.project ?? defaultProject ?? '');
  const [name, setName] = useState(env?.name ?? '');
  const [notes, setNotes] = useState(env?.notes ?? '');
  const [touched, setTouched] = useState(false);

  const save = useVaultMutation(
    () =>
      env
        ? api.envsUpdate(env.id, { project, name, notes })
        : api.envsCreate({ project, name, notes }),
    {
      success: (saved) =>
        env ? t('envs.saved', { name: saved.name }) : t('envs.created', { name: saved.name }),
      onSuccess: (saved) => onDone(saved.id),
      onError: (error) => {
        if (error.code !== 'already_exists') return false;
        setTouched(true);
        return true;
      },
    },
  );

  const projectProblem = labelProblem(project);
  const nameProblem = labelProblem(name);
  const taken = !nameProblem && !projectProblem && nameTaken(all, project, name, env?.id);
  const problemText = (problem: ReturnType<typeof labelProblem>) =>
    problem ? t(`envs.form.${problem}`) : undefined;
  const ready = !projectProblem && !nameProblem && !taken;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (ready && !save.isPending) save.mutate(undefined);
  };

  return (
    <DialogContent section="envs" className="max-w-[520px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="lime" size={44} glow>
              {env ? (
                <Pencil className="size-5" strokeWidth={2} />
              ) : (
                <Plus className="size-[22px]" strokeWidth={2.25} />
              )}
            </Tile>
          }
          title={env ? t('envs.form.editTitle') : t('envs.form.newTitle')}
          description={t('envs.form.description')}
        />
        <DialogBody>
          <TextField
            label={t('envs.form.project')}
            value={project}
            list={listId}
            placeholder={t('envs.form.projectPlaceholder')}
            onChange={(event) => setProject(event.target.value)}
            error={touched ? problemText(projectProblem) : undefined}
            hint={t('envs.form.projectHint')}
          />
          <datalist id={listId}>
            {projects(all).map((item) => (
              <option key={item} value={item} />
            ))}
          </datalist>
          <div className="flex flex-col gap-2">
            <TextField
              label={t('envs.form.name')}
              value={name}
              placeholder={t('envs.form.namePlaceholder')}
              onChange={(event) => setName(event.target.value)}
              error={
                touched
                  ? (problemText(nameProblem) ??
                    (taken ? t('envs.form.taken', { project: project.trim() }) : undefined))
                  : undefined
              }
            />
            <div className="flex flex-wrap items-center gap-1.5">
              {STAGES.map((stage) => (
                <button
                  key={stage}
                  type="button"
                  aria-label={t('envs.form.useName', { name: stage })}
                  onClick={() => setName(stage)}
                  className={cn(
                    'pressable rounded-full border px-2.5 py-0.5 font-mono text-[12px]',
                    name === stage
                      ? 'border-[rgb(var(--accent-rgb)/0.5)] bg-[rgb(var(--accent-rgb)/0.14)] text-[var(--accent-text)]'
                      : 'border-white/10 bg-white/[0.04] text-fg-2 hover:bg-white/[0.08]',
                  )}
                >
                  {stage}
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor={notesId} className="text-[12px] font-semibold text-fg-2">
              {t('envs.form.notes')}
            </label>
            <textarea
              id={notesId}
              value={notes}
              onChange={(event) => setNotes(event.target.value)}
              rows={3}
              placeholder={t('envs.form.notesPlaceholder')}
              className="field min-h-[76px] resize-y rounded-[10px] px-[11px] py-2 text-fg outline-none focus:border-[rgb(var(--accent-rgb)/0.55)] focus:shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.15)]"
            />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={() => onDone()}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" size="lg" loading={save.isPending}>
            {env ? t('common.save') : t('envs.form.create')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
