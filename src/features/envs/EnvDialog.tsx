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
import { FirstPartField, useFirstPart } from './FirstPart';
import { labelProblem, nameTaken, partsOf, secondPart, whereLabel } from './model';
import { useProjectNames } from './useProjectNames';
import { PERSONAL, partProblem, projectOf, WhereFields } from './WhereFields';

/** Stages most projects use, offered as one-click fills. */
const STAGES = ['local', 'dev', 'staging', 'prod'] as const;

interface EnvDialogProps {
  /** The environment to edit; `null` makes a new one. */
  env: EnvDetail | null;
  all: EnvSummary[];
  /** The project a new environment starts in (by id); Personal without it. */
  defaultProject?: string | null;
  /** Closes the dialog, with the environment's id when it was saved. */
  onDone: (id?: string) => void;
  /** Called with the environment once it is saved, before `onDone`. */
  onSaved?: (saved: EnvDetail) => void;
}

/**
 * A new environment in a project (or Personal), with an optional part and
 * its stage; or another part, stage or notes for one (it moves to another
 * project with Move to project…). When that gives the project its second
 * part, the part its environments share is named first.
 */
export function EnvDialog({ env, all, defaultProject, onDone, onSaved }: EnvDialogProps) {
  const { t } = useTranslation();
  const notesId = useId();
  const names = useProjectNames();
  const [project, setProject] = useState(
    env ? (env.project ?? PERSONAL) : (defaultProject ?? PERSONAL),
  );
  const projectId = projectOf(project);
  const parts = partsOf(all, projectId);
  // With one part, a new environment starts in it.
  const [part, setPart] = useState(env?.part ?? (parts.length === 1 ? (parts[0] ?? '') : ''));
  const [name, setName] = useState(env?.name ?? '');
  const [notes, setNotes] = useState(env?.notes ?? '');
  const [touched, setTouched] = useState(false);
  const firstPart = useFirstPart();
  const first = secondPart(all, projectId, part, env?.id);

  const input = { project: projectId, part: part.trim(), name, notes };
  const save = useVaultMutation(
    async () => {
      const naming = firstPart.naming;
      if (naming) await api.envsSetPart(naming.ids, firstPart.name.trim());
      return env ? api.envsUpdate(env.id, input) : api.envsCreate(input);
    },
    {
      success: (saved) =>
        env ? t('envs.saved', { name: saved.name }) : t('envs.created', { name: saved.name }),
      onSuccess: (saved) => {
        onSaved?.(saved);
        onDone(saved.id);
      },
      onError: (error) => {
        if (error.code !== 'already_exists') return false;
        setTouched(true);
        return true;
      },
    },
  );

  const placeProblem = partProblem(part);
  const nameProblem = labelProblem(name);
  const taken = !nameProblem && !placeProblem && nameTaken(all, projectId, part, name, env?.id);
  const problemText = (problem: ReturnType<typeof labelProblem>) =>
    problem ? t(`envs.form.${problem}`) : undefined;
  const ready = !placeProblem && !nameProblem && !taken;
  const projectName = projectId ? names.get(projectId) : undefined;
  const where = whereLabel(projectName ?? t('projects.personal'), part.trim());
  // Where KeePassXC shows a new one; an edited one stays where it is.
  const path = [projectName, part.trim(), name.trim()].filter(Boolean).join(' / ');

  const naming = firstPart.naming;
  const namingProblem = naming ? firstPart.problem(part) : null;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (!ready || save.isPending) return;
    // The project gets its second part: its first is named before.
    if (first && !naming) {
      firstPart.ask(first);
      return;
    }
    if (namingProblem) return;
    save.mutate(undefined);
  };
  const projectTitle = projectName ?? t('projects.personal');

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
          title={
            naming
              ? t('envs.firstPart.title', { project: projectTitle })
              : env
                ? t('envs.form.editTitle')
                : t('envs.form.newTitle')
          }
          description={naming ? t('envs.firstPart.text') : t('envs.form.description')}
        />
        {naming ? (
          <DialogBody>
            <FirstPartField
              value={firstPart.name}
              onChange={firstPart.setName}
              part={part}
              problem={namingProblem}
              touched={touched}
            />
          </DialogBody>
        ) : (
          <DialogBody>
            <WhereFields
              all={all}
              project={project}
              part={part}
              onProject={setProject}
              onPart={setPart}
              touched={touched}
              partOnly={env !== null}
            />
            <div className="flex flex-col gap-2">
              <TextField
                label={t('envs.form.name')}
                value={name}
                placeholder={t('envs.form.namePlaceholder')}
                onChange={(event) => setName(event.target.value)}
                error={
                  touched
                    ? (problemText(nameProblem) ??
                      (taken ? t('envs.form.taken', { where, stage: name.trim() }) : undefined))
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
            {env || !name.trim() ? null : (
              <p className="text-[12px] text-subtle">{t('envs.form.keepass', { path })}</p>
            )}
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
        )}
        <DialogFooter>
          {naming ? (
            <Button size="lg" onClick={firstPart.back}>
              {t('envs.firstPart.back')}
            </Button>
          ) : (
            <Button size="lg" onClick={() => onDone()}>
              {t('common.cancel')}
            </Button>
          )}
          <Button type="submit" variant="primary" size="lg" loading={save.isPending}>
            {naming ? t('envs.firstPart.go') : env ? t('common.save') : t('envs.form.create')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
