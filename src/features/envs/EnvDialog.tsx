import { Pencil, Plus } from 'lucide-react';
import { type FormEvent, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { errorMessage } from '@/api/useAppMutation';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { useProjects } from '@/features/projects/queries';
import { FirstPartField, useFirstPart } from './FirstPart';
import { useFolderField } from './FolderField';
import { refreshFileReports } from './files/queries';
import {
  KEEPASS_PERSONAL,
  labelProblem,
  nameTaken,
  partsOf,
  secondPart,
  whereLabel,
} from './model';
import { useProjectNames } from './useProjectNames';
import { PERSONAL, PickChip, partProblem, projectOf, WhereFields } from './WhereFields';

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
  // With one part, a new environment starts in it.
  const onlyPart = (choice: string) => {
    const parts = partsOf(all, projectOf(choice));
    return parts.length === 1 ? (parts[0] ?? '') : '';
  };
  const [part, setPart] = useState(() => env?.part ?? onlyPart(project));
  const [name, setName] = useState(env?.name ?? '');
  const [notes, setNotes] = useState(env?.notes ?? '');
  const [touched, setTouched] = useState(false);
  // The backend found the stage in the part, perhaps since the list was fetched.
  const [serverTaken, setServerTaken] = useState(false);
  const firstPart = useFirstPart();
  const naming = firstPart.naming;
  // An edited one is in its project already: it counts there as it is.
  const first = secondPart(all, projectId, [part], env ? [env.id] : []);

  const projects = useProjects().data;
  const folder = useFolderField({
    project: projects?.find((item) => item.id === projectId),
    all,
    part,
    stage: name,
    edited: env,
    onPartName: (next) => {
      setPart(next);
      setServerTaken(false);
    },
  });

  const input = { project: projectId, part: part.trim(), name, notes };
  const save = useVaultMutation(
    async () => {
      if (env) return api.envsUpdate(env.id, input, firstPart.rename, folder.change);
      if (!folder.adopt || projectId === null) {
        return api.envsCreate(input, firstPart.rename, folder.change);
      }
      // A `.env` file found in the folder: its variables come in, and the
      // app keeps it in sync from now on.
      const adopted = await api.envsFilesAdopt(
        projectId,
        folder.adopt.file,
        { type: 'new', project: projectId, part: part.trim(), name: name.trim(), notes },
        [],
        firstPart.rename,
        folder.change,
      );
      void refreshFileReports();
      return api.envsGet(adopted.id);
    },
    {
      success: (saved) =>
        env ? t('envs.saved', { name: saved.name }) : t('envs.created', { name: saved.name }),
      onSuccess: (saved) => {
        onSaved?.(saved);
        onDone(saved.id);
      },
      onError: (error) => {
        // The stage is taken: said at its field, in the form.
        if (error.code === 'already_exists') {
          firstPart.back();
          setTouched(true);
          setServerTaken(true);
          return true;
        }
        if (naming && error.code === 'invalid_input') {
          firstPart.refuse(errorMessage(t, error));
          return true;
        }
        return false;
      },
    },
  );

  const placeProblem = partProblem(part);
  const nameProblem = labelProblem(name);
  const taken =
    !nameProblem &&
    !placeProblem &&
    (serverTaken || nameTaken(all, projectId, part, name, env?.id));
  const problemText = (problem: ReturnType<typeof labelProblem>) =>
    problem ? t(`envs.form.${problem}`) : undefined;
  const ready = !placeProblem && !nameProblem && !taken;
  const projectName = projectId ? names.get(projectId) : undefined;
  const where = whereLabel(projectName ?? t('projects.personal'), part.trim());
  // Where KeePassXC shows a new one (as the backend files it; Personal
  // without a part has its own folder); an edited one stays where it is.
  const group = projectId ? [projectName, part.trim()] : [part.trim() || KEEPASS_PERSONAL];
  const path = [...group, name.trim()].filter(Boolean).join(' / ');

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (save.isPending) return;
    if (naming) {
      if (firstPart.confirm()) save.mutate(undefined);
      return;
    }
    setTouched(true);
    if (!ready) return;
    // The project gets its second part: its first is named in the same save.
    if (first) {
      firstPart.ask(first);
      return;
    }
    save.mutate(undefined);
  };
  const projectTitle = projectName ?? t('projects.personal');

  return (
    <DialogContent
      section="envs"
      className="max-w-[520px]"
      onBack={naming ? firstPart.back : undefined}
    >
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
            <FirstPartField state={firstPart} />
          </DialogBody>
        ) : (
          <DialogBody>
            <WhereFields
              all={all}
              project={project}
              part={part}
              onProject={(next) => {
                setProject(next);
                setPart(onlyPart(next));
                setServerTaken(false);
              }}
              onPart={(next) => {
                setPart(next);
                setServerTaken(false);
              }}
              touched={touched}
              partOnly={env !== null}
            />
            <div className="flex flex-col gap-2">
              <TextField
                label={t('envs.form.name')}
                value={name}
                placeholder={t('envs.form.namePlaceholder')}
                onChange={(event) => {
                  setName(event.target.value);
                  setServerTaken(false);
                }}
                error={
                  touched
                    ? (problemText(nameProblem) ??
                      (taken ? t('envs.form.taken', { where, stage: name.trim() }) : undefined))
                    : undefined
                }
              />
              <div className="flex flex-wrap items-center gap-1.5">
                {STAGES.map((stage) => (
                  <PickChip
                    key={stage}
                    label={stage}
                    ariaLabel={t('envs.form.useName', { name: stage })}
                    pressed={name === stage}
                    onClick={() => {
                      setName(stage);
                      setServerTaken(false);
                    }}
                  />
                ))}
              </div>
            </div>
            {env || !name.trim() ? null : (
              <p className="text-[12px] text-subtle">{t('envs.form.keepass', { path })}</p>
            )}
            {folder.node}
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
                className="field min-h-[76px] resize-y rounded-[10px] px-[11px] py-2 text-fg outline-none focus:border-[rgb(var(--accent-rgb)/var(--edge-alpha))] focus:shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.15)]"
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
