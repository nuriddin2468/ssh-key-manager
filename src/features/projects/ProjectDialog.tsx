import { FolderKanban, Pencil } from 'lucide-react';
import { type FormEvent, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { Project } from '@/bindings/Project';
import type { ProjectColor } from '@/bindings/ProjectColor';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/TextField';
import { useVaultMutation } from '@/features/passwords/vault';
import { nextColor } from './model';
import { ColorPicker, ProjectTile } from './ProjectTile';
import { refreshSuggestions } from './queries';

/** Characters KeePass apps split tags at, and the most a name has. */
const NAME_CHARS = /[\p{Cc};,:]/u;
const MAX_NAME = 64;

/** Why a project name can't be used, as an `projects.form.*` key, or `null`. */
export function nameProblem(name: string): 'nameEmpty' | 'nameLong' | 'nameChars' | null {
  const trimmed = name.trim();
  if (!trimmed) return 'nameEmpty';
  if ([...trimmed].length > MAX_NAME) return 'nameLong';
  if (NAME_CHARS.test(trimmed)) return 'nameChars';
  return null;
}

interface ProjectDialogProps {
  /** The project to rename or recolor; `null` makes a new one. */
  project: Project | null;
  all: Project[];
  /** Closes the dialog, with the project when it was saved. */
  onDone: (saved?: Project) => void;
}

/** A new project, or a new name and color for one. */
export function ProjectDialog({ project, all, onDone }: ProjectDialogProps) {
  const { t } = useTranslation();
  const colorLabel = useId();
  const [name, setName] = useState(project?.name ?? '');
  const [color, setColor] = useState<ProjectColor>(project?.color ?? nextColor(all));
  const [touched, setTouched] = useState(false);
  const [takenName, setTakenName] = useState<string | null>(null);

  const save = useVaultMutation(
    () =>
      project
        ? api.projectsUpdate(project.id, { name, color })
        : api.projectsCreate({ name, color }),
    {
      success: (saved) =>
        project
          ? t('projects.form.saved', { name: saved.name })
          : t('projects.form.created', { name: saved.name }),
      onSuccess: (saved) => {
        void refreshSuggestions();
        onDone(saved);
      },
      onError: (error) => {
        if (error.code !== 'already_exists') return false;
        setTakenName(name.trim());
        return true;
      },
    },
  );

  const problem = nameProblem(name);
  const taken =
    takenName === name.trim() ||
    all.some(
      (other) => other.id !== project?.id && other.name.toLowerCase() === name.trim().toLowerCase(),
    );
  const ready = !problem && !taken;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (ready && !save.isPending) save.mutate(undefined);
  };

  return (
    <DialogContent section="project" className="max-w-[480px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            project ? (
              <ProjectTile project={{ name: name || project.name, color }} size={44} />
            ) : (
              <ProjectTile project={{ name: name || '+', color }} size={44} />
            )
          }
          title={project ? t('projects.form.editTitle') : t('projects.form.newTitle')}
          description={t('projects.form.description')}
        />
        <DialogBody>
          <TextField
            label={t('projects.form.name')}
            value={name}
            placeholder={t('projects.form.namePlaceholder')}
            onChange={(event) => setName(event.target.value)}
            maxLength={MAX_NAME + 8}
            error={
              touched
                ? problem
                  ? t(`projects.form.${problem}`)
                  : taken
                    ? t('projects.form.taken', { name: name.trim() })
                    : undefined
                : undefined
            }
            hint={t('projects.form.nameHint')}
          />
          <div className="flex flex-col gap-2">
            <span id={colorLabel} className="text-[12px] font-semibold text-fg-2">
              {t('projects.form.color')}
            </span>
            <ColorPicker value={color} onChange={setColor} labelId={colorLabel} />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => onDone()}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            loading={save.isPending}
            icon={
              project ? (
                <Pencil className="size-4" strokeWidth={2} />
              ) : (
                <FolderKanban className="size-4" strokeWidth={2} />
              )
            }
          >
            {project ? t('projects.form.save') : t('projects.form.create')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
