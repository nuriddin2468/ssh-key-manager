import { FolderOpen } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { Project } from '@/bindings/Project';
import type { ProjectFolder } from '@/bindings/ProjectFolder';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { useFilesOverview } from '@/features/envs/files/queries';
import { useVaultMutation } from '@/features/passwords/vault';
import { FolderChoices } from './FolderChoices';
import {
  automaticOf,
  folderChange,
  folderOptions,
  placeOfPart,
  placeText,
  startOption,
  usePlaces,
} from './places';

interface PartFolderDialogProps {
  project: Project;
  /** The part, as its environments name it; empty for a project's one unnamed part. */
  part: string;
  onDone: () => void;
}

/**
 * Sets the folder a part of a project's environments works in: where all its
 * stages, local and remote, open their terminals. Automatic is where its
 * local stage's `.env` file is, else the project's first folder.
 */
export function PartFolderDialog({ project, part, onDone }: PartFolderDialogProps) {
  const { t } = useTranslation();
  const places = usePlaces(project.id);
  const overview = useFilesOverview(project.id).data;
  const current = placeOfPart(places.data, part);
  const [picked, setPicked] = useState<ProjectFolder | null>(null);
  const [value, setValue] = useState<string | null>(null);
  const options = folderOptions({ part: current, folders: project.folders, overview, picked });
  const start = startOption(current);
  const chosen = value ?? start;
  const change = folderChange(options, chosen, start);
  const name = part || project.name;

  const save = useVaultMutation(
    () =>
      api.projectsSetPartFolder(
        project.id,
        part,
        change?.type === 'folder' ? { folder: change.folder, path: change.path } : null,
      ),
    {
      success: () =>
        change?.type === 'folder'
          ? t('projects.partFolder.done', {
              part: name,
              path: placeText(change, project.folders),
            })
          : t('projects.partFolder.automaticDone', { part: name }),
      onSuccess: () => onDone(),
    },
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (save.isPending) return;
    if (!change) {
      onDone();
      return;
    }
    save.mutate(undefined);
  };

  return (
    <DialogContent section="project" className="max-w-[520px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="green" size={44} glow>
              <FolderOpen className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={
            part
              ? t('projects.partFolder.title', { part })
              : t('projects.partFolder.titleProject', { project: project.name })
          }
          description={t('projects.partFolder.text', { part: name })}
        />
        <DialogBody>
          {places.isPending ? (
            <div className="grid place-items-center py-8 text-subtle">
              <Spinner className="size-5" />
            </div>
          ) : (
            <FolderChoices
              project={project}
              options={options}
              automatic={automaticOf(current, project.folders)}
              value={chosen}
              onValueChange={setValue}
              onPicked={setPicked}
              legend={t('projects.partFolder.legend')}
              legendHidden
            />
          )}
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={save.isPending}
            disabled={!change}
          >
            {t('common.save')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
