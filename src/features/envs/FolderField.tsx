import { type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { PartFolderChoice } from '@/bindings/PartFolderChoice';
import type { Project } from '@/bindings/Project';
import type { ProjectFolder } from '@/bindings/ProjectFolder';
import type { UnmanagedEnvFile } from '@/bindings/UnmanagedEnvFile';
import { Checkbox } from '@/components/ui/Checkbox';
import { FolderChoices } from '@/features/projects/FolderChoices';
import {
  automaticOf,
  fileForStage,
  folderChange,
  folderOptions,
  lastName,
  placeOfPart,
  placeText,
  startOption,
  unmanagedIn,
  usePlaces,
} from '@/features/projects/places';
import { useFilesOverview } from './files/queries';
import { kindFromName } from './model';

interface FolderFieldOptions {
  /** The project the environment goes into; none for Personal, which has no folders. */
  project: Project | undefined;
  all: readonly EnvSummary[];
  /** The part as typed. */
  part: string;
  /** The stage as typed: a local one may take a `.env` file found in the folder. */
  stage: string;
  /** A new environment (an edited one changes only its part's folder). */
  creating: boolean;
  /** Names an empty part after a folder picked for it. */
  onPartName: (part: string) => void;
}

interface FolderField {
  /** The field; `null` without a project with folders. */
  node: ReactNode;
  /** What saving changes about the part's folder; `null` for nothing. */
  change: PartFolderChoice | null;
  /** A `.env` file in the folder to take under management with a new local stage. */
  adopt: UnmanagedEnvFile | null;
}

/**
 * The folder of the environment's part, in its dialog: where every stage of
 * the part opens its terminal. Automatic, the folders with `.env` files,
 * the project's folders, or another. A new local stage may take a `.env`
 * file the app doesn't manage yet that it finds there.
 */
export function useFolderField({
  project,
  all,
  part,
  stage,
  creating,
  onPartName,
}: FolderFieldOptions): FolderField {
  const { t } = useTranslation();
  const places = usePlaces(project?.id);
  const overview = useFilesOverview(project?.id ?? null, Boolean(project)).data;
  const [picked, setPicked] = useState<ProjectFolder | null>(null);
  const [value, setValue] = useState<string | null>(null);
  const [useFile, setUseFile] = useState(true);
  const folders = project?.folders ?? [];
  const current = placeOfPart(places.data, part);
  const options = folderOptions({ part: current, folders, overview, picked });
  const start = startOption(current);
  // A choice the options no longer have (another part typed) goes back to the start.
  const chosen = value !== null && options.some((option) => option.value === value) ? value : start;
  const automatic = automaticOf(current, folders);
  const place = options.find((option) => option.value === chosen)?.place ?? automatic.place;
  const local = kindFromName(stage) === 'local';
  const file = creating && local ? fileForStage(unmanagedIn(overview, place), stage) : undefined;

  if (!project || folders.length === 0 || places.isPending) {
    return { node: null, change: null, adopt: null };
  }
  // An unnamed part the project has stays unnamed: naming it would make a second.
  const unnamed = all.some(
    (env) => !env.inTrash && env.project === project.id && env.part.trim() === '',
  );
  const name = part.trim() || project.name;
  const node = (
    <div className="flex min-w-0 flex-col gap-2">
      <FolderChoices
        project={project}
        options={options}
        automatic={automatic}
        value={chosen}
        onValueChange={(next) => {
          setValue(next);
          const at = options.find((option) => option.value === next)?.place;
          if (at && part.trim() === '' && !unnamed && creating) {
            onPartName(lastName(at.path || at.folder));
          }
        }}
        onPicked={(at) => {
          setPicked(at);
          if (part.trim() === '' && !unnamed && creating)
            onPartName(lastName(at.path || at.folder));
        }}
        legend={t('envs.form.folder')}
      />
      <p className="text-[12px] text-subtle">{t('envs.form.folderHint', { part: name })}</p>
      {file ? (
        <div className="flex flex-col gap-1 rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-2.5">
          <Checkbox
            checked={useFile}
            onCheckedChange={setUseFile}
            label={
              <span className="flex flex-col gap-0.5">
                <span className="font-mono text-[12.5px]">
                  {t('envs.form.useFile', {
                    file: placeText({ folder: file.file.folder, path: file.file.path }, folders),
                  })}
                </span>
                <span className="text-[12px] leading-4 font-normal text-subtle">
                  {t('envs.form.useFileHint')}
                </span>
              </span>
            }
          />
        </div>
      ) : null}
    </div>
  );
  return {
    node,
    change: folderChange(options, chosen, start),
    adopt: file && useFile ? file : null,
  };
}
