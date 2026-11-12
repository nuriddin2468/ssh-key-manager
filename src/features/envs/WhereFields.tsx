import { useTranslation } from 'react-i18next';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Select } from '@/components/ui/Select';
import { TextField } from '@/components/ui/TextField';
import { PersonalTile, ProjectTile } from '@/features/projects/ProjectTile';
import { useProjects } from '@/features/projects/queries';
import { cn } from '@/lib/cn';
import { useFilesOverview } from './files/queries';
import { folderParts, labelProblem, partsOf } from './model';

/** Personal in the project choice: Select values are strings, never empty. */
export const PERSONAL = 'personal';

/** The project (by id) a choice names; `null` for Personal. */
export function projectOf(choice: string): string | null {
  return choice === PERSONAL ? null : choice;
}

/** What a part may be: none, or a name like a project's. */
export function partProblem(part: string): ReturnType<typeof labelProblem> {
  return part.trim() === '' ? null : labelProblem(part);
}

interface WhereFieldsProps {
  all: readonly EnvSummary[];
  /** A project's id, or [`PERSONAL`]. */
  project: string;
  part: string;
  onProject: (project: string) => void;
  onPart: (part: string) => void;
  /** Show the part's problem (after a first try). */
  touched: boolean;
  /** Without the project (where the project is given). */
  partOnly?: boolean;
}

/**
 * Where an environment goes: a project (or Personal) and an optional part.
 * The parts the project has and the folders in it with a `.env` are
 * offered under the part's field as chips, in two labelled rows, as the
 * stages are: seen without opening anything, and plain buttons for
 * keyboards and screen readers.
 */
export function WhereFields({
  all,
  project,
  part,
  onProject,
  onPart,
  touched,
  partOnly = false,
}: WhereFieldsProps) {
  const { t } = useTranslation();
  const projects = useProjects().data ?? [];
  const problem = partProblem(part);
  const chosen = projectOf(project);
  const parts = partsOf(all, chosen);
  // Folders in the project with a `.env` (`backend/.env`) name parts too.
  const overview = useFilesOverview(chosen, chosen !== null).data;
  const fromFolders =
    chosen === null
      ? []
      : folderParts(
          [
            ...(overview?.files ?? []).map((report) => report.file.path),
            ...(overview?.unmanaged ?? []).map((found) => found.file.path),
          ],
          parts,
        );
  return (
    <>
      {partOnly ? null : (
        <Select
          label={t('envs.form.project')}
          value={project}
          onValueChange={onProject}
          options={[
            { value: PERSONAL, label: t('projects.personal'), icon: <PersonalTile size={18} /> },
            ...projects.map((item) => ({
              value: item.id,
              label: item.name,
              icon: <ProjectTile project={item} size={18} />,
            })),
          ]}
        />
      )}
      <div className="flex min-w-0 flex-col gap-2">
        <TextField
          label={t('envs.form.part')}
          value={part}
          placeholder={t('envs.form.partPlaceholder')}
          onChange={(event) => onPart(event.target.value)}
          error={touched && problem ? t(`envs.form.${problem}`) : undefined}
          hint={t('envs.form.partHint')}
        />
        {parts.length > 0 ? (
          <Suggestions
            label={t('envs.form.partsIn', {
              project:
                chosen === null
                  ? t('projects.personal')
                  : (projects.find((item) => item.id === chosen)?.name ?? ''),
            })}
            items={[...parts, '']}
            value={part}
            onPick={onPart}
          />
        ) : null}
        {fromFolders.length > 0 ? (
          <Suggestions
            label={t('envs.form.partsFromFolders')}
            items={fromFolders}
            value={part}
            onPick={onPart}
          />
        ) : null}
      </div>
    </>
  );
}

/** A labelled row of parts to pick; `''` is No part. */
function Suggestions({
  label,
  items,
  value,
  onPick,
}: {
  label: string;
  items: readonly string[];
  value: string;
  onPick: (part: string) => void;
}) {
  const { t } = useTranslation();
  return (
    // A floated legend lays out as a flex item, on the chips' line.
    <fieldset className="m-0 flex min-w-0 flex-wrap items-center gap-1.5 border-0 p-0">
      <legend className="float-left mr-0.5 p-0 text-[11.5px] text-subtle">{label}</legend>
      {items.map((item) => (
        <PickChip
          key={item}
          label={item === '' ? t('envs.noPart') : item}
          mono={item !== ''}
          pressed={item.toLowerCase() === value.trim().toLowerCase()}
          onClick={() => onPick(item)}
        />
      ))}
    </fieldset>
  );
}

/** A one-click fill for a field: a stage, a part. */
export function PickChip({
  label,
  pressed,
  mono = true,
  onClick,
  ariaLabel,
}: {
  label: string;
  pressed: boolean;
  mono?: boolean;
  onClick: () => void;
  ariaLabel?: string;
}) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      aria-label={ariaLabel}
      onClick={onClick}
      className={cn(
        'pressable rounded-full border px-2.5 py-0.5 text-[12px]',
        mono && 'font-mono',
        pressed
          ? 'border-[rgb(var(--accent-rgb)/0.5)] bg-[rgb(var(--accent-rgb)/0.14)] text-[var(--accent-text)]'
          : 'border-white/10 bg-white/[0.04] text-fg-2 hover:bg-white/[0.08]',
      )}
    >
      {label}
    </button>
  );
}
