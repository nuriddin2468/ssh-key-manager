import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Select } from '@/components/ui/Select';
import { TextField } from '@/components/ui/TextField';
import { PersonalTile, ProjectTile } from '@/features/projects/ProjectTile';
import { useProjects } from '@/features/projects/queries';
import { labelProblem, partsOf } from './model';

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

/** Where an environment goes: a project (or Personal) and an optional part. */
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
  const listId = useId();
  const projects = useProjects().data ?? [];
  const problem = partProblem(part);
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
      <TextField
        label={t('envs.form.part')}
        value={part}
        list={listId}
        placeholder={t('envs.form.partPlaceholder')}
        onChange={(event) => onPart(event.target.value)}
        error={touched && problem ? t(`envs.form.${problem}`) : undefined}
        hint={t('envs.form.partHint')}
      />
      <datalist id={listId}>
        {partsOf(all, projectOf(project)).map((item) => (
          <option key={item} value={item} />
        ))}
      </datalist>
    </>
  );
}
