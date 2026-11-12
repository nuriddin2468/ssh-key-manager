import { useMutation } from '@tanstack/react-query';
import { FolderSearch } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError } from '@/api/useAppMutation';
import type { ProjectFolder } from '@/bindings/ProjectFolder';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { AppError } from '@/lib/ipc';
import { type FolderOption, placeKey, placeText } from './places';

interface FolderChoicesProps {
  project: { id: string; folders: string[] };
  options: readonly FolderOption[];
  /** Where automatic leads, and whether that is where a `.env` file is. */
  automatic: { place: ProjectFolder | null; fromFile: boolean };
  value: string;
  onValueChange: (value: string) => void;
  /** A folder from the system dialog: offered, then chosen. */
  onPicked: (place: ProjectFolder) => void;
  legend: string;
  legendHidden?: boolean;
}

/**
 * The folders a part may work in, one to choose: automatic (and where that
 * leads), the folders its `.env` files are in, the project's folders, and
 * another from the system dialog, which must be in one of the project's.
 */
export function FolderChoices({
  project,
  options,
  automatic,
  value,
  onValueChange,
  onPicked,
  legend,
  legendHidden = false,
}: FolderChoicesProps) {
  const { t } = useTranslation();
  const [outside, setOutside] = useState(false);
  const pick = useMutation({
    mutationFn: () => api.projectsPickPartFolder(project.id),
    onSuccess: (picked) => {
      if (!picked) return;
      setOutside(false);
      onPicked(picked);
      onValueChange(placeKey(picked));
    },
    onError: (error) => {
      // Not in one of the project's folders: said here, in words.
      if (AppError.from(error).code === 'invalid_input') setOutside(true);
      else toastError(t, error);
    },
  });
  const text = (place: ProjectFolder) => placeText(place, project.folders);
  const hint = (option: FolderOption) => {
    switch (option.hint) {
      case 'automatic':
        return automatic.place
          ? t(
              automatic.fromFile
                ? 'projects.partFolder.automaticFile'
                : 'projects.partFolder.automaticFolder',
              { path: text(automatic.place) },
            )
          : undefined;
      case 'current':
        return t('projects.partFolder.current');
      case 'files':
        return t('projects.partFolder.files');
      case 'project':
        return t('projects.partFolder.project');
      case 'picked':
        return t('projects.partFolder.picked');
    }
  };
  return (
    <div className="flex min-w-0 flex-col gap-2">
      <ChoiceCards
        legend={legend}
        legendHidden={legendHidden}
        value={value}
        onValueChange={(next) => {
          setOutside(false);
          onValueChange(next);
        }}
        columns={1}
        options={options.map((option) => ({
          value: option.value,
          title: option.place ? (
            <span className="font-mono text-[12.5px]">{text(option.place)}</span>
          ) : (
            t('projects.partFolder.automatic')
          ),
          hint: hint(option),
        }))}
      />
      <div className="flex flex-wrap items-center gap-2">
        <Button
          size="sm"
          variant="ghost"
          icon={<FolderSearch className="size-3.5" strokeWidth={2} />}
          loading={pick.isPending}
          onClick={() => pick.mutate()}
        >
          {t('projects.partFolder.choose')}
        </Button>
        {outside ? (
          <p role="alert" className="text-[12px] text-warning">
            {t('projects.partFolder.outside')}
          </p>
        ) : null}
      </div>
    </div>
  );
}
