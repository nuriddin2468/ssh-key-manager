import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import type { Project } from '@/bindings/Project';
import type { ProjectMember } from '@/bindings/ProjectMember';
import { useVaultMutation } from '@/features/passwords/vault';
import { refreshSuggestions } from './queries';

interface MemberChange {
  project: Project;
  member: ProjectMember;
  included: boolean;
}

/**
 * Puts an item into a project or takes it out, with a toast that can undo
 * it. A new folder goes in through the folder dialog (`projectsAddFolder`);
 * here only one the project held comes back.
 */
export function useSetMember() {
  const { t } = useTranslation();
  return useVaultMutation(
    ({ project, member, included }: MemberChange) =>
      api.projectsSetMember(project.id, member, included),
    {
      onSuccess: (_, { project, member, included }) => {
        void refreshSuggestions();
        const message = included
          ? t('projects.added', { name: project.name })
          : t('projects.removed', { name: project.name });
        // Undo puts back exactly what changed, a folder too: the project
        // held it, so it may come back.
        toast.success(message, {
          action: {
            label: t('projects.undo'),
            onClick: () =>
              void api.projectsSetMember(project.id, member, !included).then(() => invalidateAll()),
          },
        });
      },
    },
  );
}
