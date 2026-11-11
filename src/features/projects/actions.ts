import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import type { Project } from '@/bindings/Project';
import type { ProjectMember } from '@/bindings/ProjectMember';
import { useVaultMutation } from '@/features/passwords/vault';

interface MemberChange {
  project: Project;
  member: ProjectMember;
  included: boolean;
}

/**
 * Puts an item into a project or takes it out, with a toast that can undo
 * it. A folder can only be taken out here (it goes in through the folder
 * dialog, `projectsAddFolder`).
 */
export function useSetMember() {
  const { t } = useTranslation();
  return useVaultMutation(
    ({ project, member, included }: MemberChange) =>
      api.projectsSetMember(project.id, member, included),
    {
      onSuccess: (_, { project, member, included }) => {
        const message = included
          ? t('projects.added', { name: project.name })
          : t('projects.removed', { name: project.name });
        const canUndo = !(included === false && member.type === 'folder');
        toast.success(message, {
          action: canUndo
            ? {
                label: t('projects.undo'),
                onClick: () =>
                  void api
                    .projectsSetMember(project.id, member, !included)
                    .then(() => invalidateAll()),
              }
            : undefined,
        });
      },
    },
  );
}
