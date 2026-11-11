import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import type { Project } from '@/bindings/Project';
import type { ProjectMember } from '@/bindings/ProjectMember';
import { markLocked, useVaultMutation } from '@/features/passwords/vault';
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

/** Made in a Library dialog, joining `into`: `name` is what the user calls it. */
export interface Joining {
  into: Project;
  members: ProjectMember[];
  name: string;
}

/**
 * Puts what was just made from a project's Add menu into it; the dialog's own
 * toast says it was made. The vault may have locked while the dialog was
 * open (New host and Generate key don't use it): then it asks to unlock, and
 * goes on.
 */
export function useJoinMade() {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const join = useVaultMutation(
    async ({ into, members }: Joining) => {
      for (const member of members) await api.projectsSetMember(into.id, member, true);
    },
    {
      onSuccess: () => void refreshSuggestions(),
      onError: (error, joining) => {
        if (error.code !== 'vault_locked') return false;
        markLocked();
        dialogs.unlockVault({
          description: joining.name
            ? t('projects.unlockToJoin', { name: joining.name, project: joining.into.name })
            : t('projects.unlockToChange'),
          onUnlocked: () => join.mutate(joining),
        });
        return true;
      },
    },
  );
  return join;
}
