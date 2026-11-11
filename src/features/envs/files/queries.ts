import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';

// Under `vault`, so locking drops them, and under `envs`, so whatever
// changes environments refreshes them too.
export const filesKeys = {
  all: ['vault', 'envs', 'files'] as const,
  status: ['vault', 'envs', 'files', 'status'] as const,
  overview: (project: string | null) => ['vault', 'envs', 'files', 'overview', project] as const,
};

/** Where every file of every environment stands; idle while the vault is locked. */
export function useFileStatuses() {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: filesKeys.status,
    queryFn: api.envsFilesStatus,
    enabled: unlocked,
  });
}

/**
 * The management center, of every project (`null`) or one. It looks through
 * the projects' folders and asks Git, so it isn't fetched again on focus.
 */
export function useFilesOverview(project: string | null) {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: filesKeys.overview(project),
    queryFn: () => api.envsFilesOverview(project),
    enabled: unlocked,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
}
