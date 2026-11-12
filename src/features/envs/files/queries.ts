import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/commands';
import { queryClient, useVaultStatus } from '@/api/queries';

// Under `vault`, so locking drops them. The states live under `envs`, so
// whatever changes environments refreshes them; the reports, which run Git
// and look through project folders, don't (`invalidateAll` leaves out
// `env-files-*`): `refreshFileReports` fetches them again when files are
// bound, ignored or taken under management, or the user syncs.
export const filesKeys = {
  status: ['vault', 'envs', 'files', 'status'] as const,
  overview: (project: string | null) => ['vault', 'env-files-overview', project] as const,
  risks: ['vault', 'env-files-risks'] as const,
  agents: (project: string, folder: string) =>
    ['vault', 'env-files-agents', project, folder] as const,
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
 * Every file of every environment with what Git makes of it and the cloud
 * service that copies its folder, without looking for other files.
 */
export function useFileRisks() {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: filesKeys.risks,
    queryFn: () => api.envsFilesRisks(null),
    enabled: unlocked,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
  });
}

/**
 * The management center, of every project (`null`) or one. It looks through
 * the projects' folders and asks Git, so it isn't fetched again on focus.
 */
export function useFilesOverview(project: string | null, wanted = true) {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: filesKeys.overview(project),
    queryFn: () => api.envsFilesOverview(project),
    enabled: unlocked && wanted,
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
}

/**
 * What AI tools' ignore files in a project folder lack for its managed
 * files, and what the user said about the folder. Under `env-files-`, so a
 * bound file fetches it again.
 */
export function useAgentRules(project: string | null, folder: string) {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: filesKeys.agents(project ?? '', folder),
    queryFn: () => api.envsAgentsRules(project ?? '', folder),
    enabled: unlocked && project !== null,
    staleTime: 60_000,
    refetchOnWindowFocus: false,
    retry: false,
  });
}

/** Fetches the files' reports again: Git, cloud folders, files found. */
export function refreshFileReports(): Promise<void> {
  return queryClient.invalidateQueries({
    predicate: (query) =>
      query.queryKey[0] === 'vault' && String(query.queryKey[1]).startsWith('env-files-'),
  });
}
