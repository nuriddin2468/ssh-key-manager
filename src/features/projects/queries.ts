import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';

/**
 * The list is keyed by the vault's state: locked, it comes from the copy
 * kept for then (no logins), so locking and unlocking fetch it again.
 */
export const projectKeys = {
  all: ['projects'] as const,
  // Under `vault`, so locking drops them with the vault's other data.
  suggestions: ['vault', 'project-suggestions'] as const,
};

/** The projects, by name; also while the vault is locked, without logins. */
export function useProjects() {
  const state = useVaultStatus().data?.state;
  return useQuery({
    queryKey: [...projectKeys.all, state ?? 'unknown'],
    queryFn: api.projectsList,
    enabled: state !== undefined,
  });
}

/**
 * What the app proposes; only while the vault is unlocked. Looking means
 * reading code folders, so it is kept for a few minutes.
 */
export function useSuggestions() {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: projectKeys.suggestions,
    queryFn: api.projectsSuggestions,
    enabled: unlocked,
    staleTime: 5 * 60_000,
  });
}
