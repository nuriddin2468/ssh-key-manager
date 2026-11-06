import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';

// Under `vault`, so locking drops them from the cache with the entries.
const listKey = ['vault', 'envs'] as const;
const detailKey = (id: string) => ['vault', 'envs', id] as const;

/** The environments of the unlocked vault; idle while it is locked. */
export function useEnvs() {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({ queryKey: listKey, queryFn: api.envsList, enabled: unlocked });
}

/** One environment's variables, never their values. */
export function useEnv(id: string | undefined) {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: detailKey(id ?? ''),
    queryFn: () => api.envsGet(id ?? ''),
    enabled: unlocked && Boolean(id),
  });
}
