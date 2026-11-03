import { QueryClient, useQuery } from '@tanstack/react-query';
import { api } from './commands';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The data is local files; refetching on focus keeps it in sync with
      // edits made in a terminal while the window was in the background.
      refetchOnWindowFocus: true,
      staleTime: 2_000,
      retry: false,
    },
    mutations: { retry: false },
  },
});

export const keys = {
  environment: ['environment'] as const,
  keys: ['keys'] as const,
  agent: ['agent'] as const,
  config: ['config'] as const,
  knownHosts: ['known-hosts'] as const,
  hostsFile: ['hosts-file'] as const,
  audit: ['audit'] as const,
  vaultStatus: ['vault', 'status'] as const,
  vaultEntries: ['vault', 'entries'] as const,
};

/** Everything derived from files in `~/.ssh`, the hosts file or the agent. */
export function invalidateAll(): Promise<void> {
  return queryClient.invalidateQueries({
    predicate: (query) => query.queryKey[0] !== 'environment',
  });
}

export const useEnvironment = () =>
  useQuery({ queryKey: keys.environment, queryFn: api.environment, staleTime: Infinity });

export const useKeys = () => useQuery({ queryKey: keys.keys, queryFn: api.listKeys });

export const useAgent = () =>
  useQuery({ queryKey: keys.agent, queryFn: api.agent, refetchInterval: 15_000 });

export const useConfig = () => useQuery({ queryKey: keys.config, queryFn: api.config });

export const useKnownHosts = () => useQuery({ queryKey: keys.knownHosts, queryFn: api.knownHosts });

export const useHostsFile = () => useQuery({ queryKey: keys.hostsFile, queryFn: api.hostsFile });

export const useAudit = () => useQuery({ queryKey: keys.audit, queryFn: api.audit });

export const useVaultStatus = () =>
  useQuery({ queryKey: keys.vaultStatus, queryFn: api.vaultStatus });

/** Entries of the unlocked vault; idle while it is locked. */
export const useVaultEntries = () => {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({ queryKey: keys.vaultEntries, queryFn: api.vaultEntries, enabled: unlocked });
};
