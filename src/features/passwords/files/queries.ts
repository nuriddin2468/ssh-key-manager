import { useQuery, useQueryClient } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { useEffect } from 'react';
import { api } from '@/api/commands';

/** Under `['vault']`, so whatever refreshes the vault refreshes this too. */
export const vaultLocationKey = ['vault', 'location'] as const;

/** Where the vault's files are, and whether that is the default place. */
export const useVaultLocation = () =>
  useQuery({ queryKey: vaultLocationKey, queryFn: api.vaultLocation });

/**
 * Refetches the vault when its files change on disk, e.g. when Dropbox or
 * iCloud Drive brings a version saved on another computer. Mount it once,
 * on the Passwords page or app-wide.
 */
export function useVaultFileEvents(): void {
  const queryClient = useQueryClient();
  useEffect(() => {
    if (!isTauri()) return;
    const stop = listen('vault-changed', () => {
      void queryClient.invalidateQueries({ queryKey: ['vault'] });
    });
    return () => {
      void stop.then((unlisten) => unlisten());
    };
  }, [queryClient]);
}
