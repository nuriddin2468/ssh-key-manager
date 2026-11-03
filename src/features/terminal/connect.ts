import { useCallback } from 'react';
import { useRouter } from '@/app/router';

/**
 * Opens a session to `alias` in the Terminal section. Other screens ask for a
 * session only through this hook; the section starts one per call (the nonce
 * tells two calls for the same host apart).
 */
export function useConnect(): (alias: string) => void {
  const { navigate } = useRouter();
  return useCallback(
    (alias: string) => navigate({ page: 'terminal', connect: alias, nonce: Date.now() }),
    [navigate],
  );
}
