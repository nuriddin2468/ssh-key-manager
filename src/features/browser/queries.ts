import { useQuery } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { useEffect } from 'react';
import { api } from '@/api/commands';
import { queryClient } from '@/api/queries';
import type { PairingRequest } from '@/bindings/PairingRequest';

export const browserKey = ['browser'] as const;

/** Events from src-tauri/src/browser/mod.rs. */
export const PAIRING_EVENT = 'browser-pairing';
export const CHANGED_EVENT = 'browser-changed';
export const UNLOCK_EVENT = 'browser-unlock';

export const useBrowserStatus = () =>
  useQuery({ queryKey: browserKey, queryFn: api.browserStatus });

interface BrowserEventHandlers {
  /** A browser asks to pair (a request), or that request is over (`null`). */
  onPairing: (request: PairingRequest | null) => void;
  /** The extension asks to unlock the vault. */
  onUnlock: () => void;
}

/** Listens to the bridge's events; refetches the status when they change it. */
export function useBrowserEvents({ onPairing, onUnlock }: BrowserEventHandlers): void {
  useEffect(() => {
    if (!isTauri()) return;
    const refetch = () => void queryClient.invalidateQueries({ queryKey: browserKey });
    const unlisten = [
      listen<PairingRequest | null>(PAIRING_EVENT, (event) => {
        onPairing(event.payload);
        refetch();
      }),
      listen(CHANGED_EVENT, refetch),
      listen(UNLOCK_EVENT, onUnlock),
    ];
    return () => {
      for (const promise of unlisten) void promise.then((stop) => stop());
    };
  }, [onPairing, onUnlock]);
}

/** Formats a pairing code as two groups of three digits. */
export function groupCode(code: string): string {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}
