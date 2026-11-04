// The Nearby status and contacts, kept current by the backend's events.

import { useQuery } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { useEffect } from 'react';
import { api } from '@/api/commands';
import { queryClient, useVaultStatus } from '@/api/queries';
import type { NearbyStatus } from '@/bindings/NearbyStatus';

/** Emitted by the backend with the whole status (see `nearby/mod.rs`). */
const CHANGED_EVENT = 'nearby-changed';
/** Emitted when a pairing added a contact. */
const CONTACTS_EVENT = 'nearby-contacts';
/** The same events from the dev backend, as window events. */
export const MOCK_CHANGED_EVENT = 'sshkm-mock:nearby-changed';
export const MOCK_CONTACTS_EVENT = 'sshkm-mock:nearby-contacts';

export const nearbyKeys = {
  status: ['nearby', 'status'] as const,
  contacts: ['nearby', 'contacts'] as const,
};

export const useNearby = () => useQuery({ queryKey: nearbyKeys.status, queryFn: api.nearbyStatus });

/** The paired devices; they live in the vault, so only while it is unlocked. */
export function useContacts() {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: nearbyKeys.contacts,
    queryFn: api.nearbyContacts,
    enabled: unlocked,
  });
}

/** Puts a status the backend sent into the cache. */
export function setStatus(status: NearbyStatus): void {
  queryClient.setQueryData(nearbyKeys.status, status);
}

/** App-wide: follows the backend's events. Mounted once in the shell. */
export function useNearbyEvents(): void {
  useEffect(() => {
    const contacts = () => void queryClient.invalidateQueries({ queryKey: nearbyKeys.contacts });
    if (isTauri()) {
      const unlisten = [
        listen<NearbyStatus>(CHANGED_EVENT, (event) => setStatus(event.payload)),
        listen(CONTACTS_EVENT, contacts),
      ];
      return () => {
        for (const promise of unlisten) void promise.then((stop) => stop());
      };
    }
    if (!import.meta.env.DEV) return undefined;
    const changed = (event: Event) => setStatus((event as CustomEvent<NearbyStatus>).detail);
    window.addEventListener(MOCK_CHANGED_EVENT, changed);
    window.addEventListener(MOCK_CONTACTS_EVENT, contacts);
    return () => {
      window.removeEventListener(MOCK_CHANGED_EVENT, changed);
      window.removeEventListener(MOCK_CONTACTS_EVENT, contacts);
    };
  }, []);
}
