// The Nearby status, contacts and the user's devices, kept current by the
// backend's events.

import { useQuery } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { useEffect } from 'react';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll, queryClient, useVaultStatus } from '@/api/queries';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import i18n from '@/i18n';
import { summaryLine } from './model';

/** Emitted by the backend with the whole status (see `nearby/mod.rs`). */
const CHANGED_EVENT = 'nearby-changed';
/** Emitted when a pairing added a contact. */
const CONTACTS_EVENT = 'nearby-contacts';
/** Emitted when the user's devices changed. */
const DEVICES_EVENT = 'nearby-devices';
/** The same events from the dev backend, as window events. */
export const MOCK_CHANGED_EVENT = 'sshkm-mock:nearby-changed';
export const MOCK_CONTACTS_EVENT = 'sshkm-mock:nearby-contacts';
export const MOCK_DEVICES_EVENT = 'sshkm-mock:nearby-devices';

export const nearbyKeys = {
  status: ['nearby', 'status'] as const,
  contacts: ['nearby', 'contacts'] as const,
  devices: ['nearby', 'devices'] as const,
  vaultCloud: ['nearby', 'vaultCloud'] as const,
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

/** The user's devices, this computer among them; kept in the vault too. */
export function useMyDevices() {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: nearbyKeys.devices,
    queryFn: api.nearbyDevices,
    enabled: unlocked,
  });
}

/** The cloud service whose folder holds the vault, if one does: its entries then sync through it. */
export function useVaultCloud() {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: nearbyKeys.vaultCloud,
    queryFn: api.nearbyVaultCloud,
    enabled: unlocked,
  });
}

/** Steps after which the vault or `~/.ssh` changed. */
const CHANGES = new Set(['received', 'added', 'joined', 'synced']);

/** Puts a status the backend sent into the cache. */
export function setStatus(status: NearbyStatus): void {
  const before = queryClient.getQueryData<NearbyStatus>(nearbyKeys.status);
  queryClient.setQueryData(nearbyKeys.status, status);
  const pairing = status.pairing;
  const step = pairing?.phase.type;
  const was = before?.pairing?.id === pairing?.id ? before?.pairing?.phase.type : undefined;
  if (!pairing || !step || step === was) return;
  // Something went into the vault or ~/.ssh: show it everywhere.
  if (CHANGES.has(step)) void invalidateAll();
  // A sync another of the user's devices started: only a word about it.
  if (pairing.phase.type === 'synced' && pairing.kind === 'sync' && !pairing.outgoing) {
    toast.success(i18n.t('nearby.sync.notice', { peer: pairing.peer ?? '' }), {
      description: summaryLine(i18n.t, pairing.phase.summary),
    });
  }
}

/** App-wide: follows the backend's events. Mounted once in the shell. */
export function useNearbyEvents(): void {
  useEffect(() => {
    const contacts = () => void queryClient.invalidateQueries({ queryKey: nearbyKeys.contacts });
    const devices = () => void queryClient.invalidateQueries({ queryKey: nearbyKeys.devices });
    if (isTauri()) {
      const unlisten = [
        listen<NearbyStatus>(CHANGED_EVENT, (event) => setStatus(event.payload)),
        listen(CONTACTS_EVENT, contacts),
        listen(DEVICES_EVENT, devices),
      ];
      return () => {
        for (const promise of unlisten) void promise.then((stop) => stop());
      };
    }
    if (!import.meta.env.DEV) return undefined;
    const changed = (event: Event) => setStatus((event as CustomEvent<NearbyStatus>).detail);
    window.addEventListener(MOCK_CHANGED_EVENT, changed);
    window.addEventListener(MOCK_CONTACTS_EVENT, contacts);
    window.addEventListener(MOCK_DEVICES_EVENT, devices);
    return () => {
      window.removeEventListener(MOCK_CHANGED_EVENT, changed);
      window.removeEventListener(MOCK_CONTACTS_EVENT, contacts);
      window.removeEventListener(MOCK_DEVICES_EVENT, devices);
    };
  }, []);
}
