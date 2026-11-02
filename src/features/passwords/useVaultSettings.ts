import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { keys, queryClient, useVaultStatus } from '@/api/queries';
import type { VaultSettings } from '@/bindings/VaultSettings';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { toastVaultError } from './vault';

/**
 * The vault's preferences (kept by the backend, which runs the timers) and an
 * `update` that shows the change at once and rolls it back if saving fails.
 */
export function useVaultSettings() {
  const { t } = useTranslation();
  const status = useVaultStatus();

  const save = useMutation({
    mutationFn: api.vaultSetSettings,
    onMutate: (next) => {
      queryClient.setQueryData<VaultStatus>(keys.vaultStatus, (current) =>
        current ? { ...current, settings: next } : current,
      );
    },
    onError: (error) => toastVaultError(t, error),
    onSettled: () => queryClient.invalidateQueries({ queryKey: keys.vaultStatus }),
  });

  const update = (patch: Partial<VaultSettings>) => {
    const current = status.data?.settings;
    if (current) save.mutate({ ...current, ...patch });
  };

  return { status: status.data, settings: status.data?.settings, update };
}
