import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { queryClient, useVaultStatus } from '@/api/queries';
import { lockToastKey } from './model';
import { isVaultLocked, markLocked, onVaultLocked } from './vault';

/** Activity is reported at most this often; the auto-lock counts minutes. */
const ACTIVITY_INTERVAL = 30_000;
const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel'] as const;

/**
 * App-wide vault wiring, mounted once in the shell:
 * - `vault-locked` from the backend switches to the lock screen at once and,
 *   for locks the user didn't ask for, shows a quiet toast;
 * - while unlocked, pointer and keyboard activity postpones the auto-lock;
 * - a `vault_locked` error from any query or mutation refetches the status.
 */
export function useVaultEvents(): void {
  const { t } = useTranslation();
  const unlocked = useVaultStatus().data?.state === 'unlocked';

  useEffect(
    () =>
      onVaultLocked((reason) => {
        markLocked();
        const key = lockToastKey(reason);
        if (!key) return;
        toast(t(key), {
          id: 'vault-locked',
          description: reason === 'changed' ? t('passwords.lockedChangedHint') : undefined,
        });
      }),
    [t],
  );

  useEffect(() => {
    if (!unlocked) return;
    let last = 0;
    const report = () => {
      const now = Date.now();
      if (now - last < ACTIVITY_INTERVAL) return;
      last = now;
      api.vaultActivity().catch(() => undefined);
    };
    for (const name of ACTIVITY_EVENTS) window.addEventListener(name, report, { passive: true });
    return () => {
      for (const name of ACTIVITY_EVENTS) window.removeEventListener(name, report);
    };
  }, [unlocked]);

  useEffect(() => {
    const queries = queryClient.getQueryCache().subscribe((event) => {
      if (event.type === 'updated' && event.action.type === 'error') {
        if (isVaultLocked(event.action.error)) markLocked();
      }
    });
    const mutations = queryClient.getMutationCache().subscribe((event) => {
      if (event.type === 'updated' && event.action.type === 'error') {
        if (isVaultLocked(event.action.error)) markLocked();
      }
    });
    return () => {
      queries();
      mutations();
    };
  }, []);
}
