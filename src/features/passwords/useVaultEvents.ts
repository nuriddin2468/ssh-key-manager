import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll, queryClient, useVaultStatus } from '@/api/queries';
import { useRouter } from '@/app/router';
import { lockToastKey } from './model';
import {
  checkUnsavedRecoveryKey,
  isVaultLocked,
  markLocked,
  onVaultLocked,
  onVaultUnlocked,
  showUnsavedRecoveryKey,
  toastVaultError,
} from './vault';

/** Activity is reported at most this often; the auto-lock counts minutes. */
const ACTIVITY_INTERVAL = 30_000;
const ACTIVITY_EVENTS = ['pointerdown', 'pointermove', 'keydown', 'wheel'] as const;

/**
 * App-wide vault wiring, mounted once in the shell:
 * - `vault-locked` from the backend switches to the lock screen at once and,
 *   for locks the user didn't ask for, shows a quiet toast;
 * - `vault-unlocked` refetches everything, as the vault may have been
 *   unlocked elsewhere (for the browser, while this window was hidden);
 * - after an unlock, a reminder of a new recovery key that a lock took off
 *   the screen before it was confirmed as saved: on the Passwords page, and
 *   as a toast elsewhere. The key itself is shown only when the user asks,
 *   after their yes in a native dialog;
 * - while unlocked, pointer and keyboard activity postpones the auto-lock;
 * - a `vault_locked` error from any query or mutation refetches the status.
 */
export function useVaultEvents(): void {
  const { t } = useTranslation();
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  const { route, navigate } = useRouter();
  const onKeyPage = route.page === 'passwords' || route.page === 'envs';

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

  useEffect(() => onVaultUnlocked(() => void invalidateAll()), []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: only when the vault opens, not on every page change
  useEffect(() => {
    if (!unlocked) return;
    void checkUnsavedRecoveryKey().then((unsaved) => {
      if (!unsaved || onKeyPage) return;
      toast(t('passwords.unsavedKeyTitle'), {
        id: 'recovery-key-unsaved',
        description: t('passwords.unsavedKeyText'),
        duration: 15_000,
        action: {
          label: t('passwords.unsavedKeyShow'),
          onClick: () => {
            navigate({ page: 'passwords' });
            showUnsavedRecoveryKey().catch((error) => toastVaultError(t, error));
          },
        },
      });
    });
  }, [unlocked]);

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
