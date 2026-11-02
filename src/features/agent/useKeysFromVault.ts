import type { TFunction } from 'i18next';
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll, queryClient, useVaultStatus } from '@/api/queries';
import { errorMessage, toastError } from '@/api/useAppMutation';
import type { AddFromVaultReport } from '@/bindings/AddFromVaultReport';
import type { VaultState } from '@/bindings/VaultState';
import { watchKeyEntries } from '@/features/keys/vaultKey';
import { AppError } from '@/lib/ipc';
import { useSettings } from '@/lib/settings';

/** "a, b and c" in the current language. */
function list(names: string[], language: string): string {
  return new Intl.ListFormat(language, { type: 'conjunction' }).format(names);
}

/** Toasts what unlocking keys with saved passphrases did; silent if nothing. */
export function toastAddedFromVault(
  t: TFunction,
  language: string,
  report: AddFromVaultReport,
): void {
  if (report.added.length > 0) {
    toast.success(t('agent.unlockedSaved', { count: report.added.length }), {
      description: list(report.added, language),
    });
  }
  if (report.failed.length > 0) {
    const outdated = report.failed.every((f) => f.code === 'wrong_passphrase');
    const first = report.failed[0];
    toast.error(
      t('agent.failedSaved', {
        names: list(
          report.failed.map((f) => f.name),
          language,
        ),
      }),
      {
        description: outdated
          ? t('agent.failedSavedHint', { count: report.failed.length })
          : first && errorMessage(t, new AppError(first.code, '')),
      },
    );
  }
}

/**
 * Mounted once in the app shell. Keeps track of which keys have a saved
 * passphrase (so screens can say so while the vault is locked) and, when the
 * vault opens with "unlock keys on open" turned on, adds those keys to
 * ssh-agent for the default lifetime.
 */
export function useKeysFromVault(): void {
  const { t, i18n } = useTranslation();
  const status = useVaultStatus();
  const { defaultLifetime } = useSettings();
  const previous = useRef<VaultState | undefined>(undefined);
  const lifetime = useRef(defaultLifetime);
  lifetime.current = defaultLifetime;

  useEffect(() => watchKeyEntries(queryClient), []);

  const state = status.data?.state;
  const enabled = status.data?.settings.unlockKeysOnOpen ?? false;
  useEffect(() => {
    const before = previous.current;
    previous.current = state;
    // Only on a change to unlocked: not when the app finds it unlocked already.
    if (!enabled || state !== 'unlocked' || before === undefined || before === 'unlocked') return;
    api.agentAddAllFromVault(lifetime.current).then(
      (report) => {
        toastAddedFromVault(t, i18n.language, report);
        if (report.added.length > 0) void invalidateAll();
      },
      (error: unknown) => {
        if (AppError.from(error).code !== 'vault_locked') toastError(t, error);
      },
    );
  }, [state, enabled, t, i18n.language]);
}
