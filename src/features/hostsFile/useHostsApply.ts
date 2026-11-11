import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { HostsApplyResult } from '@/bindings/HostsApplyResult';

/** Explains an apply that did not change the file. */
export function reportUnapplied(t: TFunction, result: HostsApplyResult): void {
  if (result.outcome === 'cancelled') toast(t('hostsFile.cancelled'));
  if (result.outcome === 'stale') toast.error(t('hostsFile.stale'));
}

/**
 * Undoes an apply: puts back the backup it made, with the administrator
 * password, but only over the file it wrote. Changed since, it is left
 * alone and the Backups dialog has the copy.
 */
export async function undoApply(
  t: TFunction,
  result: HostsApplyResult,
  flushDns: boolean,
): Promise<void> {
  if (!result.backup) return;
  try {
    const restored = await api.restoreHostsBackup({
      path: result.backup,
      flushDns,
      revision: result.file.revision,
    });
    if (restored.outcome === 'applied') toast.success(t('hostsFile.restored'));
    else if (restored.outcome === 'stale') toast.error(t('hostsFile.undoStale'));
    else reportUnapplied(t, restored);
  } catch (error) {
    toastError(t, error);
  } finally {
    await invalidateAll();
  }
}

/**
 * Writing the hosts file with the administrator password: applying changes or
 * restoring a backup. The backend words the password dialog. With `undo`, the
 * toast after an apply can undo it through the backup it made.
 */
export function useHostsApply(options: { undo?: boolean } = {}) {
  const { t } = useTranslation();
  const apply = useAppMutation(api.applyHostsChanges, {
    success: (result) =>
      result.outcome === 'applied' && !(options.undo && result.backup)
        ? t('hostsFile.applied')
        : undefined,
    // A stale result is the caller's to explain: it may carry the changes over.
    onSuccess: (result, vars) => {
      if (result.outcome === 'cancelled') reportUnapplied(t, result);
      if (result.outcome === 'applied' && options.undo && result.backup) {
        toast.success(t('hostsFile.applied'), {
          action: {
            label: t('hostsFile.undo'),
            onClick: () => void undoApply(t, result, vars.flushDns),
          },
        });
      }
    },
  });
  const restore = useAppMutation(api.restoreHostsBackup, {
    success: (result) => (result.outcome === 'applied' ? t('hostsFile.restored') : undefined),
    onSuccess: (result) => {
      if (result.outcome === 'stale') toast.error(t('hostsFile.restoreStale'));
      else reportUnapplied(t, result);
    },
  });
  return { apply, restore };
}
