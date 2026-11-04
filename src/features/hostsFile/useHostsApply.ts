import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import type { HostsApplyResult } from '@/bindings/HostsApplyResult';

/** Explains an apply that did not change the file. */
export function reportUnapplied(t: TFunction, result: HostsApplyResult): void {
  if (result.outcome === 'cancelled') toast(t('hostsFile.cancelled'));
  if (result.outcome === 'stale') toast.error(t('hostsFile.stale'));
}

/**
 * Writing the hosts file with the administrator password: applying changes or
 * restoring a backup. The backend words the password dialog.
 */
export function useHostsApply() {
  const { t } = useTranslation();
  const apply = useAppMutation(api.applyHostsChanges, {
    success: (result) => (result.outcome === 'applied' ? t('hostsFile.applied') : undefined),
    // A stale result is the caller's to explain: it may carry the changes over.
    onSuccess: (result) => {
      if (result.outcome === 'cancelled') reportUnapplied(t, result);
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
