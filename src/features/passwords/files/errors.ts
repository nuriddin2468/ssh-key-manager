import type { TFunction } from 'i18next';
import { toast } from 'sonner';
import type { AppError, AppErrorCode } from '@/lib/ipc';

/**
 * For `useAppMutation`'s `onError`: shows the message given for the error's
 * code (or the sync conflict message) and returns true, or returns false to
 * let the generic toast handle it. `cancelled` — the user said no in the
 * backend's native confirmation — shows nothing.
 */
export function showFileError(
  t: TFunction,
  error: AppError,
  messages: Partial<Record<AppErrorCode, string>>,
): boolean {
  if (error.code === 'cancelled') return true;
  const message =
    messages[error.code] ?? (error.code === 'conflict' ? t('vaultFiles.conflict') : undefined);
  if (!message) return false;
  toast.error(message);
  return true;
}
