// Errors of a change to a file in `~/.ssh` that are not failures: the file
// changed since it was read, and the user said no in the system's own
// confirmation dialog.

import type { TFunction } from 'i18next';
import { toast } from 'sonner';
import { invalidateAll } from '@/api/queries';
import { AppError } from '@/lib/ipc';

/**
 * For `useAppMutation`'s `onError`. A file that changed since it was read
 * (`conflict`) is read again and `changed` says so, so the user can look and
 * try again; a declined confirmation (`cancelled`) needs no message. Returns
 * true when the error was one of these.
 */
export function fileChangeError(error: unknown, changed: string): boolean {
  const code = AppError.from(error).code;
  if (code === 'cancelled') return true;
  if (code !== 'conflict') return false;
  void invalidateAll();
  toast.error(changed);
  return true;
}

/** {@link fileChangeError} for `~/.ssh/config`. */
export const configChangeError = (t: TFunction, error: unknown) =>
  fileChangeError(error, t('hosts.changedOnDisk'));
