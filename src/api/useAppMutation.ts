import { useMutation } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { AppError } from '@/lib/ipc';
import { invalidateAll } from './queries';

/** A localised sentence for an error from a command. */
export function errorMessage(t: TFunction, error: unknown): string {
  const appError = AppError.from(error);
  return t(`errors.${appError.code}`, { defaultValue: t('errors.unknown') });
}

/** Shows a failed command as a toast with the localised reason and details. */
export function toastError(t: TFunction, error: unknown): void {
  const appError = AppError.from(error);
  toast.error(errorMessage(t, appError), {
    description:
      appError.code === 'unknown' || appError.code === 'io' ? appError.message : undefined,
  });
}

interface Options<TVars, TResult> {
  /** Toast shown on success; return nothing for a silent success. */
  success?: (result: TResult, vars: TVars) => string | undefined;
  onSuccess?: (result: TResult, vars: TVars) => void;
  /** Handle an error yourself (e.g. a wrong passphrase in a form); return true to skip the toast. */
  onError?: (error: AppError, vars: TVars) => boolean | undefined;
}

/**
 * A command that changes files or the agent: on success every query is
 * refreshed and an optional toast is shown; failures become a toast unless
 * `onError` handles them.
 */
export function useAppMutation<TVars, TResult>(
  run: (vars: TVars) => Promise<TResult>,
  options: Options<TVars, TResult> = {},
) {
  const { t } = useTranslation();
  return useMutation({
    mutationFn: run,
    onSuccess: async (result, vars) => {
      await invalidateAll();
      const message = options.success?.(result, vars);
      if (message) toast.success(message);
      options.onSuccess?.(result, vars);
    },
    onError: (error, vars) => {
      const appError = AppError.from(error);
      if (options.onError?.(appError, vars)) return;
      toastError(t, appError);
    },
  });
}
