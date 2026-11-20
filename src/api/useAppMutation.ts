import { useMutation } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { type DialogFailure, useDialogErrors } from '@/components/ui/Dialog';
import { AppError } from '@/lib/ipc';
import { invalidateAll } from './queries';

/** A localised sentence for an error from a command. */
export function errorMessage(t: TFunction, error: unknown): string {
  const appError = AppError.from(error);
  return t(`errors.${appError.code}`, { defaultValue: t('errors.unknown') });
}

/** A failed command in words: the localised reason, and what the system said when unexpected. */
export function failureOf(t: TFunction, error: unknown): DialogFailure {
  const appError = AppError.from(error);
  return {
    text: errorMessage(t, appError),
    detail: appError.code === 'unknown' || appError.code === 'io' ? appError.message : undefined,
  };
}

/** Shows a failed command as a toast with the localised reason and details. */
export function toastError(t: TFunction, error: unknown): void {
  const { text, detail } = failureOf(t, error);
  toast.error(text, { description: detail });
}

/**
 * Says a failed command where the user is: above the buttons of the dialog
 * the component is in, else in a toast.
 */
export function useShowError(): (error: unknown) => void {
  const { t } = useTranslation();
  const dialog = useDialogErrors();
  return useCallback(
    (error: unknown) => {
      if (dialog?.show(failureOf(t, error))) return;
      toastError(t, error);
    },
    [t, dialog],
  );
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
 * refreshed and an optional toast is shown; a failure `onError` doesn't
 * handle is said above the buttons of the dialog the component is in (and
 * cleared on the next try), else in a toast. One `onError` handles, at a
 * field, brings that field into view. The mutation leaves TanStack's cache as soon as
 * nothing shows it: its variables may hold a key's passphrase or the master
 * password (the default keeps finished mutations for five minutes).
 */
export function useAppMutation<TVars, TResult>(
  run: (vars: TVars) => Promise<TResult>,
  options: Options<TVars, TResult> = {},
) {
  const { t } = useTranslation();
  const dialog = useDialogErrors();
  return useMutation({
    mutationFn: run,
    gcTime: 0,
    onMutate: () => dialog?.clear(),
    onSuccess: async (result, vars) => {
      await invalidateAll();
      const message = options.success?.(result, vars);
      if (message) toast.success(message);
      options.onSuccess?.(result, vars);
    },
    onError: (error, vars) => {
      const appError = AppError.from(error);
      if (options.onError?.(appError, vars)) {
        dialog?.revealInvalid();
        return;
      }
      if (dialog?.show(failureOf(t, appError))) return;
      toastError(t, appError);
    },
  });
}
