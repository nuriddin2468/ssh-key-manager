// Vault state shared by the Passwords page, the sidebar and Settings: the
// detail query, what happens when the vault locks, and its error handling.

import { useMutation, useQuery } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { TFunction } from 'i18next';
import { useState, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll, keys, queryClient, useVaultStatus } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import type { Environment } from '@/bindings/Environment';
import type { LockReason } from '@/bindings/LockReason';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { displayPath } from '@/lib/format';
import { AppError } from '@/lib/ipc';
import { conflictCopyPath } from './model';

export const LOCKED_EVENT = 'vault-locked';
/** Emitted by the backend whenever the vault is unlocked, by any window or prompt. */
export const UNLOCKED_EVENT = 'vault-unlocked';
/** `pnpm dev` only: the mock vault announces locks with this window event. */
export const MOCK_LOCKED_EVENT = 'sshkm:mock-vault-locked';

const entryKey = (id: string) => ['vault', 'entry', id] as const;

/** One entry's details (never its secrets); idle while the vault is locked. */
export function useVaultEntry(id: string | undefined) {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: entryKey(id ?? ''),
    queryFn: () => api.vaultEntry(id ?? ''),
    enabled: unlocked && Boolean(id),
  });
}

/**
 * Switches the UI to the lock screen at once, before the status is fetched
 * again: entries and details leave the cache, finished commands leave
 * TanStack's mutation cache (their variables may hold a master password or a
 * passphrase), and anything that shows a revealed secret unmounts with the
 * unlocked view.
 */
export function markLocked(): void {
  queryClient.setQueryData<VaultStatus>(keys.vaultStatus, (status) =>
    status && status.state === 'unlocked'
      ? { ...status, state: status.files.exists ? 'locked' : 'missing' }
      : status,
  );
  queryClient.removeQueries({
    queryKey: ['vault'],
    predicate: (query) => query.queryKey[1] !== 'status',
  });
  // Chats are sealed with the vault: their texts and plain values go too.
  queryClient.removeQueries({ queryKey: ['chats'] });
  queryClient.getMutationCache().clear();
  void queryClient.invalidateQueries({ queryKey: keys.vaultStatus });
}

export const isVaultLocked = (error: unknown) => AppError.from(error).code === 'vault_locked';

/**
 * Toasts vault-specific failures and returns true if it handled them:
 * `vault_locked` (shows the lock screen), `conflict` (the vault changed on
 * another computer; for the database the backend kept a copy of this change,
 * for the key slots it loaded the other version) and `cancelled` (the user
 * said no in a native confirmation, which needs no toast).
 */
export function handleVaultError(t: TFunction, error: unknown): boolean {
  const appError = AppError.from(error);
  if (appError.code === 'cancelled') return true;
  if (appError.code === 'vault_locked') {
    markLocked();
    toast.error(t('errors.vault_locked'));
    return true;
  }
  if (appError.code === 'conflict') {
    const path = conflictCopyPath(appError.message);
    const home = queryClient.getQueryData<Environment>(keys.environment)?.paths.home;
    toast.error(path ? t('errors.conflict') : t('passwords.keysConflict'), {
      description: path
        ? t('passwords.conflictCopy', { path: displayPath(path, home) })
        : undefined,
      duration: 12_000,
    });
    void queryClient.invalidateQueries({ queryKey: ['vault'] });
    return true;
  }
  return false;
}

/** Toasts any failure of a vault command. */
export function toastVaultError(t: TFunction, error: unknown): void {
  if (!handleVaultError(t, error)) toastError(t, error);
}

interface VaultMutationOptions<TVars, TResult> {
  /** Toast shown on success; return nothing for a silent success. */
  success?: (result: TResult, vars: TVars) => string | undefined;
  onSuccess?: (result: TResult, vars: TVars) => void;
  /** Handle an error yourself (e.g. a wrong password in a form); return true to skip the toast. */
  onError?: (error: AppError, vars: TVars) => boolean | undefined;
}

/**
 * `useAppMutation` for vault commands: also handles `vault_locked` and
 * `conflict`, and drops the mutation from TanStack's cache as soon as nothing
 * shows it, because its variables may hold a master password or an entry's
 * new password (the default keeps finished mutations for five minutes).
 */
export function useVaultMutation<TVars, TResult>(
  run: (vars: TVars) => Promise<TResult>,
  options: VaultMutationOptions<TVars, TResult> = {},
) {
  const { t } = useTranslation();
  return useMutation({
    mutationFn: run,
    gcTime: 0,
    onSuccess: async (result, vars) => {
      await invalidateAll();
      const message = options.success?.(result, vars);
      if (message) toast.success(message);
      options.onSuccess?.(result, vars);
    },
    onError: (error, vars) => {
      const appError = AppError.from(error);
      if (options.onError?.(appError, vars)) return;
      toastVaultError(t, appError);
    },
  });
}

/**
 * Runs a command whose result is a secret (a revealed password, a recovery
 * key) without TanStack, so the result exists only where the caller keeps it.
 */
export function useSecretCall<TArgs extends unknown[], TResult>(
  run: (...args: TArgs) => Promise<TResult>,
) {
  const [pending, setPending] = useState(false);
  const call = async (...args: TArgs): Promise<TResult> => {
    setPending(true);
    try {
      return await run(...args);
    } finally {
      setPending(false);
    }
  };
  return { pending, call };
}

/** Calls `handler` whenever the backend locks the vault. */
export function onVaultLocked(handler: (reason: LockReason) => void): () => void {
  if (isTauri()) {
    const stop = listen<LockReason>(LOCKED_EVENT, (event) => handler(event.payload));
    return () => void stop.then((unlisten) => unlisten());
  }
  if (!import.meta.env.DEV) return () => undefined;
  const listener = (event: Event) => handler((event as CustomEvent<LockReason>).detail);
  window.addEventListener(MOCK_LOCKED_EVENT, listener);
  return () => window.removeEventListener(MOCK_LOCKED_EVENT, listener);
}

/**
 * Calls `handler` when the vault is unlocked outside this window: for the
 * browser, with Touch ID or in the small unlock window. Tauri only.
 */
export function onVaultUnlocked(handler: () => void): () => void {
  if (!isTauri()) return () => undefined;
  const stop = listen(UNLOCKED_EVENT, () => handler());
  return () => void stop.then((unlisten) => unlisten());
}

// After an unlock the form that had focus is gone; the unlocked view then
// starts in its search field instead of leaving focus on the page.
let searchFocusRequested = false;

export function requestSearchFocus(): void {
  searchFocusRequested = true;
}

/** True once after `requestSearchFocus`. */
export function takeSearchFocusRequest(): boolean {
  const requested = searchFocusRequested;
  searchFocusRequested = false;
  return requested;
}

// A recovery key that was just created and not yet confirmed as saved. It is
// kept outside the page so switching sections doesn't lose it.
let pendingRecoveryKey: string | null = null;
const listeners = new Set<() => void>();

export function setPendingRecoveryKey(key: string | null): void {
  pendingRecoveryKey = key;
  for (const listener of listeners) listener();
}

export function usePendingRecoveryKey(): string | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => pendingRecoveryKey,
  );
}
