// The failures of the managed files' commands, told apart from the vault's
// own: a `conflict` here is mostly about a file (it changed since it was
// compared, the environment changed since an edit), and the backend's
// reasons for refusing a binding come back in English, so they are mapped
// to the user's language.

import type { TFunction } from 'i18next';
import { toast } from 'sonner';
import type { EnvFile } from '@/bindings/EnvFile';
import { conflictCopyPath } from '@/features/passwords/model';
import { AppError } from '@/lib/ipc';
import { fileName, isTemplateName } from './model';

/**
 * A conflict over the vault's own files (another computer saved it, its
 * key slots changed), which the vault's error handling explains.
 */
export function isVaultConflict(error: unknown): boolean {
  const appError = AppError.from(error);
  return (
    appError.code === 'conflict' &&
    (conflictCopyPath(appError.message) !== null || /\.keys\b/.test(appError.message))
  );
}

/** A conflict over an environment's file or its variables, not the vault. */
export function isFileConflict(error: unknown): boolean {
  return AppError.from(error).code === 'conflict' && !isVaultConflict(error);
}

/** Why a binding (or a file taken under management) was refused, in words, if it is known. */
export function bindRefusal(t: TFunction, error: unknown): string | null {
  const { code, message } = AppError.from(error);
  if (code === 'already_exists') {
    return /another environment/.test(message)
      ? t('envs.files.errors.otherEnv')
      : t('envs.files.bind.taken');
  }
  if (code !== 'invalid_input') return null;
  if (/template to commit|isn.t a \.env file/.test(message)) {
    const quoted = /"([^"]*)"/.exec(message)?.[1] ?? '';
    return isTemplateName(quoted)
      ? t('envs.files.errors.template')
      : t('envs.files.errors.notEnvName');
  }
  if (/not a file in a folder/.test(message)) return t('envs.files.errors.notEnvName');
  if (/symbolic link/.test(message)) return t('envs.files.errors.link');
  if (/pipe or a device/.test(message)) return t('envs.files.errors.notAFile');
  if (/out of the project/.test(message)) return t('envs.files.errors.outside');
  if (/never writes/.test(message)) return t('envs.files.errors.protected');
  if (/isn.t in a project that holds/.test(message)) return t('envs.files.errors.notInProject');
  return null;
}

/**
 * The backend found an environment of the chosen name in the group
 * (`group / name`), not a file another binding names.
 */
export function isEnvNameClash(error: unknown): boolean {
  const { code, message } = AppError.from(error);
  return (
    code === 'already_exists' && !/another environment/.test(message) && message.includes(' / ')
  );
}

/**
 * Tells that a line couldn't be added to `.gitignore` for `file`, so Git
 * would take it along: not the error itself, which would speak of a
 * folder not found. The vault's own failures (locked, changed elsewhere)
 * are left to the vault's handling: `false` then.
 */
export function ignoreFailed(t: TFunction, error: unknown, file: EnvFile): boolean {
  const appError = AppError.from(error);
  if (appError.code === 'vault_locked' || isVaultConflict(appError)) return false;
  toast.error(t('envs.center.ignoreFailed', { file: fileName(file) }));
  return true;
}
