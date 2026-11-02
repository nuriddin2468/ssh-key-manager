import { invoke, isTauri } from '@tauri-apps/api/core';
import type { ErrorCode } from '@/bindings/ErrorCode';

export type AppErrorCode = ErrorCode | 'unknown';

/** An error returned by a backend command, normalised to `{ code, message }`. */
export class AppError extends Error {
  readonly code: AppErrorCode;

  constructor(code: AppErrorCode, message: string) {
    super(message);
    this.name = 'AppError';
    this.code = code;
  }

  static from(error: unknown): AppError {
    if (error instanceof AppError) return error;
    if (isErrorInfo(error)) return new AppError(error.code, error.message);
    if (error instanceof Error) return new AppError('unknown', error.message);
    return new AppError('unknown', String(error));
  }
}

function isErrorInfo(value: unknown): value is { code: ErrorCode; message: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as { code?: unknown }).code === 'string' &&
    typeof (value as { message?: unknown }).message === 'string'
  );
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>;
let devBackend: Invoke | undefined;

/**
 * Calls a Tauri command. In `pnpm dev` outside the desktop shell, an
 * in-memory backend answers instead so the UI can be developed in a browser;
 * production builds never include it.
 */
export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    if (isTauri()) return await invoke<T>(command, args);
    if (import.meta.env.DEV) {
      devBackend ??= (await import('@/mocks/backend')).invoke;
      return (await devBackend(command, args)) as T;
    }
    throw new AppError('unsupported', 'This build only runs inside the desktop app.');
  } catch (error) {
    throw AppError.from(error);
  }
}
