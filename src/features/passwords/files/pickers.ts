// System file dialogs for the vault's files. In `pnpm dev` outside the
// desktop shell there are none, so each returns a made-up path the mock
// backend understands (see src/mocks/vaultFiles.ts).

import { isTauri } from '@tauri-apps/api/core';
import { open, save } from '@tauri-apps/plugin-dialog';

const DEV_HOME = '/Users/dev';

interface Filter {
  name: string;
  extensions: string[];
}

export async function pickFile(title: string, filter: Filter, devPath: string) {
  if (!isTauri()) return devPath;
  const path = await open({ title, multiple: false, directory: false, filters: [filter] });
  return typeof path === 'string' ? path : null;
}

export async function pickFolder(title: string) {
  if (!isTauri()) return `${DEV_HOME}/Library/CloudStorage/Dropbox`;
  const path = await open({ title, multiple: false, directory: true });
  return typeof path === 'string' ? path : null;
}

export async function pickSaveTarget(title: string, fileName: string, filter: Filter) {
  if (!isTauri()) return `${DEV_HOME}/Documents/${fileName}`;
  return save({ title, defaultPath: fileName, filters: [filter] });
}

/** The last part of a path, on any platform. */
export function baseName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

/** Everything but the last part of a path. */
export function folderOf(path: string): string {
  const index = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
  return index > 0 ? path.slice(0, index) : path;
}

/** `2026-11-02`, for default file names. */
export function today(now: Date = new Date()): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
}
