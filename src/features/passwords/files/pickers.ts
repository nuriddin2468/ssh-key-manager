// System file dialogs for choosing where the vault lives. The backend
// confirms what these pick in a native dialog. Files that are read or
// written for import and export are picked by the backend itself. In
// `pnpm dev` outside the desktop shell there are no dialogs, so each returns
// a made-up path the mock backend understands (see src/mocks/vaultFiles.ts).

import { isTauri } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-dialog';

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

/** The last part of a path, on any platform. */
export function baseName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

/** Everything but the last part of a path. */
export function folderOf(path: string): string {
  const index = Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\'));
  return index > 0 ? path.slice(0, index) : path;
}
