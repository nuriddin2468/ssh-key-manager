// System file dialogs for choosing where the vault lives. The backend opens
// them and keeps what was picked: moving or switching takes only that path,
// confirmed in a native dialog. Files that are read or written for import and
// export are picked by the backend too. In `pnpm dev` outside the desktop
// shell the mock backend answers with made-up paths (src/mocks/vaultFiles.ts).

import { api } from '@/api/commands';

/** A KeePass file to use as the vault; `null` if the dialog was cancelled. */
export function pickFile(): Promise<string | null> {
  return api.vaultPickFile();
}

/** A folder to move the vault to; `null` if the dialog was cancelled. */
export function pickFolder(): Promise<string | null> {
  return api.vaultPickFolder();
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
