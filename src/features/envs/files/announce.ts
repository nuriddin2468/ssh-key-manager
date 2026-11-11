// What a round of keeping files in step tells the user: each edit of a file
// that went to the vault, with Undo, and each file that came into conflict.
// From the `env-files-changed` event and from the results of the user's own
// actions (Sync now, keeping a side), so the browser preview shows them too.
// In the app both arrive for one round: each edit is told once (by the
// revision it led to) and each conflict once while it lasts, under a toast
// id of its own, so whichever comes second changes nothing.

import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import type { TFunction } from 'i18next';
import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll, queryClient } from '@/api/queries';
import type { Route } from '@/app/router';
import { useRouter } from '@/app/router';
import type { EnvFile } from '@/bindings/EnvFile';
import type { EnvFileChange } from '@/bindings/EnvFileChange';
import type { EnvFilesSynced } from '@/bindings/EnvFilesSynced';
import { toastVaultError } from '@/features/passwords/vault';
import { AppError } from '@/lib/ipc';
import { isFileConflict } from './errors';
import { fileName } from './model';

const EVENT = 'env-files-changed';
/** Names a toast lists before "…". */
const SHOWN_NAMES = 4;

/** The Undo button in a toast, as the recycle bin's Undo looks. */
export const TOAST_ACTION_CLASSES = {
  actionButton:
    '!h-7 !rounded-lg !border !border-white/15 !bg-white/10 !px-2.5 !text-[12.5px] !font-medium !text-fg hover:!bg-white/15',
};

/** Conflicts already told of, so a round that changes nothing says nothing. */
let toldConflicts = new Set<string>();

const conflictKey = (envId: string, folder: string, path: string) => `${envId}\n${folder}\n${path}`;
/** Edits already told of, by the revision they led to. */
const toldEdits: string[] = [];
/** Edits remembered; older ones are long gone from the screen. */
const MAX_TOLD = 200;

/** The toast of a file's conflict: one per file, whoever tells it. */
export function conflictToastId(envId: string, file: EnvFile): string {
  return `env-file-conflict:${conflictKey(envId, file.folder, file.path)}`;
}

/** Notes that a conflict was told of already, by a dialog of its own. */
export function markConflictTold(envId: string, file: EnvFile): void {
  toldConflicts.add(conflictKey(envId, file.folder, file.path));
}

function names(list: string[]): string {
  const shown = list.slice(0, SHOWN_NAMES).join(', ');
  return list.length > SHOWN_NAMES ? `${shown}, …` : shown;
}

/** One line on what an edit of a file changed, by name. */
export function changeSummary(t: TFunction, change: EnvFileChange): string {
  return [
    change.changed.length > 0 ? t('envs.files.savedChanged', { names: names(change.changed) }) : '',
    change.added.length > 0 ? t('envs.files.savedAdded', { names: names(change.added) }) : '',
    change.removed.length > 0 ? t('envs.files.savedRemoved', { names: names(change.removed) }) : '',
  ]
    .filter(Boolean)
    .join(' · ');
}

/**
 * Undoes an edit of a file that went to the vault. The environment may have
 * changed since, or the earlier version left its history: those say so.
 */
export async function undoChange(t: TFunction, change: EnvFileChange): Promise<void> {
  const env = `${change.group} / ${change.envName}`;
  try {
    await api.envsFilesUndo(change.undo);
    await invalidateAll();
    toast.success(t('envs.files.undone', { env }));
  } catch (error) {
    const appError = AppError.from(error);
    if (isFileConflict(appError)) {
      toast.error(t('envs.files.errors.undoChanged', { env }));
    } else if (appError.code === 'not_found') {
      toast.error(t('envs.files.errors.undoGone'));
    } else {
      toastVaultError(t, appError);
    }
  }
}

/**
 * Tells of a round's edits that went to the vault, each with Undo, and of
 * files that came into conflict since the last round.
 */
export function announceSynced(
  t: TFunction,
  synced: EnvFilesSynced,
  navigate: (route: Route) => void,
): void {
  // Conflicts first: the newest toast is in front, and Undo matters most.
  const conflicts = synced.files.filter((status) => status.state.type === 'conflict');
  const now = new Set(
    conflicts.map((status) => conflictKey(status.envId, status.file.folder, status.file.path)),
  );
  for (const status of conflicts) {
    if (toldConflicts.has(conflictKey(status.envId, status.file.folder, status.file.path))) {
      continue;
    }
    toast.warning(t('envs.files.conflictToast', { file: fileName(status.file) }), {
      id: conflictToastId(status.envId, status.file),
      description: `${status.group} / ${status.envName}`,
      duration: 10_000,
      action: {
        label: t('envs.files.show'),
        onClick: () => navigate({ page: 'envs', envId: status.envId }),
      },
      classNames: TOAST_ACTION_CLASSES,
    });
  }
  for (const change of synced.changes) {
    if (toldEdits.includes(change.undo.after)) continue;
    toldEdits.push(change.undo.after);
    if (toldEdits.length > MAX_TOLD) toldEdits.shift();
    toast.success(
      t('envs.files.saved', {
        file: fileName(change.file),
        env: `${change.group} / ${change.envName}`,
      }),
      {
        id: `env-file-edit:${change.undo.after}`,
        description: changeSummary(t, change),
        duration: 10_000,
        action: { label: t('envs.undo'), onClick: () => void undoChange(t, change) },
        classNames: TOAST_ACTION_CLASSES,
      },
    );
  }
  toldConflicts = now;
}

/** Listens for the backend's rounds: refreshes environments and tells of them. */
export function useEnvFilesEvents(): void {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  useEffect(() => {
    if (!isTauri()) return;
    const stop = listen<EnvFilesSynced>(EVENT, (event) => {
      void queryClient.invalidateQueries({ queryKey: ['vault', 'envs'] });
      announceSynced(t, event.payload, navigate);
    });
    return () => void stop.then((unlisten) => unlisten());
  }, [t, navigate]);
}
