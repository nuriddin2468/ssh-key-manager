import { useKeys } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { explain, type MessageAction, type SshRun } from './login';

/**
 * The "Unlock key…" fix for runs where `ssh` could not open a key of the
 * user's for want of its passphrase: it adds that key to ssh-agent, asking
 * for the passphrase (or taking the saved one), then calls `onUnlocked`.
 * Nothing for other runs, or a key the app does not list.
 */
export function useUnlockFix(
  onUnlocked?: () => void,
): (run: SshRun) => Partial<Record<MessageAction, () => void>> {
  const keys = useKeys().data?.keys ?? [];
  const dialogs = useDialogs();
  return (run) => {
    const explanation = explain(run);
    if (explanation.kind !== 'passphraseMissing') return {};
    const key = keys.find((k) => k.privatePath && namesKey(explanation.key, k.privatePath));
    return key ? { unlockKey: () => dialogs.unlockKey(key, undefined, onUnlocked) } : {};
  };
}

/** Whether `ssh`'s `Enter passphrase for key '…'` names `path`; `ssh` prints at most 100 bytes of it. */
export function namesKey(shown: string, path: string): boolean {
  if (shown === path) return true;
  const bytes = new TextEncoder().encode(path);
  return bytes.length > 100 && new TextDecoder().decode(bytes.slice(0, 100)) === shown;
}
