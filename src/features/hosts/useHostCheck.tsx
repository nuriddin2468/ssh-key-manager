import { useCallback, useMemo, useSyncExternalStore } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { refreshConnectionHistory } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import { Dialog } from '@/components/ui/Dialog';
import { useVaultKey } from '@/features/keys/vaultKey';
import { AppError } from '@/lib/ipc';
import { useKeyForFile } from './HostFields';
import { KeyCheckDialog } from './KeyCheckDialog';
import type { RunContext } from './login';
import { formFromHost, type SignInMethod } from './model';
import { useDialog } from './useDialog';
import { hostAliases, useHostVault, vaultErrorMessage } from './vault';

export interface CheckResult {
  run: ConnectionTest;
  context: RunContext;
}

// Checks by alias, shared by the list and the editor: a check started in one
// shows as running in the other, and its result waits in the editor until
// it is closed.
const running = new Set<string>();
const results = new Map<string, CheckResult>();
const listeners = new Set<() => void>();

function changed() {
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export function setCheckResult(alias: string, result: CheckResult | null) {
  if (result) results.set(alias, result);
  else results.delete(alias);
  changed();
}

interface Options {
  /** The editor's unsaved choices; the saved block's otherwise. */
  form?: { identityFile: string; method: SignInMethod | null };
  /** Called with each result, after it is stored. */
  onResult?: (result: CheckResult) => void;
}

/**
 * "Check" for a host. With the vault open it signs in with what the vault
 * saved for the host; otherwise only keys ssh can use by itself get in (ones
 * in ssh-agent, or without a passphrase). A key with a passphrase that
 * neither ssh-agent nor the open vault holds is asked for first: render
 * `dialog` for that.
 */
export function useHostCheck(host: HostEntry, { form, onResult }: Options = {}) {
  const { t } = useTranslation();
  const vault = useHostVault(host);
  const alias = vault.vault === 'unlocked' ? vault.alias : (hostAliases(host)[0] ?? '');
  const withVault = vault.vault === 'unlocked';
  const passwordSaved = vault.vault === 'unlocked' && Boolean(vault.entry);
  const context: RunContext = passwordSaved ? 'vaultTest' : 'test';

  const saved = useMemo(() => formFromHost(host, { passwordSaved }), [host, passwordSaved]);
  const identityFile = form?.identityFile ?? saved.identityFile;
  const method = form ? form.method : saved.method;
  const hostKey = useKeyForFile(identityFile).key;
  const hostKeyVault = useVaultKey(hostKey?.fingerprint);
  const lockedKey =
    method !== 'password' &&
    hostKey?.encrypted &&
    !hostKey.inAgent &&
    !hostKey.hardware &&
    !(hostKeyVault.vault === 'unlocked' && hostKeyVault.entry)
      ? hostKey
      : undefined;

  const isRunning = useSyncExternalStore(subscribe, () => running.has(alias));
  const result = useSyncExternalStore(subscribe, () => results.get(alias) ?? null);
  const [keyCheck, openKeyCheck, closeKeyCheck] = useDialog<{
    key: KeyView;
    context: RunContext;
  }>();

  const finish = useCallback(
    (next: CheckResult) => {
      setCheckResult(alias, next);
      void refreshConnectionHistory();
      onResult?.(next);
    },
    [alias, onResult],
  );

  /** Checks at once, without asking for a key's passphrase. */
  const checkNow = useCallback(async () => {
    if (!alias || running.has(alias)) return;
    running.add(alias);
    changed();
    try {
      const run = withVault
        ? await api.vaultTestConnection(alias)
        : await api.testConnection(alias);
      finish({ run, context });
    } catch (error) {
      if (AppError.from(error).code === 'vault_locked') toast.error(vaultErrorMessage(t, error));
      else toastError(t, error);
    } finally {
      running.delete(alias);
      changed();
    }
  }, [alias, withVault, context, finish, t]);

  const run = () => {
    if (isRunning) return;
    if (lockedKey) openKeyCheck({ key: lockedKey, context });
    else void checkNow();
  };

  const dialog = (
    <Dialog open={keyCheck !== null} onOpenChange={(open) => open || closeKeyCheck()}>
      {keyCheck ? (
        <KeyCheckDialog
          alias={alias}
          keyView={keyCheck.key}
          onChecked={(checked) => finish({ run: checked, context: keyCheck.context })}
          onDone={closeKeyCheck}
        />
      ) : null}
    </Dialog>
  );

  return {
    alias,
    run,
    checkNow,
    running: isRunning,
    result,
    clearResult: () => setCheckResult(alias, null),
    dialog,
  };
}
