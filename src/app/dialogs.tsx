import { isTauri } from '@tauri-apps/api/core';
import { open as openFile } from '@tauri-apps/plugin-dialog';
import {
  createContext,
  type ReactNode,
  use,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useEnvironment } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { KeyView } from '@/bindings/KeyView';
import { Dialog } from '@/components/ui/Dialog';
import { UnlockDialog } from '@/features/agent/UnlockDialog';
import { AddHostDialog } from '@/features/hosts/AddHostDialog';
import { GenerateKeyDialog } from '@/features/keys/GenerateKeyDialog';
import { PassphraseDialog } from '@/features/keys/PassphraseDialog';
import { useSettings } from '@/lib/settings';
import { useRouter } from './router';

type Open =
  | { kind: 'generate'; onCreated?: (key: KeyView) => void }
  | { kind: 'addHost' }
  | { kind: 'passphrase'; key: KeyView; suggest: boolean }
  | { kind: 'unlock'; key: KeyView; lifetime: number | null; onUnlocked?: () => void }
  | null;

interface DialogsValue {
  generateKey: () => void;
  /** Generates a key and hands it to `onCreated`, staying on the current page. */
  generateKeyFor: (onCreated: (key: KeyView) => void) => void;
  addHost: () => void;
  /** `suggest` starts with a generated passphrase, to be saved in the vault. */
  editPassphrase: (key: KeyView, options?: { suggest?: boolean }) => void;
  /**
   * Adds a key to the agent, asking for its passphrase when it has one, then
   * calls `onUnlocked`.
   */
  unlockKey: (key: KeyView, lifetime?: number | null, onUnlocked?: () => void) => void;
  importKey: () => Promise<void>;
}

const DialogsContext = createContext<DialogsValue | null>(null);

/** App-wide dialogs, so any page (or the menu bar) can open them. */
export function DialogsProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const settings = useSettings();
  const environment = useEnvironment();
  const [open, setOpen] = useState<Open>(null);
  const close = useCallback(() => setOpen(null), []);

  // `pnpm dev` only: `?open=generate` or `?open=addHost` shows a dialog on load.
  useEffect(() => {
    if (!import.meta.env.DEV) return;
    const dialog = new URLSearchParams(window.location.search).get('open');
    if (dialog === 'generate' || dialog === 'addHost') setOpen({ kind: dialog });
  }, []);

  const addPlain = useAppMutation(
    (vars: { key: KeyView; lifetime: number | null }) =>
      api.agentAdd(vars.key.id, null, vars.lifetime),
    { success: (_, vars) => t('keys.unlocked', { name: vars.key.name }) },
  );
  const importMutation = useAppMutation((source: string) => api.importKey(source, null), {
    success: (key) => t('keys.imported', { name: key.name }),
    onSuccess: (key) => navigate({ page: 'keys', keyId: key.id }),
  });

  const value = useMemo<DialogsValue>(
    () => ({
      generateKey: () => setOpen({ kind: 'generate' }),
      generateKeyFor: (onCreated) => setOpen({ kind: 'generate', onCreated }),
      addHost: () => setOpen({ kind: 'addHost' }),
      editPassphrase: (key, options) =>
        setOpen({ kind: 'passphrase', key, suggest: options?.suggest ?? false }),
      unlockKey: (key, lifetime = settings.defaultLifetime, onUnlocked) => {
        if (key.encrypted) setOpen({ kind: 'unlock', key, lifetime, onUnlocked });
        else addPlain.mutate({ key, lifetime }, { onSuccess: () => onUnlocked?.() });
      },
      importKey: async () => {
        try {
          const source = isTauri()
            ? await openFile({
                multiple: false,
                directory: false,
                title: t('keys.import'),
                defaultPath: environment.data?.paths.home,
              })
            : '/Users/dev/Downloads/id_ed25519_laptop';
          if (typeof source === 'string') importMutation.mutate(source);
        } catch (error) {
          toastError(t, error);
        }
      },
    }),
    [settings.defaultLifetime, addPlain, importMutation, environment.data, t],
  );

  return (
    <DialogsContext value={value}>
      {children}
      <Dialog open={open !== null} onOpenChange={(next) => (next ? undefined : close())}>
        {open?.kind === 'generate' ? (
          <GenerateKeyDialog onDone={close} onCreated={open.onCreated} />
        ) : null}
        {open?.kind === 'addHost' ? <AddHostDialog onDone={close} /> : null}
        {open?.kind === 'passphrase' ? (
          <PassphraseDialog keyView={open.key} suggest={open.suggest} onDone={close} />
        ) : null}
        {open?.kind === 'unlock' ? (
          <UnlockDialog
            keyView={open.key}
            lifetime={open.lifetime}
            onDone={close}
            onUnlocked={open.onUnlocked}
          />
        ) : null}
      </Dialog>
    </DialogsContext>
  );
}

export function useDialogs(): DialogsValue {
  const value = use(DialogsContext);
  if (!value) throw new Error('useDialogs must be used inside <DialogsProvider>');
  return value;
}
