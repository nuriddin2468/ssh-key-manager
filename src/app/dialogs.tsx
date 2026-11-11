import { isTauri } from '@tauri-apps/api/core';
import { open as openFile } from '@tauri-apps/plugin-dialog';
import {
  createContext,
  type ReactNode,
  use,
  useCallback,
  useEffect,
  useMemo,
  useRef,
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
import { RotateKeyDialog } from '@/features/keys/rotation/RotateKeyDialog';
import { UnlockVaultDialog } from '@/features/passwords/UnlockVaultDialog';
import { useSettings } from '@/lib/settings';
import { useRouter } from './router';

type Open =
  | { kind: 'generate'; onCreated?: (key: KeyView) => void }
  | { kind: 'addHost'; onSaved?: (alias: string) => void }
  | { kind: 'passphrase'; key: KeyView; suggest: boolean }
  | { kind: 'unlock'; key: KeyView; lifetime: number | null; onUnlocked?: () => void }
  | null;

interface VaultUnlock {
  description?: string;
  onUnlocked?: () => void;
}

interface DialogsValue {
  generateKey: () => void;
  /** Generates a key and hands it to `onCreated`, staying on the current page. */
  generateKeyFor: (onCreated: (key: KeyView) => void) => void;
  addHost: () => void;
  /** Adds a host and hands its name to `onSaved`, staying on the current page. */
  addHostFor: (onSaved: (alias: string) => void) => void;
  /** `suggest` starts with a generated passphrase, to be saved in the vault. */
  editPassphrase: (key: KeyView, options?: { suggest?: boolean }) => void;
  /**
   * Adds a key to the agent, asking for its passphrase when it has one, then
   * calls `onUnlocked`.
   */
  unlockKey: (key: KeyView, lifetime?: number | null, onUnlocked?: () => void) => void;
  /**
   * Opens the vault in a dialog, on whatever page or dialog is showing (it
   * opens above the others), then calls `onUnlocked`. `description` says what
   * it is opened for.
   */
  unlockVault: (options?: VaultUnlock) => void;
  importKey: () => Promise<void>;
  /** Replaces a key with a new one on its hosts; goes on with a rotation already started. */
  rotateKey: (key: KeyView) => void;
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
  // Its own state, so it opens above another of these dialogs instead of
  // replacing it. It opens from code, not a Radix trigger, so focus goes back
  // by hand.
  const [vault, setVault] = useState<VaultUnlock | null>(null);
  // Its own state too: the key and vault dialogs it opens go above it.
  const [rotating, setRotating] = useState<KeyView | null>(null);
  const vaultOpener = useRef<HTMLElement | null>(null);
  const showVault = useCallback((next: VaultUnlock) => {
    const active = document.activeElement;
    vaultOpener.current = active instanceof HTMLElement && active !== document.body ? active : null;
    setVault(next);
  }, []);
  const closeVault = useCallback(() => {
    const element = vaultOpener.current;
    vaultOpener.current = null;
    setVault(null);
    requestAnimationFrame(() => setTimeout(() => element?.isConnected && element.focus(), 0));
  }, []);

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
      addHostFor: (onSaved) => setOpen({ kind: 'addHost', onSaved }),
      editPassphrase: (key, options) =>
        setOpen({ kind: 'passphrase', key, suggest: options?.suggest ?? false }),
      unlockKey: (key, lifetime = settings.defaultLifetime, onUnlocked) => {
        if (key.encrypted) setOpen({ kind: 'unlock', key, lifetime, onUnlocked });
        else addPlain.mutate({ key, lifetime }, { onSuccess: () => onUnlocked?.() });
      },
      unlockVault: (options) => showVault(options ?? {}),
      rotateKey: (key) => setRotating(key),
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
    [settings.defaultLifetime, addPlain, importMutation, environment.data, t, showVault],
  );

  return (
    <DialogsContext value={value}>
      {children}
      <Dialog open={open !== null} onOpenChange={(next) => (next ? undefined : close())}>
        {open?.kind === 'generate' ? (
          <GenerateKeyDialog onDone={close} onCreated={open.onCreated} />
        ) : null}
        {open?.kind === 'addHost' ? <AddHostDialog onDone={close} onSaved={open.onSaved} /> : null}
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
      <Dialog
        open={rotating !== null}
        onOpenChange={(next) => (next ? undefined : setRotating(null))}
      >
        {rotating ? <RotateKeyDialog keyView={rotating} onDone={() => setRotating(null)} /> : null}
      </Dialog>
      <Dialog open={vault !== null} onOpenChange={(next) => (next ? undefined : closeVault())}>
        {vault ? (
          <UnlockVaultDialog
            description={vault.description}
            onUnlocked={vault.onUnlocked}
            onDone={closeVault}
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
