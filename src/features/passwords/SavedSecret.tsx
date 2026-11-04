import { useMutation } from '@tanstack/react-query';
import { Copy, Eye, EyeOff } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useDialogs } from '@/app/dialogs';
import { IconButton } from '@/components/ui/IconButton';
import { Spinner } from '@/components/ui/Spinner';
import { toastVaultError, useSecretCall } from './vault';

/** A revealed secret hides itself again after this long. */
export const REVEAL_MS = 30_000;
export const MASK = '••••••••••••';

/**
 * What to do with a secret once the vault the user just opened lists its
 * entry, by `SavedSecret`'s `id`. Kept outside the component: the screen may
 * remount it while the entries load. A wish older than a few seconds is
 * dropped, so a later unlock doesn't show a secret by surprise.
 */
const wishes = new Map<string, { action: 'reveal' | 'copy'; at: number }>();
const WISH_MS = 15_000;

interface SavedSecretProps {
  /** Names the secret while its entry is unknown, e.g. `key:<fingerprint>`. */
  id: string;
  /** The vault entry that holds the secret; unknown while the vault is locked. */
  entryId: string | undefined;
  locked: boolean;
  labels: { show: string; hide: string; copy: string; copied: string };
  /** What the vault is opened for, in the unlock dialog. */
  unlockReason: string;
}

/**
 * A secret saved in the vault, shown where it is used: masked until clicked.
 * A locked vault is opened in a dialog first, so nobody has to go to
 * Passwords to read it. The secret lives only in this component's state.
 */
export function SavedSecret({ id, entryId, locked, labels, unlockReason }: SavedSecretProps) {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const [revealed, setRevealed] = useState<string | null>(null);
  const reveal = useSecretCall(api.vaultReveal);
  const copy = useMutation({
    mutationFn: (id: string) => api.vaultCopy(id, 'password'),
    onSuccess: (result) => {
      toast.success(labels.copied, {
        id: 'vault-copy',
        description:
          result.clearsInSecs !== null
            ? t('passwords.clearsIn', { seconds: result.clearsInSecs })
            : undefined,
      });
    },
    onError: (error) => toastVaultError(t, error),
  });

  // Locking the vault, or another entry, hides it.
  useEffect(() => {
    void entryId;
    if (locked) setRevealed(null);
  }, [locked, entryId]);
  useEffect(() => {
    if (revealed === null) return;
    const timer = window.setTimeout(() => setRevealed(null), REVEAL_MS);
    return () => window.clearTimeout(timer);
  }, [revealed]);

  const run = (action: 'reveal' | 'copy', entry: string) => {
    if (action === 'copy') {
      copy.mutate(entry);
      return;
    }
    reveal
      .call(entry, 'password')
      .then(setRevealed)
      .catch((error: unknown) => toastVaultError(t, error));
  };
  // After each render: the entry shows up a render or two after the unlock.
  useEffect(() => {
    const wish = wishes.get(id);
    if (!wish || locked || !entryId) return;
    wishes.delete(id);
    if (Date.now() - wish.at < WISH_MS) run(wish.action, entryId);
  });

  const act = (action: 'reveal' | 'copy') => {
    if (reveal.pending || copy.isPending) return;
    if (locked || !entryId) {
      dialogs.unlockVault({
        description: unlockReason,
        onUnlocked: () => wishes.set(id, { action, at: Date.now() }),
      });
    } else {
      run(action, entryId);
    }
  };

  return (
    <span className="flex min-w-0 items-center gap-1">
      {revealed === null ? (
        <button
          type="button"
          aria-label={labels.show}
          onClick={() => act('reveal')}
          className="field pressable flex h-[30px] min-w-0 items-center gap-2 rounded-lg px-2.5 text-muted hover:text-fg"
        >
          <span aria-hidden="true" className="truncate font-mono tracking-[0.1em]">
            {MASK}
          </span>
          {reveal.pending ? (
            <Spinner className="size-3.5 shrink-0" />
          ) : (
            <Eye aria-hidden="true" className="size-[15px] shrink-0" strokeWidth={1.75} />
          )}
        </button>
      ) : (
        <>
          <span className="selectable min-w-0 font-mono text-[12.5px] break-all text-fg">
            {revealed}
          </span>
          <IconButton
            label={labels.hide}
            icon={<EyeOff className="size-[15px]" strokeWidth={1.75} />}
            onClick={() => setRevealed(null)}
          />
        </>
      )}
      <IconButton
        label={labels.copy}
        icon={
          copy.isPending ? (
            <Spinner className="size-3.5" />
          ) : (
            <Copy className="size-[15px]" strokeWidth={1.75} />
          )
        }
        onClick={() => act('copy')}
      />
    </span>
  );
}
