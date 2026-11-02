import { BookKey, WandSparkles } from 'lucide-react';
import { type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { GenerateOptions } from '@/bindings/GenerateOptions';
import { Button } from '@/components/ui/Button';
import { SwitchRow } from '@/components/ui/Switch';
import { cn } from '@/lib/cn';
import { keyEntryInput, type VaultKey } from './vaultKey';

/** Five words from the EFF list and a digit: about 68 bits, easy to type. */
const PASSPHRASE: GenerateOptions = {
  mode: 'passphrase',
  words: 5,
  separator: '-',
  capitalize: true,
  number: true,
};

/** Generates a passphrase with the vault's generator; works while it is locked. */
export function generatePassphrase(): Promise<string> {
  return api.vaultGenerate(PASSPHRASE);
}

/** "Generate a strong passphrase", for the passphrase fields of a form. */
export function GeneratePassphraseButton({
  onGenerated,
}: {
  onGenerated: (value: string) => void;
}) {
  const { t } = useTranslation();
  const [busy, setBusy] = useState(false);
  // Screen readers hear that the fields were filled; focus stays on the button.
  const [announcement, setAnnouncement] = useState('');
  const run = async () => {
    setBusy(true);
    setAnnouncement('');
    try {
      onGenerated(await generatePassphrase());
      setAnnouncement(t('generate.suggested'));
    } catch (error) {
      toastError(t, error);
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        className="self-start"
        loading={busy}
        icon={<WandSparkles aria-hidden="true" className="size-[15px]" strokeWidth={1.9} />}
        onClick={() => void run()}
      >
        {t('generate.suggest')}
      </Button>
      <span aria-live="polite" className="sr-only">
        {announcement}
      </span>
    </>
  );
}

/**
 * Creates the vault entry holding a key's passphrase, or updates `existing`
 * (keeping its title, notes and other fields).
 */
export async function savePassphrase(
  key: { name: string; fingerprint: string },
  passphrase: string,
  existing?: EntrySummary,
): Promise<EntryDetail> {
  if (!existing) return api.vaultAdd(keyEntryInput(key, passphrase));
  const detail = await api.vaultEntry(existing.id);
  return api.vaultUpdate(existing.id, keyEntryInput(key, passphrase, detail));
}

interface VaultSaveRowProps {
  vault: VaultKey;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
  /** Called before going to the Passwords page, e.g. to close the dialog. */
  onLeave: () => void;
}

/**
 * A row for a `SwitchGroup`: the "save in the vault" switch while the vault
 * is unlocked, else a short explanation with a way to the Passwords page.
 */
export function VaultSaveRow({
  vault,
  checked,
  onCheckedChange,
  disabled,
  onLeave,
}: VaultSaveRowProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const leave = () => {
    onLeave();
    navigate({ page: 'passwords' });
  };
  switch (vault.vault) {
    case 'unlocked':
      return (
        <SwitchRow
          label={vault.entry ? t('generate.updateInVault') : t('generate.saveInVault')}
          hint={t('generate.saveInVaultHint')}
          checked={checked && !disabled}
          disabled={disabled}
          onCheckedChange={onCheckedChange}
        />
      );
    case 'locked':
      return (
        <InfoRow
          label={t('generate.vaultLocked')}
          hint={t('generate.vaultLockedHint')}
          action={t('generate.unlockVault')}
          onAction={leave}
        />
      );
    case 'missing':
      return (
        <InfoRow
          label={t('generate.vaultMissing')}
          hint={t('generate.vaultMissingHint')}
          action={t('generate.setUpVault')}
          onAction={leave}
        />
      );
    default:
      return null;
  }
}

interface InfoRowProps {
  label: string;
  hint: string;
  action: string;
  onAction: () => void;
}

/** Laid out like a `SwitchRow`, with a button where the switch would be. */
function InfoRow({ label, hint, action, onAction }: InfoRowProps) {
  return (
    <div className="flex items-center gap-3 rounded-[10px] px-2.5 py-[9px]">
      <div className="flex min-w-0 flex-1 flex-col">
        <span className="font-medium text-fg">{label}</span>
        <span className="text-[12px] text-subtle">{hint}</span>
      </div>
      <Button size="sm" onClick={onAction}>
        {action}
      </Button>
    </div>
  );
}

interface VaultCalloutProps {
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}

/** A tinted note about the vault, in the section's accent, with an action below. */
export function VaultCallout({ children, action, className }: VaultCalloutProps) {
  return (
    <div
      className={cn(
        'flex items-start gap-2.5 rounded-xl border border-[rgb(var(--accent-rgb)/0.3)] bg-[rgb(var(--accent-rgb)/0.08)] px-3 py-2.5',
        className,
      )}
    >
      <VaultIcon className="mt-px size-4 shrink-0 text-[var(--accent-text)]" />
      <div className="flex min-w-0 flex-1 flex-col items-start gap-2">
        <p className="text-[12.5px] leading-[18px] text-fg-2">{children}</p>
        {action}
      </div>
    </div>
  );
}

/** The icon for things kept in the vault. */
export function VaultIcon({ className }: { className?: string }) {
  return <BookKey aria-hidden="true" className={className} strokeWidth={1.9} />;
}
