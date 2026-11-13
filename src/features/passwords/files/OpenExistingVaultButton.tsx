import { FolderOpen } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { VaultLocation } from '@/bindings/VaultLocation';
import { Button, type ButtonProps } from '@/components/ui/Button';
import { showFileError } from './errors';
import { baseName, pickFile } from './pickers';

export interface OpenExistingVaultButtonProps
  extends Omit<ButtonProps, 'onClick' | 'loading' | 'type'> {
  /** Called once the app uses the chosen file; the vault status refetches by itself. */
  onOpened?: (location: VaultLocation) => void;
}

/**
 * For the first-run screen: use a vault made on another computer, or any
 * KeePass (`.kdbx`) database, instead of creating one. The page then asks
 * for its master password, or — without a keys file next to it — for its
 * recovery key or KeePass password.
 */
export function OpenExistingVaultButton({
  onOpened,
  children,
  variant = 'secondary',
  icon,
  ...props
}: OpenExistingVaultButtonProps) {
  const { t } = useTranslation();
  const open = useAppMutation((path: string) => api.vaultUseFile(path), {
    success: (location) =>
      t('vaultFiles.openExisting.opened', { file: baseName(location.paths.database) }),
    onSuccess: (location) => onOpened?.(location),
    onError: (error) =>
      showFileError(t, error, {
        parse: t('vaultFiles.location.notKeepass'),
        unsupported: t('vaultFiles.location.oldKeepass'),
      }),
  });

  const choose = async () => {
    try {
      const path = await pickFile();
      if (path) open.mutate(path);
    } catch (error) {
      toastError(t, error);
    }
  };

  return (
    <Button
      variant={variant}
      icon={icon ?? <FolderOpen className="size-4" strokeWidth={1.75} />}
      loading={open.isPending}
      onClick={() => void choose()}
      {...props}
    >
      {children ?? t('vaultFiles.openExisting.button')}
    </Button>
  );
}
