import { AlertTriangle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useVaultStatus } from '@/api/queries';
import { errorMessage } from '@/api/useAppMutation';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { EmptyState } from '@/components/ui/EmptyState';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { BackToProject } from '@/features/projects/BackToProject';
import { AppError } from '@/lib/ipc';
import { CreateVault, RecoveryKeyScreen, UnsavedRecoveryKey } from './CreateVault';
import { UnlockVault } from './UnlockVault';
import { VaultBrowser } from './VaultBrowser';
import { usePendingRecoveryKey, useUnsavedRecoveryKeyReminder } from './vault';

/**
 * The password vault: create it, unlock it, or browse it. A recovery key that
 * was just created stays on screen until it is confirmed as saved.
 */
export function PasswordsPage({ entryId }: { entryId?: string }) {
  const { t } = useTranslation();
  const status = useVaultStatus();
  const recoveryKey = usePendingRecoveryKey();
  const remind = useUnsavedRecoveryKeyReminder();
  const state = status.data?.state;

  if (!recoveryKey && !remind && state === 'unlocked') return <VaultBrowser entryId={entryId} />;

  return (
    <>
      <Toolbar leading={<BackToProject />} title={t('passwords.title')} />
      <PageBody>
        {recoveryKey ? (
          <RecoveryKeyScreen recoveryKey={recoveryKey} />
        ) : remind && state === 'unlocked' ? (
          <UnsavedRecoveryKey />
        ) : status.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : status.isError ? (
          <EmptyState
            className="my-auto"
            icon={
              <Tile tone="rose" size={52} glow>
                <AlertTriangle className="size-6" strokeWidth={2} />
              </Tile>
            }
            title={t('passwords.loadFailed')}
            description={
              // The only `unsupported` the status gives: vault.keys from a newer app.
              AppError.from(status.error).code === 'unsupported'
                ? t('passwords.keysTooNew')
                : errorMessage(t, status.error)
            }
            action={<Button onClick={() => void status.refetch()}>{t('common.retry')}</Button>}
          />
        ) : state === 'missing' ? (
          <CreateVault />
        ) : status.data ? (
          <UnlockVault files={status.data.files} device={status.data.device} />
        ) : null}
      </PageBody>
    </>
  );
}
