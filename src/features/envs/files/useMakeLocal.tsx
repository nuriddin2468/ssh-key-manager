import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { useVaultMutation } from '@/features/passwords/vault';
import { isProduction } from '../model';
import { useEnvLabel } from '../useProjectNames';

/**
 * Makes an environment local, so it can be written to files. One that
 * looks like production asks first: its values would be on this disk.
 */
export function useMakeLocal(env: EnvSummary) {
  const { t } = useTranslation();
  const envLabelOf = useEnvLabel();
  const [confirming, setConfirming] = useState(false);
  const label = envLabelOf(env);
  const makeLocal = useVaultMutation(() => api.envsSetKind(env.id, 'local'), {
    success: () => t('envs.kind.nowLocal', { name: label }),
    onSuccess: () => setConfirming(false),
  });
  const start = () => {
    if (isProduction(env.name)) setConfirming(true);
    else makeLocal.mutate(undefined);
  };
  const dialog = (
    <ConfirmDialog
      open={confirming}
      onOpenChange={setConfirming}
      title={t('envs.kind.prodTitle', { name: label })}
      description={t('envs.kind.prodText', { name: label })}
      confirmLabel={t('envs.kind.makeLocal')}
      destructive
      busy={makeLocal.isPending}
      onConfirm={() => makeLocal.mutate(undefined)}
    />
  );
  return { start, dialog, pending: makeLocal.isPending };
}
