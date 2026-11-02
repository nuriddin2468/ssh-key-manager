import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { Finding } from '@/bindings/Finding';
import type { FixAction } from '@/bindings/FixAction';
import type { KeyView } from '@/bindings/KeyView';

const FIX_LABELS = {
  fixPermissions: 'audit.action.fixPermissions',
  addPassphrase: 'audit.action.addPassphrase',
  regeneratePublic: 'audit.action.regeneratePublic',
  removeIdentityFile: 'audit.action.removeIdentityFile',
} as const;

/** The label of a finding's one-click fix, or of "open" when there is none. */
export function fixLabelKey(finding: Finding) {
  if (finding.fix) return FIX_LABELS[finding.fix.kind];
  if (finding.subject.hostId !== null && !finding.subject.keyId) return 'audit.action.openHost';
  return 'audit.action.openKey';
}

/** Runs a finding's fix: some apply at once, some open a dialog or a page. */
export function useFix(keysById: ReadonlyMap<string, KeyView>) {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const { navigate } = useRouter();

  const run = useAppMutation(
    async (action: FixAction) => {
      switch (action.kind) {
        case 'fixPermissions':
          return api
            .fixPermissions([{ path: action.path, kind: action.target }])
            .then(() => undefined);
        case 'regeneratePublic':
          return api.regeneratePublic(action.keyId).then(() => undefined);
        case 'removeIdentityFile':
          return api.removeIdentityFile(action.hostId, action.path).then(() => undefined);
        case 'addPassphrase':
          return undefined;
      }
    },
    {
      success: (_, action) =>
        action.kind === 'fixPermissions' ? t('audit.fixedPermissions', { count: 1 }) : undefined,
    },
  );

  const fix = (finding: Finding) => {
    const action = finding.fix;
    if (action?.kind === 'addPassphrase') {
      const key = keysById.get(action.keyId);
      if (key) dialogs.editPassphrase(key);
      return;
    }
    if (action) {
      run.mutate(action);
      return;
    }
    if (finding.subject.keyId) navigate({ page: 'keys', keyId: finding.subject.keyId });
    else if (finding.subject.hostId !== null)
      navigate({ page: 'hosts', hostId: finding.subject.hostId });
  };

  return { fix, pending: run.isPending ? run.variables : undefined };
}
