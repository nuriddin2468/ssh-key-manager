import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { Finding } from '@/bindings/Finding';
import type { FixAction } from '@/bindings/FixAction';
import type { KeyView } from '@/bindings/KeyView';
import { editOf } from '@/features/hostsFile/draft';
import { reportUnapplied } from '@/features/hostsFile/useHostsApply';
import { AppError } from '@/lib/ipc';

const FIX_LABELS = {
  fixPermissions: 'audit.action.fixPermissions',
  addPassphrase: 'audit.action.addPassphrase',
  regeneratePublic: 'audit.action.regeneratePublic',
  removeIdentityFile: 'audit.action.removeIdentityFile',
  turnOffHostsEntry: 'audit.action.turnOff',
} as const;

/** The label of a finding's one-click fix, or of "open" when there is none. */
export function fixLabelKey(finding: Finding) {
  if (finding.fix) return FIX_LABELS[finding.fix.kind];
  if (hostsFileLine(finding) !== undefined) return 'audit.action.openHostsFile';
  if (finding.subject.hostId !== null && !finding.subject.keyId) return 'audit.action.openHost';
  return 'audit.action.openKey';
}

/** The hosts file line a finding is about, if it is about one. */
function hostsFileLine(finding: Finding): number | undefined {
  const kind = finding.kind;
  if (kind.kind === 'hostsFileRedirect') return kind.line;
  if (kind.kind === 'hostsFileConflict') return kind.lines[0];
  if (kind.kind === 'hostsFileExpired') return kind.line;
  return undefined;
}

/** Runs a finding's fix: some apply at once, some open a dialog or a page. */
export function useFix(keysById: ReadonlyMap<string, KeyView>) {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const { navigate } = useRouter();
  // With the vault open, a missing passphrase can be generated and saved there.
  const vaultUnlocked = useVaultStatus().data?.state === 'unlocked';

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
        case 'turnOffHostsEntry': {
          const file = await api.hostsFile();
          const entry = file.view.entries.find((e) => e.line === action.line);
          if (!entry) throw new AppError('not_found', `hosts file line ${action.line}`);
          const result = await api.applyHostsChanges({
            revision: file.revision,
            changes: [
              {
                kind: 'set',
                line: entry.line,
                entry: { ...editOf(entry), enabled: false, expires: null },
              },
            ],
            flushDns: true,
            prompt: t('hostsFile.authPrompt'),
          });
          if (result.outcome === 'applied')
            toast.success(t('hostsFile.turnedOff', { name: entry.names[0] ?? entry.address }));
          else reportUnapplied(t, result);
          return undefined;
        }
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
      if (key) dialogs.editPassphrase(key, { suggest: vaultUnlocked });
      return;
    }
    if (action) {
      run.mutate(action);
      return;
    }
    const line = hostsFileLine(finding);
    if (line !== undefined) navigate({ page: 'hostsFile', line });
    else if (finding.subject.keyId) navigate({ page: 'keys', keyId: finding.subject.keyId });
    else if (finding.subject.hostId !== null)
      navigate({ page: 'hosts', hostId: finding.subject.hostId });
  };

  return { fix, pending: run.isPending ? run.variables : undefined };
}
