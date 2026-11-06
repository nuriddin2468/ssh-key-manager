import { useMemo } from 'react';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import { useKeyForFile } from '@/features/hosts/HostFields';
import { formFromHost } from '@/features/hosts/model';
import { useHostVault } from '@/features/hosts/vault';
import { useVaultKey } from '@/features/keys/vaultKey';
import type { HostFacts } from './model';

/**
 * What the "Why it failed" panel needs to know about `host`, and its key.
 * `identityFile`: the editor's unsaved choice; the saved block's otherwise.
 */
export function useHostFacts(
  host: HostEntry,
  identityFile?: string,
): { facts: HostFacts; key: KeyView | undefined } {
  const vault = useHostVault(host);
  const passwordSaved = vault.vault === 'unlocked' && Boolean(vault.entry);
  const saved = useMemo(() => formFromHost(host, { passwordSaved }), [host, passwordSaved]);
  const { key } = useKeyForFile(identityFile ?? saved.identityFile);
  const keyVault = useVaultKey(key?.fingerprint);
  const keyLocked = Boolean(
    key?.encrypted &&
      !key.inAgent &&
      !key.hardware &&
      !(keyVault.vault === 'unlocked' && keyVault.entry),
  );
  return {
    facts: {
      passwordSaved,
      vaultOpen: vault.vault === 'unlocked',
      vaultLocked: vault.vault === 'locked',
      hasKey: Boolean(key),
      keyLocked,
    },
    key,
  };
}
