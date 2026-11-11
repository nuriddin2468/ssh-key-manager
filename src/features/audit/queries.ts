import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/commands';
import { useAudit, useVaultStatus } from '@/api/queries';
import type { Severity } from '@/bindings/Severity';
import { useSettings } from '@/lib/settings';
import { leakKeys } from './LeakScan';
import { splitIgnored } from './leakModel';
import { sshItem, vaultItem } from './model';

/** The vault's findings; keyed by its state, so locking or unlocking checks again. */
export function useVaultAudit() {
  const vaultState = useVaultStatus().data?.state;
  return useQuery({
    queryKey: ['vault', 'audit', vaultState],
    queryFn: api.vaultAudit,
    enabled: vaultState !== undefined,
  });
}

/** The leak scanner's findings, while the vault is unlocked; locking drops them. */
export function useLeakFindings() {
  const vaultState = useVaultStatus().data?.state;
  return useQuery({
    queryKey: [...leakKeys.findings, vaultState],
    queryFn: api.leaksFindings,
    enabled: vaultState === 'unlocked',
  });
}

/**
 * Audit's open findings by severity, as its summary counts them: of SSH, the
 * vault and the leak scanner, without those the user set aside.
 * `undefined` until the SSH audit has run.
 */
export function useOpenFindingCounts(): Record<Severity, number> | undefined {
  const audit = useAudit();
  const vault = useVaultAudit();
  const leaks = useLeakFindings();
  const ignoredList = useSettings().ignoredFindings;
  if (!audit.data) return undefined;
  const ignored = new Set(ignoredList);
  const locked = vault.data?.state === 'locked';
  const severities = [
    ...[...audit.data.findings.map(sshItem), ...(vault.data?.findings ?? []).map(vaultItem)]
      .filter((item) => !ignored.has(item.ignoreId))
      .map((item) => item.severity),
    ...splitIgnored(locked ? [] : (leaks.data ?? []), ignored).open.map((group) => group.severity),
  ];
  const counts: Record<Severity, number> = { critical: 0, warning: 0, info: 0 };
  for (const severity of severities) counts[severity] += 1;
  return counts;
}
