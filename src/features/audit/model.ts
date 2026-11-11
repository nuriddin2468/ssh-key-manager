import type { TFunction } from 'i18next';
import type { AuditReport } from '@/bindings/AuditReport';
import type { Finding } from '@/bindings/Finding';
import type { FixAction } from '@/bindings/FixAction';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import type { Severity } from '@/bindings/Severity';
import type { VaultFinding } from '@/bindings/VaultFinding';
import type { LeakGroup, LeakKind } from './leakModel';
import { IGNORE_PREFIX } from './vaultModel';

export const SEVERITY_ORDER: Severity[] = ['critical', 'warning', 'info'];

/** Hosts a finding names before it says how many more there are. */
const HOSTS_NAMED = 3;

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#FF6B6B',
  warning: '#FFB547',
  info: '#6CB4FF',
};

/** Findings per key id, for the key list and details panel. */
export function findingsByKey(report: AuditReport | undefined): Map<string, Finding[]> {
  const map = new Map<string, Finding[]>();
  for (const finding of report?.findings ?? []) {
    const ids =
      finding.kind.kind === 'duplicateKey'
        ? finding.kind.keyIds
        : finding.subject.keyId
          ? [finding.subject.keyId]
          : [];
    for (const id of ids) {
      const list = map.get(id) ?? [];
      list.push(finding);
      map.set(id, list);
    }
  }
  return map;
}

export function findingTitle(t: TFunction, finding: Finding): string {
  return t(`audit.kinds.${finding.kind.kind}.title`);
}

export function findingText(t: TFunction, finding: Finding): string {
  const kind = finding.kind;
  switch (kind.kind) {
    case 'rsaTooShort':
    case 'rsaBelowRecommended':
      return t(`audit.kinds.${kind.kind}.text`, { bits: kind.bits });
    case 'privateKeyPermissions':
    case 'sshDirPermissions':
    case 'configPermissions':
      return kind.mode
        ? t(`audit.kinds.${kind.kind}.textMode`, { mode: kind.mode })
        : t(`audit.kinds.${kind.kind}.text`);
    case 'duplicateKey':
      return t('audit.kinds.duplicateKey.text', { count: kind.keyIds.length });
    case 'identityFileMissing':
      return t('audit.kinds.identityFileMissing.text', { path: kind.path });
    case 'legacyFormat':
      return t('audit.kinds.legacyFormat.text', { format: kind.format.toUpperCase() });
    case 'hostsFileRedirect':
      return kind.name.replace(/\.$/, '').toLowerCase() === 'localhost'
        ? t('audit.kinds.hostsFileRedirect.textLocalhost', { address: kind.address })
        : t('audit.kinds.hostsFileRedirect.text', { name: kind.name, address: kind.address });
    case 'hostsFileExpired':
      return t('audit.kinds.hostsFileExpired.text', {
        names: kind.names.join(' '),
        address: kind.address,
        time: new Intl.DateTimeFormat(undefined, {
          dateStyle: 'medium',
          timeStyle: 'short',
        }).format(new Date(kind.expires)),
      });
    case 'hostsFileConflict':
      return t('audit.kinds.hostsFileConflict.text', {
        name: kind.name,
        addresses: kind.addresses.join(', '),
        address: kind.addresses[0] ?? '',
      });
    case 'strictHostKeyCheckingOff':
      return t(
        kind.knownHostsDiscarded
          ? 'audit.kinds.strictHostKeyCheckingOff.textDiscarded'
          : 'audit.kinds.strictHostKeyCheckingOff.text',
        { value: kind.value },
      );
    case 'knownHostsDiscarded':
      return t('audit.kinds.knownHostsDiscarded.text', { value: kind.value });
    case 'agentForwarding':
      return t(
        kind.wildcard
          ? 'audit.kinds.agentForwarding.textWildcard'
          : 'audit.kinds.agentForwarding.text',
      );
    case 'tooManyAgentKeys': {
      // A long config would make the sentence a list.
      const shown = kind.hosts.slice(0, HOSTS_NAMED).join(', ');
      const more = kind.hosts.length - HOSTS_NAMED;
      return t('audit.kinds.tooManyAgentKeys.text', {
        count: kind.agentKeys,
        hosts:
          more > 0
            ? t('audit.kinds.tooManyAgentKeys.hostsMore', { list: shown, count: more })
            : shown,
      });
    }
    default:
      return t(`audit.kinds.${kind.kind}.text`);
  }
}

/** What the finding is about, as a short label: a key name, `Host x`, a path. */
export function findingSubject(
  finding: Finding,
  keysById: ReadonlyMap<string, KeyView>,
  hosts: readonly HostEntry[],
  displayPath: (path: string) => string,
): string {
  const { keyId, hostId, path } = finding.subject;
  if (finding.kind.kind === 'hostsFileRedirect' || finding.kind.kind === 'hostsFileConflict') {
    return finding.kind.name;
  }
  if (finding.kind.kind === 'hostsFileExpired') return finding.kind.names.join(' ');
  if (keyId) return keysById.get(keyId)?.name ?? keyId.split('#').pop() ?? keyId;
  if (hostId !== null) {
    const host = hosts.find((h) => h.id === hostId);
    if (host?.kind === 'match') return `Match ${host.criteria ?? ''}`.trim();
    if (host) return `Host ${host.patterns.join(' ') || host.criteria || ''}`.trim();
  }
  // The block as the audit saw it, if the config has changed since.
  if (hostId !== null && 'patterns' in finding.kind && finding.kind.patterns.length > 0) {
    return `Host ${finding.kind.patterns.join(' ')}`;
  }
  return path ? displayPath(path) : '';
}

/** The parts of the setup the audit looks at; each finding belongs to one. */
export type Area = 'keys' | 'config' | 'hostsFile' | 'passwords' | 'leaks';

export const AREAS: Area[] = ['keys', 'config', 'hostsFile', 'passwords', 'leaks'];

type SshKind = Finding['kind']['kind'];
type VaultKind = VaultFinding['kind']['kind'];

/**
 * What the audit checks, in the order the page lists them, with the kinds of
 * finding each check turns up. A check with no open finding passed.
 */
export const CHECKS = [
  { id: 'algorithms', area: 'keys', kinds: ['dsaKey', 'rsaTooShort', 'rsaBelowRecommended'] },
  { id: 'passphrases', area: 'keys', kinds: ['unencryptedKey'] },
  { id: 'keyPermissions', area: 'keys', kinds: ['privateKeyPermissions'] },
  {
    id: 'keyFiles',
    area: 'keys',
    kinds: ['missingPublicKey', 'orphanPublicKey', 'pairMismatch', 'duplicateKey', 'legacyFormat'],
  },
  { id: 'folderPermissions', area: 'config', kinds: ['sshDirPermissions', 'configPermissions'] },
  { id: 'identityFiles', area: 'config', kinds: ['identityFileMissing'] },
  { id: 'hostKeys', area: 'config', kinds: ['strictHostKeyCheckingOff', 'knownHostsDiscarded'] },
  { id: 'agentForwarding', area: 'config', kinds: ['agentForwarding'] },
  { id: 'agentKeys', area: 'config', kinds: ['tooManyAgentKeys'] },
  { id: 'redirects', area: 'hostsFile', kinds: ['hostsFileRedirect'] },
  { id: 'hostsEntries', area: 'hostsFile', kinds: ['hostsFileConflict', 'hostsFileExpired'] },
  { id: 'weak', area: 'passwords', kinds: ['weakPassword'] },
  { id: 'reused', area: 'passwords', kinds: ['reusedPassword'] },
  { id: 'breached', area: 'passwords', kinds: ['breachedPassword'] },
  { id: 'old', area: 'passwords', kinds: ['oldPassword'] },
  { id: 'links', area: 'passwords', kinds: ['keyNotFound', 'hostNotFound'] },
  { id: 'passwordLogin', area: 'passwords', kinds: ['passwordLogin'] },
  { id: 'leaksAi', area: 'leaks', kinds: ['leakAi'] },
  { id: 'leaksRepositories', area: 'leaks', kinds: ['leakRepository'] },
  { id: 'leaksFiles', area: 'leaks', kinds: ['leakLocalFile'] },
  { id: 'leaksHistory', area: 'leaks', kinds: ['leakHistory'] },
] as const satisfies readonly {
  id: string;
  area: Area;
  kinds: readonly (SshKind | VaultKind | LeakKind)[];
}[];

export type CheckId = (typeof CHECKS)[number]['id'];

/** Every kind of finding belongs to a check: a new kind fails to compile until it has one. */
type Unchecked = Exclude<SshKind | VaultKind | LeakKind, (typeof CHECKS)[number]['kinds'][number]>;
export const EVERY_KIND_CHECKED: [Unchecked] extends [never] ? true : Unchecked = true;

/** One finding on the page: from `~/.ssh`, the vault, or the leak scanner. */
export type AuditItem = { ignoreId: string; area: Area; severity: Severity; kind: string } & (
  | { source: 'ssh'; finding: Finding }
  | { source: 'vault'; finding: VaultFinding }
  | { source: 'leak'; group: LeakGroup }
);

const AREA_OF: Record<string, Area> = Object.fromEntries(
  CHECKS.flatMap((check) => check.kinds.map((kind) => [kind, check.area])),
);

export function sshItem(finding: Finding): AuditItem {
  return {
    source: 'ssh',
    ignoreId: finding.id,
    area: AREA_OF[finding.kind.kind] ?? 'keys',
    severity: finding.severity,
    kind: finding.kind.kind,
    finding,
  };
}

export function vaultItem(finding: VaultFinding): AuditItem {
  return {
    source: 'vault',
    ignoreId: `${IGNORE_PREFIX}${finding.id}`,
    area: 'passwords',
    severity: finding.severity,
    kind: finding.kind.kind,
    finding,
  };
}

export function leakItem(group: LeakGroup): AuditItem {
  return {
    source: 'leak',
    ignoreId: group.ignoreId,
    area: 'leaks',
    severity: group.severity,
    kind: group.kind,
    group,
  };
}

/** The most serious severity among `items`, or `null` for none. */
export function worstSeverity(items: readonly { severity: Severity }[]): Severity | null {
  for (const severity of SEVERITY_ORDER) {
    if (items.some((item) => item.severity === severity)) return severity;
  }
  return null;
}

/** Items most severe first; items of the same severity keep their order. */
export function bySeverity<T extends { severity: Severity }>(items: readonly T[]): T[] {
  const rank = (item: T) => SEVERITY_ORDER.indexOf(item.severity);
  return items
    .map((item, at) => ({ item, at }))
    .sort((a, b) => rank(a.item) - rank(b.item) || a.at - b.at)
    .map(({ item }) => item);
}

/** The open findings each check turned up. */
export function checkResults(
  items: readonly AuditItem[],
): Map<CheckId, { count: number; worst: Severity | null }> {
  const results = new Map<CheckId, { count: number; worst: Severity | null }>();
  for (const check of CHECKS) {
    const kinds: readonly string[] = check.kinds;
    const found = items.filter((item) => kinds.includes(item.kind));
    results.set(check.id, { count: found.length, worst: worstSeverity(found) });
  }
  return results;
}

/** One-click fixes that need no answer from the user: file permissions and `.pub` files. */
export function automaticFixes(items: readonly AuditItem[]): FixAction[] {
  return items.flatMap((item) =>
    item.source === 'ssh' &&
    (item.finding.fix?.kind === 'fixPermissions' || item.finding.fix?.kind === 'regeneratePublic')
      ? [item.finding.fix]
      : [],
  );
}
