import type { TFunction } from 'i18next';
import type { AuditReport } from '@/bindings/AuditReport';
import type { Finding } from '@/bindings/Finding';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import type { Severity } from '@/bindings/Severity';

export const SEVERITY_ORDER: Severity[] = ['critical', 'warning', 'info'];

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
    if (host) return `Host ${host.patterns.join(' ') || host.criteria || ''}`.trim();
  }
  if (finding.kind.kind === 'identityFileMissing') {
    return `Host ${finding.kind.patterns.join(' ')}`;
  }
  return path ? displayPath(path) : '';
}

/** Keys that have no warning or critical finding. */
export function healthyKeyCount(keys: readonly KeyView[], byKey: Map<string, Finding[]>): number {
  return keys.filter((key) => !(byKey.get(key.id) ?? []).some((f) => f.severity !== 'info')).length;
}
