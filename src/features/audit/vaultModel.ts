import type { TFunction } from 'i18next';
import type { Route } from '@/app/router';
import type { VaultFinding } from '@/bindings/VaultFinding';
import { formatDate } from '@/lib/format';

/** Ids of ignored vault findings are kept with this prefix, apart from SSH ones. */
export const IGNORE_PREFIX = 'vault:';

export function vaultFindingTitle(t: TFunction, finding: VaultFinding): string {
  return t(`audit.vault.kinds.${finding.kind.kind}.title`);
}

/** The finding's sentence; `titles` names entries by id. */
export function vaultFindingText(
  t: TFunction,
  finding: VaultFinding,
  titles: ReadonlyMap<string, string>,
  language: string,
): string {
  const kind = finding.kind;
  switch (kind.kind) {
    case 'weakPassword':
      return t(
        kind.score === 0
          ? 'audit.vault.kinds.weakPassword.textScore0'
          : 'audit.vault.kinds.weakPassword.text',
      );
    case 'reusedPassword': {
      const others = kind.entryIds
        .filter((id) => id !== finding.entryId)
        .map((id) => titles.get(id) ?? '—');
      const names = new Intl.ListFormat(language, { type: 'conjunction' }).format(others);
      return t('audit.vault.kinds.reusedPassword.text', { names });
    }
    case 'oldPassword':
      return t('audit.vault.kinds.oldPassword.text', {
        count: kind.years,
        date: formatDate(kind.changed, language),
      });
    case 'keyNotFound':
      return t('audit.vault.kinds.keyNotFound.text');
    case 'hostNotFound':
      return t('audit.vault.kinds.hostNotFound.text', { host: kind.host });
    case 'passwordLogin':
      return t('audit.vault.kinds.passwordLogin.text', { host: kind.host });
  }
}

type Label = 'audit.vault.openEntry' | 'audit.action.openKey' | 'audit.action.openHost';

/**
 * Where to fix a finding: a key's passphrase is changed on the key (which
 * updates the vault too), a password login on its host, anything else on the
 * entry itself.
 */
export function vaultFindingTarget(finding: VaultFinding): { route: Route; label: Label } {
  if (finding.kind.kind === 'passwordLogin' && finding.hostId !== null) {
    return { route: { page: 'hosts', hostId: finding.hostId }, label: 'audit.action.openHost' };
  }
  if (finding.keyId !== null) {
    return { route: { page: 'keys', keyId: finding.keyId }, label: 'audit.action.openKey' };
  }
  return { route: { page: 'passwords', entryId: finding.entryId }, label: 'audit.vault.openEntry' };
}
