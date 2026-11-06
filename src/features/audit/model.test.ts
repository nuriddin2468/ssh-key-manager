import { describe, expect, it } from 'vitest';
import type { Finding } from '@/bindings/Finding';
import type { VaultFinding } from '@/bindings/VaultFinding';
import {
  automaticFixes,
  bySeverity,
  CHECKS,
  checkResults,
  sshItem,
  vaultItem,
  worstSeverity,
} from './model';

function ssh(
  id: string,
  kind: Finding['kind'],
  severity: Finding['severity'],
  fix: Finding['fix'] = null,
): Finding {
  return {
    id,
    severity,
    kind,
    subject: { keyId: null, hostId: null, path: null },
    fix,
  };
}

function vault(
  id: string,
  kind: VaultFinding['kind'],
  severity: VaultFinding['severity'],
): VaultFinding {
  return { id, severity, kind, entryId: 'e1', keyId: null, hostId: null };
}

const permissions = ssh(
  'perm',
  { kind: 'privateKeyPermissions', mode: '644', problem: 'groupOrOtherAccess' },
  'critical',
  {
    kind: 'fixPermissions',
    path: '/home/me/.ssh/id_rsa',
    target: 'privateKey',
  },
);
const passphrase = ssh('pass', { kind: 'unencryptedKey' }, 'warning', {
  kind: 'addPassphrase',
  keyId: 'k1',
});
const pub = ssh('pub', { kind: 'missingPublicKey' }, 'info', {
  kind: 'regeneratePublic',
  keyId: 'k2',
});
const redirect = ssh(
  'dns',
  { kind: 'hostsFileRedirect', name: 'github.com', address: '10.0.0.1', line: 3 },
  'critical',
);
const weak = vault('weak', { kind: 'weakPassword', score: 0 }, 'critical');

describe('audit items', () => {
  it('belong to the area of their check', () => {
    expect(sshItem(permissions).area).toBe('keys');
    expect(
      sshItem(
        ssh(
          'dir',
          { kind: 'sshDirPermissions', mode: null, problem: 'groupOrOtherAccess' },
          'warning',
        ),
      ).area,
    ).toBe('config');
    expect(sshItem(redirect).area).toBe('hostsFile');
    expect(vaultItem(weak)).toMatchObject({ area: 'passwords', ignoreId: 'vault:weak' });
  });

  it('come most severe first, in their own order otherwise', () => {
    const items = [sshItem(pub), sshItem(passphrase), sshItem(permissions), sshItem(redirect)];
    expect(bySeverity(items).map((item) => item.ignoreId)).toEqual(['perm', 'dns', 'pass', 'pub']);
    expect(worstSeverity(items)).toBe('critical');
    expect(worstSeverity([])).toBeNull();
  });
});

describe('checks', () => {
  it('pass when they turned up nothing', () => {
    const results = checkResults([sshItem(passphrase), sshItem(redirect), vaultItem(weak)]);
    expect(results.get('passphrases')).toEqual({ count: 1, worst: 'warning' });
    expect(results.get('redirects')).toEqual({ count: 1, worst: 'critical' });
    expect(results.get('weak')).toEqual({ count: 1, worst: 'critical' });
    expect(results.get('algorithms')).toEqual({ count: 0, worst: null });
    expect(results.size).toBe(CHECKS.length);
  });

  it('have distinct ids', () => {
    expect(new Set(CHECKS.map((check) => check.id)).size).toBe(CHECKS.length);
  });
});

describe('automatic fixes', () => {
  it('take only fixes that need no answer from the user', () => {
    const fixes = automaticFixes([
      sshItem(permissions),
      sshItem(passphrase),
      sshItem(pub),
      vaultItem(weak),
    ]);
    expect(fixes.map((fix) => fix.kind)).toEqual(['fixPermissions', 'regeneratePublic']);
  });
});
