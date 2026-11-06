import { describe, expect, it } from 'vitest';
import type { Finding } from '@/bindings/Finding';
import type { HostEntry } from '@/bindings/HostEntry';
import type { VaultFinding } from '@/bindings/VaultFinding';
import i18n from '@/i18n';
import {
  automaticFixes,
  bySeverity,
  CHECKS,
  checkResults,
  findingSubject,
  findingText,
  sshItem,
  vaultItem,
  worstSeverity,
} from './model';
import { fixLabelKey } from './useFix';

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

describe('config settings', () => {
  const t = i18n.getFixedT('en');
  const strict = (knownHostsDiscarded: boolean) =>
    ssh(
      'strict',
      {
        kind: 'strictHostKeyCheckingOff',
        value: 'no',
        patterns: ['lab-*'],
        knownHostsDiscarded,
      },
      knownHostsDiscarded ? 'critical' : 'warning',
      { kind: 'removeConfigOption', hostId: 2, key: 'StrictHostKeyChecking', value: 'no' },
    );
  const tooMany = ssh(
    'tooManyAgentKeys',
    { kind: 'tooManyAgentKeys', agentKeys: 8, hosts: ['gh github.com', 'build'] },
    'warning',
    { kind: 'addIdentitiesOnly', hostIds: [0, 7] },
  );

  it('belong to the config area and need a click to fix', () => {
    expect(sshItem(strict(false)).area).toBe('config');
    expect(sshItem(tooMany).area).toBe('config');
    expect(automaticFixes([sshItem(strict(true)), sshItem(tooMany)])).toEqual([]);
    expect(fixLabelKey(strict(false))).toBe('audit.action.removeConfigOption');
    expect(fixLabelKey(tooMany)).toBe('audit.action.addIdentitiesOnly');
  });

  it('say what the setting does', () => {
    expect(findingText(t, strict(false))).toMatch(/^StrictHostKeyChecking no makes ssh trust/);
    expect(findingText(t, strict(true))).toContain('UserKnownHostsFile /dev/null');
    const many = { ...tooMany.kind, hosts: ['a', 'b', 'c', 'd', 'e'] };
    expect(findingText(t, { ...tooMany, kind: many })).toContain('on a, b, c and 2 more before');
    expect(findingText(t, tooMany)).toContain(
      'holds 8 keys, and ssh may try them all on gh github.com, build',
    );
    const forwarding = (wildcard: boolean) =>
      findingText(
        t,
        ssh('fwd', { kind: 'agentForwarding', value: 'yes', patterns: ['*'], wildcard }, 'info'),
      );
    expect(forwarding(true)).toMatch(/^Every server/);
    expect(forwarding(false)).toMatch(/^This server/);
  });

  it('name their block, or the file before the first one', () => {
    const block = { ...strict(false), subject: { keyId: null, hostId: 2, path: '/h/.ssh/config' } };
    const hosts = [
      { id: 2, kind: 'match', patterns: [], criteria: 'host lab-1' } as unknown as HostEntry,
    ];
    expect(findingSubject(block, new Map(), hosts, (p) => p)).toBe('Match host lab-1');
    // The block as the audit saw it, once the config changed.
    expect(findingSubject(block, new Map(), [], (p) => p)).toBe('Host lab-*');
    const global = { ...tooMany, subject: { keyId: null, hostId: null, path: '/h/.ssh/config' } };
    expect(findingSubject(global, new Map(), [], (p) => p.replace('/h', '~'))).toBe(
      '~/.ssh/config',
    );
  });
});
