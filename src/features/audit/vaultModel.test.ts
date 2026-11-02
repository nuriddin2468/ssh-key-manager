import { describe, expect, it } from 'vitest';
import type { VaultFinding } from '@/bindings/VaultFinding';
import i18n from '@/i18n';
import { vaultFindingTarget, vaultFindingText, vaultFindingTitle } from './vaultModel';

const t = i18n.getFixedT('en');

function finding(partial: Partial<VaultFinding> & Pick<VaultFinding, 'kind'>): VaultFinding {
  return {
    id: `${partial.kind.kind}:e1`,
    severity: 'warning',
    entryId: 'e1',
    keyId: null,
    hostId: null,
    ...partial,
  };
}

const titles = new Map([
  ['e1', 'AWS console'],
  ['e2', 'Router admin'],
  ['e3', 'Old forum'],
]);

describe('vaultFindingText', () => {
  it('names the other entries that share a password', () => {
    const reused = finding({ kind: { kind: 'reusedPassword', entryIds: ['e1', 'e2', 'e3'] } });
    expect(vaultFindingTitle(t, reused)).toBe('Reused password');
    expect(vaultFindingText(t, reused, titles, 'en')).toBe(
      'Also used by Router admin and Old forum. If one place leaks it, the others are exposed too.',
    );
  });

  it('tells a password guessed at once from a weak one', () => {
    const at = (score: number) =>
      vaultFindingText(t, finding({ kind: { kind: 'weakPassword', score } }), titles, 'en');
    expect(at(0)).toMatch(/^Guessed almost at once/);
    expect(at(1)).toMatch(/^Easy to guess/);
  });

  it('counts the years since an old password changed', () => {
    const old = (years: number) =>
      vaultFindingText(
        t,
        finding({ kind: { kind: 'oldPassword', changed: '2023-05-04T10:00:00Z', years } }),
        titles,
        'en',
      );
    expect(old(1)).toBe('Unchanged for over a year, since May 4, 2023.');
    expect(old(3)).toBe('Unchanged for over 3 years, since May 4, 2023.');
  });

  it('names the host of a host entry', () => {
    const login = finding({ kind: { kind: 'passwordLogin', host: 'prod-api' } });
    expect(vaultFindingText(t, login, titles, 'en')).toContain('prod-api');
  });
});

describe('vaultFindingTarget', () => {
  it('sends password logins to their host', () => {
    const login = finding({ kind: { kind: 'passwordLogin', host: 'prod-api' }, hostId: 3 });
    expect(vaultFindingTarget(login)).toEqual({
      route: { page: 'hosts', hostId: 3 },
      label: 'audit.action.openHost',
    });
  });

  it('sends a key passphrase to its key, where changing it updates the vault too', () => {
    const weak = finding({ kind: { kind: 'weakPassword', score: 1 }, keyId: 'SHA256:a#id' });
    expect(vaultFindingTarget(weak).route).toEqual({ page: 'keys', keyId: 'SHA256:a#id' });
  });

  it('sends everything else to the entry', () => {
    const gone = finding({ kind: { kind: 'keyNotFound', fingerprint: 'SHA256:x' } });
    expect(vaultFindingTarget(gone)).toEqual({
      route: { page: 'passwords', entryId: 'e1' },
      label: 'audit.vault.openEntry',
    });
    const missingHost = finding({ kind: { kind: 'hostNotFound', host: 'old-vpn' } });
    expect(vaultFindingTarget(missingHost).route.page).toBe('passwords');
  });
});
