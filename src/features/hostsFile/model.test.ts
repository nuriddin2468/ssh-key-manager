import { describe, expect, it } from 'vitest';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import { EMPTY_FORM, optionRow } from '@/features/hosts/model';
import { resolutionTarget } from './HostResolution';
import { isAddress, isIpAddress, isValidName, lookupName } from './model';

function entry(line: number, address: string, names: string[], enabled = true): HostsFileEntry {
  return {
    line,
    address,
    kind: 'private',
    names,
    comment: null,
    enabled,
    system: false,
    shadowed: [],
    group: null,
    expires: null,
  };
}

describe('lookupName', () => {
  const entries = [
    entry(1, '10.0.0.1', ['api.internal']),
    entry(2, '10.0.0.2', ['API.internal.']),
    entry(3, '10.0.0.3', ['api.internal'], false),
    entry(4, 'fd00::1', ['api.internal']),
    entry(5, '10.0.0.9', ['other']),
  ];

  it('finds turned-on lines and marks the first per address family as used', () => {
    expect(lookupName(entries, 'Api.Internal.').map((m) => [m.entry.line, m.used])).toEqual([
      [1, true],
      [2, false],
      [4, true],
    ]);
    expect(lookupName(entries, 'missing')).toEqual([]);
  });
});

describe('names and addresses', () => {
  it('validates names like the core does', () => {
    expect(isValidName('git.example.com.')).toBe(true);
    expect(isValidName('my_host-1')).toBe(true);
    expect(isValidName('*.corp')).toBe(false);
    expect(isValidName('a..b')).toBe(false);
    expect(isValidName('%h.example.com')).toBe(false);
  });

  it('recognises address literals', () => {
    expect(isAddress('10.0.4.12')).toBe(true);
    expect(isAddress('fe80::1')).toBe(true);
    expect(isAddress('db.internal')).toBe(false);
  });

  it('validates addresses like the core does', () => {
    for (const good of [
      '10.0.4.12',
      '::1',
      '::ffff:10.0.0.1',
      'fe80::1%lo0',
      'fe80::1%eth0.100',
      'fe80::1%12',
      'fe80::1%wl_p-2',
      `fe80::1%${'a'.repeat(64)}`,
    ]) {
      expect(isIpAddress(good), good).toBe(true);
    }
    for (const bad of [
      '10.0.4.256',
      '10.0.4',
      'db.internal',
      'fe80::1%',
      '10.0.0.1%lo0',
      'fe80::1%lo0%1',
      'fe80::1%a b',
      // A scope that would add a line of its own.
      'fe80::1%x\n203.0.113.66 www.bank.example',
      'fe80::1%lo0\r',
      'fe80::1%ünï',
      'fe80::1%a/b',
      'fe80::\n1',
      'fe80::\t1',
      `fe80::1%${'a'.repeat(65)}`,
    ]) {
      expect(isIpAddress(bad), JSON.stringify(bad)).toBe(false);
    }
  });
});

describe('resolutionTarget', () => {
  it('uses HostName, or the first alias without one', () => {
    expect(resolutionTarget({ ...EMPTY_FORM, patterns: 'prod', hostName: 'db.internal' })).toBe(
      'db.internal',
    );
    expect(resolutionTarget({ ...EMPTY_FORM, patterns: 'nas nas.home' })).toBe('nas');
  });

  it('skips addresses, patterns and hosts behind a jump host', () => {
    expect(resolutionTarget({ ...EMPTY_FORM, patterns: 'prod', hostName: '10.0.4.12' })).toBe(null);
    expect(resolutionTarget({ ...EMPTY_FORM, patterns: '*.corp' })).toBe(null);
    expect(
      resolutionTarget({ ...EMPTY_FORM, patterns: 'prod', hostName: 'db', proxyJump: 'bastion' }),
    ).toBe(null);
    expect(
      resolutionTarget({
        ...EMPTY_FORM,
        patterns: 'prod',
        hostName: 'db',
        other: [optionRow('ProxyCommand', 'nc -X 5 -x proxy:1080 %h %p')],
      }),
    ).toBe(null);
    expect(
      resolutionTarget({ ...EMPTY_FORM, patterns: 'prod', hostName: 'db', proxyJump: 'none' }),
    ).toBe('db');
  });
});
