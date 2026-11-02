import { describe, expect, it } from 'vitest';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import { EMPTY_FORM, optionRow } from '@/features/hosts/model';
import { resolutionTarget } from './HostResolution';
import { isAddress, isValidName, lookupName } from './model';

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
