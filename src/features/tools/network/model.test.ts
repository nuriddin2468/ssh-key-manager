import { describe, expect, it } from 'vitest';
import type { HostEntry } from '@/bindings/HostEntry';
import { configTargets, formatMs, isAddress, isHost, parsePort } from './model';

describe('isHost', () => {
  it('takes names and addresses', () => {
    for (const host of [
      'example.com',
      'prod-api',
      '_dmarc.example.com',
      '10.0.0.1',
      '::1',
      '[fe80::1]',
    ]) {
      expect(isHost(host), host).toBe(true);
    }
  });

  it('refuses the rest', () => {
    for (const host of [
      '',
      'a b',
      'host/path',
      'user@host',
      '300.1.1.1',
      '1.2.3',
      'example..com',
    ]) {
      expect(isHost(host), host).toBe(false);
    }
  });

  it('tells addresses from names', () => {
    expect(isAddress('192.168.1.1')).toBe(true);
    expect(isAddress('2001:db8::1')).toBe(true);
    expect(isAddress('example.com')).toBe(false);
  });
});

describe('parsePort', () => {
  it('reads ports from 1 to 65535', () => {
    expect(parsePort('22')).toBe(22);
    expect(parsePort(' 443 ')).toBe(443);
    expect(parsePort('0')).toBeNull();
    expect(parsePort('65536')).toBeNull();
    expect(parsePort('22a')).toBeNull();
    expect(parsePort('')).toBeNull();
  });
});

function entry(partial: Partial<HostEntry>): HostEntry {
  return {
    id: 0,
    kind: 'host',
    patterns: [],
    criteria: null,
    options: [],
    hostName: null,
    user: null,
    port: null,
    identityFiles: [],
    proxyJump: null,
    isWildcard: false,
    lineStart: 1,
    lineEnd: 1,
    ...partial,
  };
}

describe('configTargets', () => {
  it('lists single-name hosts with where ssh connects', () => {
    const targets = configTargets([
      entry({ patterns: ['github.com'] }),
      entry({ patterns: ['bastion'], hostName: 'bastion.example.net', port: 2222 }),
      entry({ patterns: ['prod'], hostName: '10.0.4.12', proxyJump: 'bastion' }),
      entry({ patterns: ['direct'], hostName: 'd.example', proxyJump: 'none' }),
      entry({ patterns: ['*'], isWildcard: true }),
      entry({ kind: 'match', criteria: 'all' }),
    ]);
    expect(targets).toEqual([
      { alias: 'github.com', host: 'github.com', port: 22, jump: null },
      { alias: 'bastion', host: 'bastion.example.net', port: 2222, jump: null },
      { alias: 'prod', host: '10.0.4.12', port: 22, jump: 'bastion' },
      { alias: 'direct', host: 'd.example', port: 22, jump: null },
    ]);
  });
});

describe('formatMs', () => {
  it('keeps a decimal only for short times', () => {
    expect(formatMs(3.14, 'en')).toBe('3.1');
    expect(formatMs(23.6, 'en')).toBe('24');
    expect(formatMs(1234.5, 'en')).toBe('1,235');
  });
});
