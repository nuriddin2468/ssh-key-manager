import { describe, expect, it } from 'vitest';
import type { HostEntry } from '@/bindings/HostEntry';
import { changesFor, firstAlias, hasProxyCommand } from './model';

function host(id: number, patterns: string[], options: [string, string][]): HostEntry {
  return {
    id,
    kind: 'host',
    patterns,
    criteria: null,
    options: options.map(([key, value]) => ({ key, value })),
    hostName: null,
    user: null,
    port: null,
    identityFiles: [],
    proxyJump: options.find(([key]) => key === 'ProxyJump')?.[1] ?? null,
    isWildcard: false,
    lineStart: 1,
    lineEnd: 2,
  };
}

describe('ProxyJump wizard model', () => {
  it('lists the lines each block changes', () => {
    const web = host(
      1,
      ['web'],
      [
        ['ProxyJump', 'old'],
        ['ProxyJump', 'ignored'],
      ],
    );
    const db = host(2, ['db'], [['HostName', '10.0.0.6']]);
    const done = host(3, ['done'], [['ProxyJump', 'bastion']]);
    expect(changesFor([web, db, done], 'bastion')).toEqual([
      { host: web, removed: ['old', 'ignored'] },
      { host: db, removed: [] },
    ]);
  });

  it('names blocks and notices a ProxyCommand', () => {
    expect(firstAlias(host(1, ['*.x', 'web'], []))).toBe('web');
    expect(hasProxyCommand(host(1, ['a'], [['ProxyCommand', 'nc %h %p']]))).toBe(true);
    expect(hasProxyCommand(host(1, ['a'], []))).toBe(false);
  });
});
