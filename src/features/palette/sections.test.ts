import type { TFunction } from 'i18next';
import { Lock } from 'lucide-react';
import { describe, expect, it } from 'vitest';
import type { HostEntry } from '@/bindings/HostEntry';
import { entryItems, hostItems, hostsOf, type PaletteItem } from './items';
import { buildSections } from './sections';

const t = ((key: string) => key) as unknown as TFunction;
const noop = () => undefined;

const block = (id: number, patterns: string[], extra: Partial<HostEntry> = {}): HostEntry => ({
  id,
  kind: 'host',
  patterns,
  criteria: null,
  options: [],
  hostName: null,
  user: null,
  port: null,
  identityFiles: [],
  proxyJump: null,
  isWildcard: patterns.some((pattern) => /[*?]/.test(pattern)),
  lineStart: 1,
  lineEnd: 1,
  ...extra,
});

const hosts = hostItems(
  t,
  hostsOf([
    block(0, ['prod', 'web'], { user: 'deploy', hostName: '10.0.0.5' }),
    block(1, ['*.internal']),
    block(2, ['prod']),
  ]),
  { connect: noop, open: noop },
);
const lock: PaletteItem = {
  id: 'action:lock',
  title: 'Lock the vault',
  verbs: [],
  scope: 'actions',
  action: '',
  icon: Lock,
  tone: 'pink',
  run: noop,
};
const entries = entryItems(
  t,
  [
    {
      id: 'e1',
      title: 'GitHub',
      username: 'me',
      url: 'https://github.com/login',
      kind: 'login',
      hasPassword: true,
      hasOtp: true,
    },
  ],
  { copy: noop },
);
const all = [lock, ...hosts, ...entries];
const ids = (sections: ReturnType<typeof buildSections>) =>
  sections.map((section) => [section.id, section.items.map((ranked) => ranked.item.id)]);

const browse = () => [{ id: 'actions', label: 'Actions', items: [lock] }];

describe('items', () => {
  it('makes a connect and an open item per alias, and only open for patterns', () => {
    expect(hosts.map((item) => item.id)).toEqual([
      'host:prod:connect',
      'host:prod:open',
      'host:web:connect',
      'host:web:open',
      'host:*.internal:open',
    ]);
    expect(hosts[0]?.detail).toBe('deploy@10.0.0.5');
    expect(hosts.find((item) => item.id === 'host:*.internal:open')?.primary).toBe(true);
  });

  it('copies only what an entry has, its password first', () => {
    expect(entries.map((item) => item.id)).toEqual([
      'entry:e1:password',
      'entry:e1:username',
      'entry:e1:otp',
    ]);
    expect(entries[0]?.detail).toBe('me · github.com');
  });
});

describe('buildSections', () => {
  it('shows recently run items before the suggestions, each once', () => {
    const sections = buildSections(all, '', {
      recent: ['action:lock', 'gone', 'host:web:connect'],
      recentLabel: 'Recent',
      browse,
    });
    expect(ids(sections)).toEqual([['recent', ['action:lock', 'host:web:connect']]]);
  });

  it('ranks matches within the scope a prefix names', () => {
    expect(ids(buildSections(all, '#git', { recent: [], recentLabel: '', browse }))).toEqual([
      ['matches', ['entry:e1:password', 'entry:e1:username', 'entry:e1:otp']],
    ]);
    expect(ids(buildSections(all, '@ copy', { recent: [], recentLabel: '', browse }))).toEqual([]);
    expect(
      ids(buildSections(all, 'copy otp git', { recent: [], recentLabel: '', browse })),
    ).toEqual([['matches', ['entry:e1:otp']]]);
  });

  it('browses a scope with nothing typed after its prefix', () => {
    const sections = buildSections(all, '@', {
      recent: ['action:lock'],
      recentLabel: 'Recent',
      browse: (scope) =>
        scope === 'hosts' ? [{ id: 'hosts', label: 'Hosts', items: hosts.slice(0, 1) }] : [],
    });
    expect(ids(sections)).toEqual([['hosts', ['host:prod:connect']]]);
  });
});
