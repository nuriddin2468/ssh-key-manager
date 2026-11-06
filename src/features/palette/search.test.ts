import { describe, expect, it } from 'vitest';
import {
  byRecent,
  fold,
  matchText,
  normalizeQuery,
  parseQuery,
  rank,
  type Searchable,
  TIER,
} from './search';

const item = (id: string, title: string, extra: Partial<Searchable> = {}): Searchable => ({
  id,
  title,
  verbs: [],
  ...extra,
});

const titles = (items: Searchable[], query: string, recent: string[] = []) =>
  rank(items, query, recent).map((ranked) => ranked.item.id);

describe('matchText', () => {
  it('tells exact, prefix, contains and fuzzy apart', () => {
    expect(matchText('prod', 'prod')?.tier).toBe(TIER.exact);
    expect(matchText('Production', 'prod')?.tier).toBe(TIER.prefix);
    expect(matchText('web-prod', 'prod')?.tier).toBe(TIER.contains);
    expect(matchText('reproduce', 'prod')?.tier).toBe(TIER.contains);
    expect(matchText('pr-o-d', 'prod')?.tier).toBe(TIER.fuzzy);
    expect(matchText('dorp', 'prod')).toBeNull();
  });

  it('ranks a word start above text inside a word', () => {
    const word = matchText('web-prod', 'prod');
    const inside = matchText('reproduce', 'prod');
    expect(word && inside && word.score > inside.score).toBe(true);
  });

  it('ignores case and accents and keeps positions', () => {
    expect(matchText('Ünïcode Server', 'unicode')).toMatchObject({
      tier: TIER.prefix,
      positions: [0, 1, 2, 3, 4, 5, 6],
    });
    expect(fold('Ünïcode')).toHaveLength('Ünïcode'.length);
  });

  it('lets a space stand for any separator', () => {
    expect(matchText('web-prod.example', 'web prod')?.tier).toBe(TIER.prefix);
  });

  it('needs two letters for a fuzzy match', () => {
    expect(matchText('abc', 'z')).toBeNull();
    expect(matchText('a-b-c', 'ac')?.tier).toBe(TIER.fuzzy);
  });
});

describe('rank', () => {
  const hosts = [
    item('production', 'production'),
    item('prod', 'prod'),
    item('web-prod', 'web-prod'),
    item('p-r-o-d', 'p-r-o-d'),
  ];

  it('puts exact matches first, then prefixes, then the rest', () => {
    expect(titles(hosts, 'prod')).toEqual(['prod', 'production', 'web-prod', 'p-r-o-d']);
  });

  it('puts recently used items first within a tier, never above a better tier', () => {
    expect(titles(hosts, 'prod', ['p-r-o-d', 'production'])).toEqual([
      'prod',
      'production',
      'web-prod',
      'p-r-o-d',
    ]);
    const prefixes = [item('prometheus', 'prometheus'), item('prod-db', 'prod-db')];
    expect(titles(prefixes, 'pro')).toEqual(['prod-db', 'prometheus']);
    expect(titles(prefixes, 'pro', ['prometheus'])).toEqual(['prometheus', 'prod-db']);
  });

  it('reads a leading or trailing verb as the action', () => {
    const items = [
      item('host:prod:connect', 'prod', { verbs: ['Connect', 'ssh'], primary: true }),
      item('host:prod:open', 'prod', { verbs: ['Open host'] }),
      item('host:db:connect', 'db', { verbs: ['Connect', 'ssh'], primary: true }),
    ];
    expect(titles(items, 'connect prod')).toEqual(['host:prod:connect']);
    expect(titles(items, 'prod ssh')).toEqual(['host:prod:connect']);
    expect(titles(items, 'open prod')).toEqual(['host:prod:open']);
    // The object alone: its main action first.
    expect(titles(items, 'prod')).toEqual(['host:prod:connect', 'host:prod:open']);
    // The action alone: everything it applies to.
    expect(titles(items, 'ssh')).toEqual(['host:db:connect', 'host:prod:connect']);
  });

  it('finds items by their keywords, below title matches', () => {
    const items = [
      item('a', 'web', { keywords: ['deploy@10.0.0.5'] }),
      item('b', '10.0.0.5-backup'),
    ];
    expect(titles(items, '10.0.0.5')).toEqual(['b', 'a']);
    expect(rank(items, '10.0.0.5')[1]?.positions).toEqual([]);
  });

  it('returns nothing for an empty query', () => {
    expect(rank(hosts, '   ')).toEqual([]);
  });
});

describe('byRecent', () => {
  it('lists recently used items first, the rest in their order', () => {
    const items = [item('a', 'a'), item('b', 'b'), item('c', 'c')];
    expect(byRecent(items, ['c', 'gone', 'b']).map((i) => i.id)).toEqual(['c', 'b', 'a']);
  });
});

describe('parseQuery', () => {
  it('reads the scope prefixes', () => {
    expect(parseQuery('> lock')).toEqual({ scope: 'actions', text: 'lock' });
    expect(parseQuery('@prod')).toEqual({ scope: 'hosts', text: 'prod' });
    expect(parseQuery(' #github ')).toEqual({ scope: 'passwords', text: 'github' });
    expect(parseQuery('prod > x')).toEqual({ scope: 'all', text: 'prod > x' });
  });

  it('normalizes the text', () => {
    expect(normalizeQuery('  Connect   PROD ')).toBe('connect prod');
  });
});
