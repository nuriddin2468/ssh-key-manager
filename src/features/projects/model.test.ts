import { describe, expect, it } from 'vitest';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { KeyView } from '@/bindings/KeyView';
import type { Project } from '@/bindings/Project';
import {
  aliasOf,
  cardColumns,
  hostAliases,
  hostsFileEntries,
  initials,
  missing,
  nextColor,
  personal,
  planHostsFileSwitch,
  problemsFirst,
  projectTone,
} from './model';

const project = (patch: Partial<Project>): Project => ({
  id: 'p1',
  name: 'Shop',
  color: 'blue',
  folders: [],
  hosts: [],
  keys: [],
  environments: [],
  logins: [],
  hostsFile: [],
  modified: '2026-11-10T10:00:00Z',
  ...patch,
});

const host = (id: number, patterns: string[], wildcard = false): HostEntry =>
  ({
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
    isWildcard: wildcard,
    lineStart: 1,
    lineEnd: 1,
  }) as HostEntry;

const key = (name: string, fingerprint: string | null) =>
  ({ id: name, name, fingerprint }) as unknown as KeyView;
const env = (project: string, name: string, inTrash = false) =>
  ({ id: `${project}/${name}`, project, name, inTrash }) as EnvSummary;
const entry = (id: string, kind: EntrySummary['kind'] = 'login', inTrash = false) =>
  ({ id, kind, inTrash }) as EntrySummary;

describe('project tiles', () => {
  it('take two letters from two words, else from one', () => {
    expect(initials('Shop')).toBe('SH');
    expect(initials('Marketing site')).toBe('MS');
    expect(initials('home-lab')).toBe('HL');
    expect(initials('Ёж')).toBe('ЁЖ');
    expect(initials('  ')).toBe('');
  });

  it('use the rose tone for red and a color few projects have for new ones', () => {
    expect(projectTone('red')).toBe('rose');
    expect(projectTone('teal')).toBe('teal');
    expect(nextColor([])).toBe('teal');
    expect(nextColor([project({ color: 'teal' })])).toBe('blue');
  });
});

describe('Personal', () => {
  it('holds what no project does', () => {
    const projects = [
      project({ hosts: ['prod'], keys: ['SHA256:a'], environments: ['shop-api'], logins: ['l1'] }),
    ];
    const mine = personal(projects, {
      hosts: [host(0, ['prod', 'prod.example.com']), host(1, ['blog']), host(2, ['*'], true)],
      keys: [key('id_a', 'SHA256:a'), key('id_b', 'SHA256:b'), key('broken', null)],
      envs: [env('shop-api', 'dev'), env('blog', 'dev'), env('old', 'dev', true)],
      entries: [entry('l1'), entry('l2'), entry('h1', 'host'), entry('l3', 'login', true)],
    });
    expect(mine).toEqual({
      hosts: ['blog'],
      keys: ['SHA256:b'],
      environments: ['blog'],
      logins: ['l2'],
      folders: [],
      hostsFile: [],
    });
  });

  it('is empty while nothing is loaded', () => {
    expect(personal([], {})).toEqual({
      hosts: [],
      keys: [],
      environments: [],
      logins: [],
      folders: [],
      hostsFile: [],
    });
  });
});

describe('gone members', () => {
  it('are named only once their kind is loaded', () => {
    const shop = project({
      hosts: ['prod', 'renamed'],
      keys: ['SHA256:a', 'SHA256:gone'],
      environments: ['shop-api', 'emptied'],
      folders: ['~/code/shop', '~/code/elsewhere'],
    });
    const loaded = missing(
      shop,
      {
        hosts: [host(0, ['prod'])],
        keys: [key('id_a', 'SHA256:a')],
        envs: [env('shop-api', 'dev'), env('emptied', 'old', true)],
      },
      ['~/code/elsewhere', '~/code/not-in-shop'],
    );
    expect([...loaded.hosts]).toEqual(['renamed']);
    expect([...loaded.keys]).toEqual(['SHA256:gone']);
    expect([...loaded.environments]).toEqual(['emptied']);
    expect([...loaded.folders]).toEqual(['~/code/elsewhere']);

    const unknown = missing(shop, {});
    expect(unknown.hosts.size + unknown.keys.size + unknown.environments.size).toBe(0);
    expect(unknown.hostsFile.size).toBe(0);
    // Hosts of included files aren't listed: none is called gone then.
    const included = missing(shop, { hosts: [host(0, ['prod'])], includes: true });
    expect(included.hosts.size).toBe(0);
  });

  it('count every name of a host block', () => {
    const aliases = hostAliases([
      host(0, ['prod', 'prod.example.com', '!skip']),
      host(1, ['*'], true),
    ]);
    expect([...aliases]).toEqual(['prod', 'prod.example.com']);
  });
});

describe('cards', () => {
  it('put rows with a problem first, then new ones, and keep the order otherwise', () => {
    const rows = [
      { key: 'a' },
      { key: 'b', problem: true },
      { key: 'c' },
      { key: 'd', problem: true },
      { key: 'e', fresh: true },
    ];
    expect(problemsFirst(rows).map((row) => row.key)).toEqual(['b', 'd', 'e', 'a', 'c']);
  });

  it('go to the shorter column, measured folded', () => {
    // Hosts (23 rows, folded to 5), folders, environments, logins, keys.
    expect(cardColumns([23, 2, 3, 1, 2])).toEqual([
      [0, 3],
      [1, 2, 4],
    ]);
    expect(cardColumns([1])).toEqual([[0], []]);
    expect(cardColumns([])).toEqual([[], []]);
    // A long card counts as five rows: the next two still fit beside it.
    expect(cardColumns([40, 2, 2])).toEqual([[0], [1, 2]]);
  });
});

describe('hosts file names', () => {
  const line = (n: number, address: string, names: string[], enabled = true) =>
    ({ line: n, address, names, enabled }) as HostsFileEntry;
  const file = [
    line(1, '10.0.8.20', ['Staging-API.internal']),
    line(2, '10.0.8.21', ['staging-api.internal.'], false),
    line(3, '127.0.0.1', ['app.test', 'api.test']),
  ];

  it('find every line for a name, turned on or off', () => {
    expect(hostsFileEntries(file, ['staging-api.internal']).map((e) => e.line)).toEqual([1, 2]);
    expect(hostsFileEntries(file, ['api.test']).map((e) => e.line)).toEqual([3]);
    expect(hostsFileEntries(file, [])).toEqual([]);
  });

  it('are gone when no line lists them, once the file is read', () => {
    const shop = project({ hostsFile: ['staging-api.internal', 'old.internal'] });
    expect([...missing(shop, { hostsFile: file }).hostsFile]).toEqual(['old.internal']);
    expect(missing(shop, {}).hostsFile.size).toBe(0);
  });
});

describe('switching all of a project’s hosts file entries', () => {
  const line = (n: number, names: string[], enabled: boolean, system = false) =>
    ({ line: n, address: `10.0.0.${n}`, names, enabled, system }) as HostsFileEntry;
  const file = [
    line(1, ['localhost', 'app.test'], true, true),
    line(2, ['app.test'], false),
    line(3, ['api.test', 'docs.test'], true),
    line(4, ['api.test'], false),
    line(5, ['other.test'], false),
  ];
  const shop = project({
    id: 'p1',
    name: 'Shop',
    hostsFile: ['app.test', 'api.test', 'gone.test'],
  });
  const blog = project({ id: 'p2', name: 'Blog', hostsFile: ['docs.test', 'api.test'] });

  it('changes only entries in the other state, never the system’s or new ones', () => {
    const on = planHostsFileSwitch(shop, [shop, blog], file, true);
    expect(on.entries.map((e) => e.line)).toEqual([2, 3, 4]);
    expect(on.lines.map((e) => e.line)).toEqual([2, 4]);
    const off = planHostsFileSwitch(shop, [shop, blog], file, false);
    expect(off.lines.map((e) => e.line)).toEqual([3]);
  });

  it('names other projects’ names on a changing line', () => {
    const off = planHostsFileSwitch(shop, [shop, blog], file, false);
    expect(off.shared).toEqual([
      { name: 'api.test', projects: ['Blog'] },
      { name: 'docs.test', projects: ['Blog'] },
    ]);
    expect(planHostsFileSwitch(shop, [shop], file, false).shared).toEqual([]);
  });

  it('warns when a name ends up with several entries on', () => {
    // app.test: the system line and line 2; api.test: lines 3 and 4.
    expect(planHostsFileSwitch(shop, [shop], file, true).several).toEqual(['app.test', 'api.test']);
    expect(planHostsFileSwitch(shop, [shop], file, false).several).toEqual([]);
  });
});

describe('a host made from a project', () => {
  it('joins by its first pattern that is a name', () => {
    expect(aliasOf(['*.internal', '!bad', 'app', 'api'])).toBe('app');
    expect(aliasOf(['web?', '*'])).toBeUndefined();
  });
});
