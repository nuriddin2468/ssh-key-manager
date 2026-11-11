import { describe, expect, it } from 'vitest';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { Finding } from '@/bindings/Finding';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { KeyView } from '@/bindings/KeyView';
import type { Project } from '@/bindings/Project';
import type { Severity } from '@/bindings/Severity';
import type { VaultFinding } from '@/bindings/VaultFinding';
import {
  aliasOf,
  cardColumns,
  hostAliases,
  hostsFileEntries,
  initials,
  memberSummary,
  missing,
  nextColor,
  personal,
  planHostsFileSwitch,
  problemsFirst,
  projectFindings,
  projectProblems,
  projectTone,
  quickActions,
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

describe('switching a project’s hosts file entries', () => {
  const line = (n: number, names: string[], enabled: boolean, address = `10.0.0.${n}`) =>
    // `system` as the core sets it: only when every name is the system's.
    ({
      line: n,
      address,
      names,
      enabled,
      system: names.every((name) => name.startsWith('localhost')),
    }) as HostsFileEntry;
  const file = [
    line(1, ['localhost'], true, '127.0.0.1'),
    line(2, ['localhost', 'app.test'], true, '127.0.0.1'),
    line(3, ['app.test'], false),
    line(4, ['api.test', 'docs.test', 'unrelated.test'], true),
    line(5, ['api.test'], false),
    line(6, ['api.test'], false, 'fd00::6'),
    line(7, ['other.test'], false),
  ];
  const shop = project({
    id: 'p1',
    name: 'Shop',
    hostsFile: ['app.test', 'api.test', 'gone.test'],
  });
  const blog = project({ id: 'p2', name: 'Blog', hostsFile: ['docs.test', 'api.test'] });

  it('changes only entries in the other state, never a line with a system name', () => {
    const on = planHostsFileSwitch(shop, [shop, blog], file, true);
    expect(on.entries.map((e) => e.line)).toEqual([3, 4, 5, 6]);
    expect(on.kept.map((e) => e.line)).toEqual([2]);
    expect(on.lines.map((e) => e.line)).toEqual([3, 5, 6]);
    const off = planHostsFileSwitch(shop, [shop, blog], file, false);
    expect(off.lines.map((e) => e.line)).toEqual([4]);
  });

  it('changes one entry for its own switch', () => {
    expect(planHostsFileSwitch(shop, [shop], file, true, 5).lines.map((e) => e.line)).toEqual([5]);
    // A line with a system name has no switch: nothing changes on it.
    expect(planHostsFileSwitch(shop, [shop], file, false, 2).lines).toEqual([]);
  });

  it('names every other name on a changing line, with the projects that hold it', () => {
    const off = planHostsFileSwitch(shop, [shop, blog], file, false);
    expect(off.others).toEqual([
      { name: 'docs.test', projects: ['Blog'] },
      { name: 'unrelated.test', projects: [] },
    ]);
    expect(planHostsFileSwitch(shop, [shop], file, false).shared).toEqual([]);
    expect(planHostsFileSwitch(shop, [shop, blog], file, false, 4).others).toHaveLength(2);
  });

  it('names its own names that other projects hold too', () => {
    // api.test is Shop's and Blog's: turning off line 4 turns it off for Blog.
    const off = planHostsFileSwitch(shop, [shop, blog], file, false);
    expect(off.shared).toEqual([{ name: 'api.test', projects: ['Blog'] }]);
    expect(planHostsFileSwitch(shop, [shop, blog], file, false, 4).shared).toEqual([
      { name: 'api.test', projects: ['Blog'] },
    ]);
    // Turning on lines 3, 5 and 6: app.test is Shop's alone; api.test is Blog's too.
    expect(planHostsFileSwitch(shop, [shop, blog], file, true).shared).toEqual([
      { name: 'api.test', projects: ['Blog'] },
    ]);
  });

  it('warns when a name ends up with several entries on in one address family', () => {
    // app.test: line 2 stays on and line 3 turns on. api.test: lines 4 and 5
    // in IPv4; line 6 is IPv6, a family of its own.
    expect(planHostsFileSwitch(shop, [shop], file, true).several).toEqual(['app.test', 'api.test']);
    expect(planHostsFileSwitch(shop, [shop], file, true, 6).several).toEqual([]);
    expect(planHostsFileSwitch(shop, [shop], file, false).several).toEqual([]);
  });
});

describe('a project’s card on All projects', () => {
  const finding = (id: string, severity: Severity, subject: Partial<Finding['subject']>) =>
    ({
      id,
      severity,
      kind: { kind: 'x' },
      subject: { keyId: null, hostId: null, path: null, ...subject },
      fix: null,
    }) as unknown as Finding;
  const vaultFinding = (id: string, severity: Severity, entryId: string) =>
    ({
      id,
      severity,
      kind: { kind: 'weakPassword' },
      entryId,
      keyId: null,
      hostId: null,
    }) as VaultFinding;
  const shop = project({
    hosts: ['prod', 'old'],
    keys: ['SHA256:a'],
    logins: ['l1'],
    folders: ['~/a', '~/b'],
  });
  const library = {
    hosts: [host(1, ['prod']), host(2, ['nas'])],
    keys: [key('id_shop', 'SHA256:a'), key('id_home', 'SHA256:b')],
    entries: [entry('l1'), entry('l2')],
  };
  const found = {
    ssh: [
      finding('warn-prod', 'warning', { hostId: 1 }),
      finding('nas', 'critical', { hostId: 2 }),
      finding('crit-key', 'critical', { keyId: 'id_shop' }),
      finding('info-prod', 'info', { hostId: 1 }),
      finding('ignored', 'critical', { hostId: 1 }),
    ],
    vault: [
      vaultFinding('weak', 'warning', 'l1'),
      vaultFinding('reused', 'critical', 'l1'),
      vaultFinding('other', 'critical', 'l2'),
    ],
  };

  it('shows findings about its hosts, keys and logins, not those set aside', () => {
    const mine = projectFindings(shop, library, found, new Set(['ignored', 'vault:reused']));
    expect(mine.ssh.map((f) => f.id)).toEqual(['crit-key', 'warn-prod', 'info-prod']);
    expect(mine.vault.map((f) => f.id)).toEqual(['weak']);
  });

  it('lists problems worst first: findings, then members missing here, no suggestions', () => {
    const mine = projectFindings(shop, library, found, new Set(['ignored']));
    const gone = missing(shop, library, ['~/a']);
    expect(projectProblems(mine, gone).map((p) => p.key)).toEqual([
      'crit-key',
      'vault:reused',
      'warn-prod',
      'vault:weak',
      'host:old',
      'folder:~/a',
    ]);
  });

  it('counts its .env files that need the user as one problem, critical when Git tracks one', () => {
    const mine = projectFindings(shop, library, found, new Set(['ignored']));
    const gone = missing(shop, library, ['~/a']);
    const file = (path: string, git: EnvFileReport['git']): EnvFileReport => ({
      projects: ['p1'],
      cloud: null,
      example: null,
      git,
      envId: 'env-1',
      group: 'shop-api',
      envName: 'dev',
      file: { folder: '~/code/shop', path },
      location: null,
      state: { type: 'conflict' },
    });
    const untracked = file('.env', { state: 'untracked', repository: '/code/shop' });
    const problems = projectProblems(mine, gone, [untracked, file('.env.local', null)]);
    const files = problems.find((p) => p.source === 'files');
    expect(files?.severity).toBe('warning');
    expect(files?.source === 'files' && files.files).toHaveLength(2);
    // After the critical findings and with the warnings, before members missing here.
    expect(problems.map((p) => p.key).indexOf('env-files')).toBe(4);
    const tracked = file('.env', { state: 'tracked', repository: '/code/shop' });
    expect(
      projectProblems(mine, gone, [tracked]).find((p) => p.key === 'env-files')?.severity,
    ).toBe('critical');
    expect(projectProblems(mine, gone, []).some((p) => p.key === 'env-files')).toBe(false);
  });

  it('offers its first folder on this computer and its first host in ~/.ssh/config with a shell', () => {
    const gone = missing(shop, library, ['~/a']);
    expect(quickActions(shop, gone, ['~/a'], library.hosts)).toEqual({
      folder: '~/b',
      host: 'prod',
    });
    // Until the folders are checked, or the hosts read, none is offered.
    expect(quickActions(shop, gone, undefined, library.hosts)).toEqual({
      folder: undefined,
      host: 'prod',
    });
    expect(quickActions(shop, missing(shop, {}), ['~/a'], undefined)).toEqual({
      folder: '~/b',
      host: undefined,
    });
    // GitHub and the like give no shell.
    const code = project({ hosts: ['github.com', 'gl', 'prod'] });
    const hosts = [
      host(3, ['github.com']),
      { ...host(4, ['gl']), hostName: 'gitlab.com' },
      host(1, ['prod']),
    ];
    expect(quickActions(code, missing(code, { hosts }), [], hosts).host).toBe('prod');
    const empty = project({ hosts: ['old'] });
    expect(quickActions(empty, missing(empty, library), [], library.hosts)).toEqual({
      folder: undefined,
      host: undefined,
    });
  });
});

describe('a host made from a project', () => {
  it('joins by its first pattern that is a name', () => {
    expect(aliasOf(['*.internal', '!bad', 'app', 'api'])).toBe('app');
    expect(aliasOf(['web?', '*'])).toBeUndefined();
  });
});

describe('a project’s counts', () => {
  const t = ((key: string, options?: { count: number }) =>
    `${options?.count} ${key.split('.').pop()}`) as unknown as import('i18next').TFunction;
  const shop = project({ hosts: ['a', 'b'], environments: ['shop'], logins: ['l1'], keys: ['k'] });

  it('name only the kinds it has', () => {
    expect(memberSummary(t, shop, false)).toBe('2 hosts · 1 environments · 1 logins · 1 keys');
  });

  it('leave out environments and logins while the vault is locked', () => {
    expect(memberSummary(t, shop, true)).toBe('2 hosts · 1 keys');
  });
});
