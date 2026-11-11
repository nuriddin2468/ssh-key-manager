// What the project pages show: which items are in no project (Personal),
// which members are gone, and the look of a project's tile.

import type { EntrySummary } from '@/bindings/EntrySummary';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { KeyView } from '@/bindings/KeyView';
import type { Project } from '@/bindings/Project';
import type { ProjectColor } from '@/bindings/ProjectColor';
import type { ProjectMember } from '@/bindings/ProjectMember';
import type { Tone } from '@/components/ui/Tile';
import { listsSystemName, normalizeName } from '@/features/hostsFile/model';

/** In the order the color picker shows them. */
export const PROJECT_COLORS: ProjectColor[] = [
  'teal',
  'blue',
  'indigo',
  'violet',
  'pink',
  'red',
  'orange',
  'amber',
  'green',
  'slate',
];

/** The tile tone of a project's color. */
export function projectTone(color: ProjectColor): Tone {
  return color === 'red' ? 'rose' : color;
}

/** Up to two letters for a project's tile: of its first two words, else its first two letters. */
export function initials(name: string): string {
  const words = name
    .trim()
    .split(/[\s\-_.]+/u)
    .filter(Boolean);
  const [first = '', second] = words;
  const letters =
    second !== undefined
      ? [...first].slice(0, 1).concat([...second].slice(0, 1))
      : [...first].slice(0, 2);
  return letters.join('').toUpperCase();
}

/** The color a new project gets: the first that no project has, else the one fewest have. */
export function nextColor(projects: Project[]): ProjectColor {
  const counts = PROJECT_COLORS.map((c) => projects.filter((p) => p.color === c).length);
  return PROJECT_COLORS[counts.indexOf(Math.min(...counts))] ?? 'teal';
}

/** The names a `Host` block answers to, as projects hold them: its patterns that aren't wildcards. */
export function hostAliases(hosts: HostEntry[]): Set<string> {
  const aliases = new Set<string>();
  for (const host of hosts) {
    if (host.kind !== 'host' || host.isWildcard) continue;
    for (const pattern of host.patterns) if (!pattern.startsWith('!')) aliases.add(pattern);
  }
  return aliases;
}

/**
 * The name a project holds a new host by: its first pattern that is a name,
 * not a wildcard (`*.internal`) or a negation. `undefined` for none.
 */
export function aliasOf(patterns: readonly string[]): string | undefined {
  return patterns.find((pattern) => !/[*?!]/.test(pattern));
}

/** What the library holds, as far as it is loaded: `undefined` while a part isn't. */
export interface Library {
  hosts?: HostEntry[];
  /**
   * `~/.ssh/config` has `Include`s, whose hosts aren't in `hosts`: no host
   * can then be called gone.
   */
  includes?: boolean;
  keys?: KeyView[];
  /** Only while the vault is unlocked. */
  envs?: EnvSummary[];
  /** Only while the vault is unlocked. */
  entries?: EntrySummary[];
  /** The system hosts file's entries, turned on and off. */
  hostsFile?: HostsFileEntry[];
}

/** Members by kind, as a project holds them. */
export interface Members {
  hosts: string[];
  keys: string[];
  environments: string[];
  logins: string[];
  folders: string[];
  /** Names in the system hosts file. */
  hostsFile: string[];
}

/**
 * Personal: what no project holds. A host block is in a project when any of
 * its names is; logins are the vault's own (not a host's or a key's saved
 * password), outside the recycle bin. The hosts file is the whole
 * computer's, block lists and all: its entries show in projects only.
 */
export function personal(projects: Project[], library: Library): Members {
  const held = (pick: (p: Project) => string[]) => new Set(projects.flatMap(pick));
  const hosts = held((p) => p.hosts);
  const keys = held((p) => p.keys);
  const groups = held((p) => p.environments);
  const logins = held((p) => p.logins);
  return {
    hosts: (library.hosts ?? [])
      .filter((h) => h.kind === 'host' && !h.isWildcard)
      .filter((h) => !h.patterns.some((pattern) => hosts.has(pattern)))
      .flatMap((h) => h.patterns.filter((p) => !p.startsWith('!')).slice(0, 1)),
    keys: (library.keys ?? []).flatMap((k) =>
      k.fingerprint && !keys.has(k.fingerprint) ? [k.fingerprint] : [],
    ),
    environments: [
      ...new Set(
        (library.envs ?? [])
          .filter((e) => !e.inTrash && e.project && !groups.has(e.project))
          .map((e) => e.project),
      ),
    ],
    logins: (library.entries ?? [])
      .filter((e) => !e.inTrash && e.kind === 'login' && !logins.has(e.id))
      .map((e) => e.id),
    folders: [],
    hostsFile: [],
  };
}

/**
 * A project's members that are gone, by what is loaded: nothing is called
 * gone before it is. `goneFolders` come from `projectsMissingFolders`.
 */
export interface Missing {
  hosts: Set<string>;
  keys: Set<string>;
  environments: Set<string>;
  folders: Set<string>;
  /** Names no line of the hosts file lists, turned on or off. */
  hostsFile: Set<string>;
}

export function missing(project: Project, library: Library, goneFolders: string[] = []): Missing {
  const aliases = library.hosts && !library.includes ? hostAliases(library.hosts) : undefined;
  const fingerprints = library.keys ? new Set(library.keys.map((k) => k.fingerprint)) : undefined;
  const groups = library.envs
    ? new Set(library.envs.filter((e) => !e.inTrash).map((e) => e.project))
    : undefined;
  const listed = library.hostsFile
    ? new Set(library.hostsFile.flatMap((entry) => entry.names.map(normalizeName)))
    : undefined;
  return {
    hosts: new Set(aliases ? project.hosts.filter((h) => !aliases.has(h)) : []),
    keys: new Set(fingerprints ? project.keys.filter((k) => !fingerprints.has(k)) : []),
    environments: new Set(groups ? project.environments.filter((g) => !groups.has(g)) : []),
    folders: new Set(goneFolders.filter((folder) => project.folders.includes(folder))),
    hostsFile: new Set(listed ? project.hostsFile.filter((name) => !listed.has(name)) : []),
  };
}

/** The hosts file's entries that list one of `names`, in file order. */
export function hostsFileEntries(
  entries: readonly HostsFileEntry[],
  names: readonly string[],
): HostsFileEntry[] {
  const wanted = new Set(names);
  return entries.filter((entry) => entry.names.some((name) => wanted.has(normalizeName(name))));
}

/** Whether `project` holds `member`. */
export function holds(project: Project, member: ProjectMember): boolean {
  switch (member.type) {
    case 'host':
      return project.hosts.includes(member.alias);
    case 'key':
      return project.keys.includes(member.fingerprint);
    case 'login':
      return project.logins.includes(member.id);
    case 'environment':
      return project.environments.includes(member.group);
    case 'folder':
      return project.folders.includes(member.path);
    case 'hostsFile':
      return project.hostsFile.includes(member.name);
  }
}

/** How many members a project shows, by kind. */
export function memberCounts(members: Members) {
  return {
    hosts: members.hosts.length,
    folders: members.folders.length,
    environments: members.environments.length,
    logins: members.logins.length,
    keys: members.keys.length,
    hostsFile: members.hostsFile.length,
  };
}

/** How many rows a card shows before "Show all". */
export const CARD_LIMIT = 5;

/**
 * Rows with a problem first, then the ones just made on the page (so a new
 * host shows even when the card is folded), the rest in their order.
 */
export function problemsFirst<T extends { problem?: boolean; fresh?: boolean }>(rows: T[]): T[] {
  return [
    ...rows.filter((row) => row.problem),
    ...rows.filter((row) => !row.problem && row.fresh),
    ...rows.filter((row) => !row.problem && !row.fresh),
  ];
}

/**
 * Splits cards of `rows` rows each into two columns of about the same
 * height, in order: each card goes to the shorter column. Heights are those
 * of the cards folded to `CARD_LIMIT` rows, so showing all of one card makes
 * its column longer and moves no card to the other.
 */
export function cardColumns(rows: number[]): [number[], number[]] {
  const columns: [number[], number[]] = [[], []];
  const heights: [number, number] = [0, 0];
  rows.forEach((count, index) => {
    const side: 0 | 1 = heights[1] < heights[0] ? 1 : 0;
    columns[side].push(index);
    // A card's header, its rows (44 px each) and its "Show all" button.
    heights[side] += 52 + 45 * Math.min(count, CARD_LIMIT) + (count > CARD_LIMIT ? 36 : 0);
  });
  return columns;
}

/** A member as one string, e.g. `host:prod`, for sets and React keys. */
export function memberKey(member: ProjectMember): string {
  switch (member.type) {
    case 'host':
      return `host:${member.alias}`;
    case 'key':
      return `key:${member.fingerprint}`;
    case 'login':
      return `login:${member.id}`;
    case 'environment':
      return `env:${member.group}`;
    case 'folder':
      return `folder:${member.path}`;
    case 'hostsFile':
      return `hostsfile:${member.name}`;
  }
}

/** What switching a project's hosts file entries on or off does. */
export interface HostsFilePlan {
  /** The project's entries a switch acts on: not those listing a system name. */
  entries: HostsFileEntry[];
  /** The project's entries left as they are: they list a system name too. */
  kept: HostsFileEntry[];
  /** Those not already in the state asked for: the ones that change. */
  lines: HostsFileEntry[];
  /**
   * Names the project doesn't hold on a changing line, which change with it,
   * with the other projects that hold them.
   */
  others: { name: string; projects: string[] }[];
  /** Names that will have more than one entry on in an address family: the first wins. */
  several: string[];
}

/**
 * Plans turning `project`'s hosts file entries `on` (or off): all of them,
 * or the one on `line`. Only entries in the other state change; lines that
 * list a system name stay as they are; names the file doesn't have add
 * nothing; what else the change touches is named for the review.
 */
export function planHostsFileSwitch(
  project: Project,
  projects: Project[],
  file: readonly HostsFileEntry[],
  on: boolean,
  line?: number,
): HostsFilePlan {
  const mine = hostsFileEntries(file, project.hostsFile).filter((entry) => !entry.system);
  const entries = mine.filter((entry) => !listsSystemName(entry));
  const kept = mine.filter(listsSystemName);
  const lines = entries.filter(
    (entry) => entry.enabled !== on && (line === undefined || entry.line === line),
  );
  const held = new Set(project.hostsFile);
  const others = new Map<string, string[]>();
  for (const changing of lines) {
    for (const name of changing.names.map(normalizeName)) {
      if (held.has(name) || others.has(name)) continue;
      others.set(
        name,
        projects
          .filter((other) => other.id !== project.id && other.hostsFile.includes(name))
          .map((other) => other.name),
      );
    }
  }
  // Resolvers use the first entry on for a name in each family, IPv4 and IPv6.
  const changingNames = new Set(lines.flatMap((entry) => entry.names.map(normalizeName)));
  const onAfter = file.filter((entry) => (lines.includes(entry) ? on : entry.enabled));
  const several = project.hostsFile.filter(
    (name) =>
      on &&
      changingNames.has(name) &&
      [false, true].some(
        (ipv6) =>
          onAfter.filter(
            (entry) =>
              entry.address.includes(':') === ipv6 &&
              entry.names.some((n) => normalizeName(n) === name),
          ).length > 1,
      ),
  );
  return {
    entries,
    kept,
    lines,
    others: [...others].map(([name, holders]) => ({ name, projects: holders })),
    several,
  };
}
