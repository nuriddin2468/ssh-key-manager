// What the project pages show: which items are in no project (Personal),
// which members are gone, and the look of a project's tile.

import type { EntrySummary } from '@/bindings/EntrySummary';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import type { Project } from '@/bindings/Project';
import type { ProjectColor } from '@/bindings/ProjectColor';
import type { ProjectMember } from '@/bindings/ProjectMember';
import type { Tone } from '@/components/ui/Tile';

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
}

/** Members by kind, as a project holds them. */
export interface Members {
  hosts: string[];
  keys: string[];
  environments: string[];
  logins: string[];
  folders: string[];
}

/**
 * Personal: what no project holds. A host block is in a project when any of
 * its names is; logins are the vault's own (not a host's or a key's saved
 * password), outside the recycle bin.
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
}

export function missing(project: Project, library: Library, goneFolders: string[] = []): Missing {
  const aliases = library.hosts && !library.includes ? hostAliases(library.hosts) : undefined;
  const fingerprints = library.keys ? new Set(library.keys.map((k) => k.fingerprint)) : undefined;
  const groups = library.envs
    ? new Set(library.envs.filter((e) => !e.inTrash).map((e) => e.project))
    : undefined;
  return {
    hosts: new Set(aliases ? project.hosts.filter((h) => !aliases.has(h)) : []),
    keys: new Set(fingerprints ? project.keys.filter((k) => !fingerprints.has(k)) : []),
    environments: new Set(groups ? project.environments.filter((g) => !groups.has(g)) : []),
    folders: new Set(goneFolders.filter((folder) => project.folders.includes(folder))),
  };
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
  };
}
