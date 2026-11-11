// Projects for `pnpm dev` (see backend.ts): a few that tie the sample hosts,
// keys, environments, logins and folders together, as the real backend keeps
// them in the vault. While the mock vault is locked the list shows without
// logins and changes fail, as with the copy the backend keeps for then.
// Suggestions: a few Git folders, one of them for the existing Shop, and
// what a folder picked to look into finds.

import type { Project } from '@/bindings/Project';
import type { ProjectColor } from '@/bindings/ProjectColor';
import type { ProjectInput } from '@/bindings/ProjectInput';
import type { ProjectMember } from '@/bindings/ProjectMember';
import type { ProjectSuggestion } from '@/bindings/ProjectSuggestion';
import { isMockEntry, isMockVaultUnlocked, mockEntryId } from './vault';

type Handler = (args: Record<string, unknown>) => unknown;

const fail = (code: string, message: string) => Promise.reject({ code, message });
const now = () => `${new Date().toISOString().slice(0, 19)}Z`;
const NAME_CHARS = /[\p{Cc};,:]/u;

/** Logins by entry title, resolved once the mock vault has its ids. */
interface MockProject extends Omit<Project, 'logins'> {
  loginTitles: string[];
  logins: string[];
}

function project(
  id: string,
  name: string,
  color: ProjectColor,
  members: Partial<Pick<MockProject, 'folders' | 'hosts' | 'keys' | 'environments'>>,
  loginTitles: string[],
): MockProject {
  return {
    id,
    name,
    color,
    folders: [],
    hosts: [],
    keys: [],
    environments: [],
    ...members,
    loginTitles,
    logins: [],
    modified: '2026-11-02T09:30:00Z',
  };
}

const projects: MockProject[] = [
  project(
    '0b6e1c52-6a3f-4c1e-9d55-1f2a3b4c5d01',
    'Shop',
    'blue',
    {
      folders: ['~/code/shop-api', '~/code/shop-web'],
      hosts: ['bastion', 'prod-api', 'staging-api'],
      keys: ['SHA256:Qm7Tz2LkP9wX4cVb1NrY8sHd3FgJ6aE0uKoBiWq5ZxR'],
      environments: ['shop-api'],
    },
    ['AWS console', 'prod-api'],
  ),
  project(
    '0b6e1c52-6a3f-4c1e-9d55-1f2a3b4c5d02',
    'Marketing site',
    'violet',
    {
      folders: ['~/code/marketing-site'],
      hosts: ['github.com'],
      keys: ['SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw'],
      environments: ['marketing-site'],
    },
    ['GitHub'],
  ),
  project(
    '0b6e1c52-6a3f-4c1e-9d55-1f2a3b4c5d03',
    'Home lab',
    'amber',
    { hosts: ['legacy-nas', 'old-vpn'] },
    ['Router admin', 'legacy-nas'],
  ),
];

/** Resolves the sample logins' ids the first time the list is read. */
function resolveLogins() {
  for (const p of projects) {
    if (p.loginTitles.length === 0) continue;
    const ids = p.loginTitles.map(mockEntryId).filter((id): id is string => Boolean(id));
    if (ids.length > 0) {
      p.logins = [...new Set([...p.logins, ...ids])];
      p.loginTitles = [];
    }
  }
}

function view(p: MockProject, unlocked: boolean): Project {
  const { loginTitles: _, ...rest } = p;
  return { ...rest, logins: unlocked ? [...p.logins] : [] };
}

function checkName(text: unknown): string | Promise<never> {
  const name = String(text ?? '').trim();
  if (!name) return fail('invalid_input', 'a project needs a name');
  if ([...name].length > 64) {
    return fail('invalid_input', 'project names are at most 64 characters');
  }
  if (NAME_CHARS.test(name)) {
    return fail('invalid_input', "project names can't have `;`, `,`, `:` or control characters");
  }
  return name;
}

function taken(name: string, except?: string) {
  return projects.some((p) => p.id !== except && p.name.toLowerCase() === name.toLowerCase());
}

/** The unlocked vault's project `id`, or the failure a locked vault or a gone one gives. */
function editable(id: unknown): MockProject | Promise<never> {
  if (!isMockVaultUnlocked()) return fail('vault_locked', 'the vault is locked');
  resolveLogins();
  return projects.find((p) => p.id === id) ?? fail('not_found', `project ${id}`);
}

function setMember(
  p: MockProject,
  member: ProjectMember,
  included: boolean,
): Promise<never> | undefined {
  const toggle = (list: string[], value: string) => {
    const at = list.indexOf(value);
    if (included && at < 0) list.push(value);
    if (!included && at >= 0) list.splice(at, 1);
  };
  switch (member.type) {
    case 'host':
      if (!member.alias.trim() || /[\s*?]/.test(member.alias)) {
        return fail('invalid_input', `not a host alias: ${member.alias}`);
      }
      toggle(p.hosts, member.alias.trim());
      break;
    case 'key':
      if (!/^SHA256:[A-Za-z0-9+/=]{1,64}$/.test(member.fingerprint.trim())) {
        return fail('invalid_input', 'not a SHA256 key fingerprint');
      }
      toggle(p.keys, member.fingerprint.trim());
      break;
    case 'environment':
      if (!member.group.trim() || member.group.includes('/')) {
        return fail('invalid_input', `not a project: ${member.group}`);
      }
      toggle(p.environments, member.group.trim());
      break;
    case 'folder':
      toggle(p.folders, member.path);
      break;
    case 'login':
      if (!isMockEntry(member.id)) return fail('not_found', `entry ${member.id}`);
      toggle(p.logins, member.id);
      break;
  }
  p.modified = now();
  return undefined;
}

let nextFolder = 1;

const suggestion = (
  key: string,
  name: string,
  reasons: ProjectSuggestion['reasons'],
  members: Partial<Pick<ProjectSuggestion, 'folders' | 'hosts' | 'keys' | 'environments'>>,
): ProjectSuggestion => ({
  key,
  name,
  color: 'teal',
  existing: null,
  reasons,
  folders: [],
  hosts: [],
  keys: [],
  environments: [],
  logins: [],
  ...members,
});

const candidates: ProjectSuggestion[] = [
  suggestion(
    'billing-service',
    'billing-service',
    [{ type: 'gitFolder', folder: '~/code/billing-service' }],
    {
      folders: ['~/code/billing-service'],
      keys: ['SHA256:u9Fh2KdL7pQ3zX8mV1bN6rT4wY0sGcJ5aE2iOkHjUyB'],
      environments: ['billing'],
    },
  ),
  suggestion('shop', 'shop', [{ type: 'gitFolder', folder: '~/code/shop-admin' }], {
    folders: ['~/code/shop-admin'],
  }),
  suggestion('dotfiles', 'dotfiles', [{ type: 'gitFolder', folder: '~/dotfiles' }], {
    folders: ['~/dotfiles'],
  }),
];
/** Found once the user picks a folder to look into. */
const inPickedFolder = suggestion(
  'client-portal',
  'client-portal',
  [{ type: 'gitFolder', folder: '~/work/client-portal' }],
  { folders: ['~/work/client-portal'] },
);
const dismissed = new Set<string>();
/** Members left out when a suggestion was accepted, by its key: not offered again. */
const leftOut = new Map<string, Set<string>>();

/** A member as one string, as the backend's records key them. */
function memberKey(m: ProjectMember): string {
  switch (m.type) {
    case 'host':
      return `host:${m.alias}`;
    case 'key':
      return `key:${m.fingerprint}`;
    case 'login':
      return `login:${m.id}`;
    case 'environment':
      return `env:${m.group}`;
    case 'folder':
      return `folder:${m.path}`;
  }
}

function memberList(s: ProjectSuggestion): ProjectMember[] {
  return [
    ...s.hosts.map((alias): ProjectMember => ({ type: 'host', alias })),
    ...s.keys.map((fingerprint): ProjectMember => ({ type: 'key', fingerprint })),
    ...s.environments.map((group): ProjectMember => ({ type: 'environment', group })),
    ...s.folders.map((path): ProjectMember => ({ type: 'folder', path })),
    ...s.logins.map((id): ProjectMember => ({ type: 'login', id })),
  ];
}
let offered: ProjectSuggestion[] = [];

const COLORS: ProjectColor[] = [
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

function nextColor(taken: ProjectColor[]): ProjectColor {
  const counts = COLORS.map((c) => taken.filter((t) => t === c).length);
  return COLORS[counts.indexOf(Math.min(...counts))] ?? 'teal';
}

/** What the backend's `suggest` gives for the candidates: taken members and dismissals left out. */
function suggestions(): ProjectSuggestion[] {
  const held = new Set(
    projects
      .flatMap((p) =>
        memberList({ ...p, key: '', existing: null, reasons: [], name: p.name, color: p.color }),
      )
      .map(memberKey),
  );
  const colors = projects.map((p) => p.color);
  offered = candidates
    .filter((c) => !dismissed.has(c.key))
    .map((c) => {
      const existing = projects.find((p) => p.name.toLowerCase() === c.key);
      const declined = leftOut.get(c.key) ?? new Set<string>();
      const keep = (m: ProjectMember) => !held.has(memberKey(m)) && !declined.has(memberKey(m));
      const kept = memberList(c).filter(keep);
      const s: ProjectSuggestion = {
        ...c,
        hosts: kept.flatMap((m) => (m.type === 'host' ? [m.alias] : [])),
        keys: kept.flatMap((m) => (m.type === 'key' ? [m.fingerprint] : [])),
        environments: kept.flatMap((m) => (m.type === 'environment' ? [m.group] : [])),
        folders: kept.flatMap((m) => (m.type === 'folder' ? [m.path] : [])),
        logins: kept.flatMap((m) => (m.type === 'login' ? [m.id] : [])),
      };
      if (existing) {
        s.existing = existing.id;
        s.name = existing.name;
        s.color = existing.color;
      } else {
        s.color = nextColor(colors);
        colors.push(s.color);
      }
      return s;
    })
    .filter((s) => memberList(s).length > 0);
  return offered;
}

export const projectsHandlers: Record<string, Handler> = {
  projects_list: () => {
    const unlocked = isMockVaultUnlocked();
    if (unlocked) resolveLogins();
    return projects
      .map((p) => view(p, unlocked))
      .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
  },
  projects_create: ({ input }) => {
    if (!isMockVaultUnlocked()) return fail('vault_locked', 'the vault is locked');
    const { name: text, color } = input as ProjectInput;
    const name = checkName(text);
    if (typeof name !== 'string') return name;
    if (taken(name)) return fail('already_exists', name);
    const created = project(crypto.randomUUID(), name, color, {}, []);
    created.modified = now();
    projects.push(created);
    return view(created, true);
  },
  projects_update: ({ id, input }) => {
    const p = editable(id);
    if (p instanceof Promise) return p;
    const { name: text, color } = input as ProjectInput;
    const name = checkName(text);
    if (typeof name !== 'string') return name;
    if (taken(name, p.id)) return fail('already_exists', name);
    p.name = name;
    p.color = color;
    p.modified = now();
    return view(p, true);
  },
  projects_delete: ({ id }) => {
    const p = editable(id);
    if (p instanceof Promise) return p;
    projects.splice(projects.indexOf(p), 1);
  },
  projects_set_member: ({ id, member, included }) => {
    const m = member as ProjectMember;
    if (included && m.type === 'folder') {
      return fail('invalid_input', 'choose the folder in the folder dialog');
    }
    const p = editable(id);
    if (p instanceof Promise) return p;
    return setMember(p, m, Boolean(included)) ?? view(p, true);
  },
  projects_suggestions: () => {
    if (!isMockVaultUnlocked()) return fail('vault_locked', 'the vault is locked');
    resolveLogins();
    return suggestions();
  },
  projects_accept_suggestion: ({ key, input, members }) => {
    if (!isMockVaultUnlocked()) return fail('vault_locked', 'the vault is locked');
    const s = offered.find((o) => o.key === key);
    if (!s) return fail('not_found', 'the suggestion; look for suggestions again');
    const chosen = members as ProjectMember[];
    const offeredKeys = new Set(memberList(s).map(memberKey));
    // Every member is checked before anything changes, as the backend does.
    for (const m of chosen) {
      if (!offeredKeys.has(memberKey(m))) {
        return fail('invalid_input', 'not part of the suggestion');
      }
      if (m.type === 'login' && !isMockEntry(m.id)) return fail('not_found', `entry ${m.id}`);
    }
    let target = s.existing ? projects.find((p) => p.id === s.existing) : undefined;
    if (!target) {
      const { name: text, color } = input as ProjectInput;
      const name = checkName(text);
      if (typeof name !== 'string') return name;
      if (taken(name)) return fail('already_exists', name);
      target = project(crypto.randomUUID(), name, color, {}, []);
      projects.push(target);
    }
    for (const m of chosen) {
      const list =
        m.type === 'host'
          ? target.hosts
          : m.type === 'key'
            ? target.keys
            : m.type === 'environment'
              ? target.environments
              : m.type === 'folder'
                ? target.folders
                : target.logins;
      const value =
        m.type === 'host'
          ? m.alias
          : m.type === 'key'
            ? m.fingerprint
            : m.type === 'environment'
              ? m.group
              : m.type === 'folder'
                ? m.path
                : m.id;
      if (!list.includes(value)) list.push(value);
    }
    target.modified = now();
    const chosenKeys = new Set(chosen.map(memberKey));
    const declined = leftOut.get(s.key) ?? new Set<string>();
    for (const k of offeredKeys) if (!chosenKeys.has(k)) declined.add(k);
    leftOut.set(s.key, declined);
    offered = offered.filter((o) => o.key !== key);
    return view(target, true);
  },
  projects_dismiss_suggestion: ({ key }) => {
    dismissed.add(String(key));
    offered = offered.filter((o) => o.key !== key);
  },
  projects_restore_suggestions: () => {
    dismissed.clear();
    leftOut.clear();
  },
  // Stands in for the folder dialog: the picked folder holds one more project.
  projects_suggest_in_folder: () => {
    if (!isMockVaultUnlocked()) return fail('vault_locked', 'the vault is locked');
    if (!candidates.includes(inPickedFolder)) candidates.push(inPickedFolder);
    return suggestions();
  },
  // Stands in for the system folder dialog: picks a new folder under ~/code.
  projects_add_folder: ({ id }) => {
    const p = editable(id);
    if (p instanceof Promise) return p;
    p.folders.push(`~/code/new-folder-${nextFolder}`);
    nextFolder += 1;
    p.modified = now();
    return view(p, true);
  },
};
