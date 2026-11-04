// Changes to the hosts file are collected here and applied together, so the
// administrator password is asked once. Existing entries are named by their
// line in the revision the draft was started on.

import type { HostsChange } from '@/bindings/HostsChange';
import type { HostsEntryEdit } from '@/bindings/HostsEntryEdit';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { HostsFileView } from '@/bindings/HostsFileView';
import { MAX_GROUP_NAME } from './model';

export interface Draft {
  /** The file revision the draft was made against. */
  revision: string;
  /** Wanted state of existing entries, by line. */
  sets: Record<number, HostsEntryEdit>;
  removes: number[];
  adds: { id: number; entry: HostsEntryEdit }[];
  /**
   * New names of existing groups, by their name in the file. A map, as a group
   * may be called `__proto__`.
   */
  renames: ReadonlyMap<string, string>;
  /** Existing groups whose markers go (by their name in the file). */
  ungroups: string[];
  /** Groups made in the draft, shown before any entry is in them. An empty one is not written. */
  created: string[];
}

export const emptyDraft = (revision: string): Draft => ({
  revision,
  sets: {},
  removes: [],
  adds: [],
  renames: new Map(),
  ungroups: [],
  created: [],
});

let lastId = 0;

export function editOf(entry: HostsFileEntry): HostsEntryEdit {
  return {
    address: entry.address,
    names: entry.names,
    comment: entry.comment,
    enabled: entry.enabled,
    expires: entry.expires,
    group: entry.group,
  };
}

const sameEdit = (a: HostsEntryEdit, b: HostsEntryEdit) => JSON.stringify(a) === JSON.stringify(b);

export function changeCount(draft: Draft): number {
  return (
    Object.keys(draft.sets).length +
    draft.removes.length +
    draft.adds.length +
    draft.renames.size +
    draft.ungroups.length
  );
}

/** The draft as the backend's list of changes. */
export function toChanges(draft: Draft): HostsChange[] {
  return [
    ...[...draft.renames].map(([name, to]): HostsChange => ({ kind: 'renameGroup', name, to })),
    ...draft.ungroups.map((name): HostsChange => ({ kind: 'ungroup', name })),
    ...Object.entries(draft.sets).map(
      ([line, entry]): HostsChange => ({ kind: 'set', line: Number(line), entry }),
    ),
    ...draft.removes.map((line): HostsChange => ({ kind: 'remove', line })),
    ...draft.adds.map(({ entry }): HostsChange => ({ kind: 'add', entry })),
  ];
}

/** An existing entry as the draft shows it before its own change: its group renamed or gone. */
export function baseline(draft: Draft, base: HostsFileEntry): HostsEntryEdit {
  return { ...editOf(base), group: displayGroup(draft, base.group) };
}

/** Sets an existing entry; setting it back to how it is drops the change. */
export function setEntry(draft: Draft, base: HostsFileEntry, edit: HostsEntryEdit): Draft {
  const sets = { ...draft.sets };
  if (sameEdit(edit, baseline(draft, base))) delete sets[base.line];
  else sets[base.line] = edit;
  return { ...draft, sets };
}

/** Drops changes that a group rename or ungroup made the same as the baseline. */
function prune(draft: Draft, view: HostsFileView): Draft {
  const sets = { ...draft.sets };
  for (const base of view.entries) {
    const edit = sets[base.line];
    if (edit && sameEdit(edit, baseline(draft, base))) delete sets[base.line];
  }
  return { ...draft, sets };
}

export function removeEntry(draft: Draft, line: number): Draft {
  const sets = { ...draft.sets };
  delete sets[line];
  return { ...draft, sets, removes: [...new Set([...draft.removes, line])] };
}

export function restoreEntry(draft: Draft, line: number): Draft {
  return { ...draft, removes: draft.removes.filter((l) => l !== line) };
}

export function addEntry(draft: Draft, entry: HostsEntryEdit): Draft {
  lastId += 1;
  return { ...draft, adds: [...draft.adds, { id: lastId, entry }] };
}

export function updateAdded(draft: Draft, id: number, entry: HostsEntryEdit): Draft {
  return { ...draft, adds: draft.adds.map((a) => (a.id === id ? { id, entry } : a)) };
}

export function removeAdded(draft: Draft, id: number): Draft {
  return { ...draft, adds: draft.adds.filter((a) => a.id !== id) };
}

/** Puts an entry in another group (`null`: none), keeping its other changes. */
export function moveEntry(draft: Draft, row: EntryRow, group: string | null): Draft {
  if (row.base) {
    if (draft.removes.includes(row.base.line)) return draft;
    const edit = draft.sets[row.base.line] ?? baseline(draft, row.base);
    return setEntry(draft, row.base, { ...edit, group });
  }
  const add = draft.adds.find((a) => a.id === row.addId);
  return add ? updateAdded(draft, add.id, { ...add.entry, group }) : draft;
}

/** Adds an empty group that entries can be moved into. */
export function createGroup(draft: Draft, name: string): Draft {
  return draft.created.includes(name) ? draft : { ...draft, created: [...draft.created, name] };
}

/** The name a group in the file has in the draft (`null` once ungrouped). */
export function displayGroup(draft: Draft, original: string | null): string | null {
  if (original === null || draft.ungroups.includes(original)) return null;
  return draft.renames.get(original) ?? original;
}

/** The name in the file of the group shown as `shown`, if it is in the file. */
function originalGroup(draft: Draft, view: HostsFileView, shown: string): string | null {
  return (
    [...draft.renames].find(([, to]) => to === shown)?.[0] ??
    (view.groups.some((g) => g.name === shown) ? shown : null)
  );
}

/** Renames a group shown as `from`: an existing one, or one only new entries use. */
export function renameGroup(draft: Draft, view: HostsFileView, from: string, to: string): Draft {
  const original = originalGroup(draft, view, from);
  const renames = new Map(draft.renames);
  if (original !== null) {
    if (original === to) renames.delete(original);
    else renames.set(original, to);
  }
  const regroup = (edit: HostsEntryEdit) => (edit.group === from ? { ...edit, group: to } : edit);
  const sets: Record<number, HostsEntryEdit> = {};
  for (const [line, edit] of Object.entries(draft.sets)) sets[Number(line)] = regroup(edit);
  return prune(
    {
      ...draft,
      renames,
      sets,
      adds: draft.adds.map((a) => ({ ...a, entry: regroup(a.entry) })),
      created: draft.created.map((name) => (name === from ? to : name)),
    },
    view,
  );
}

/** Removes a group's markers; its entries stay, outside any group. */
export function ungroup(draft: Draft, view: HostsFileView, name: string): Draft {
  const original = originalGroup(draft, view, name);
  const renames = new Map(draft.renames);
  if (original !== null) renames.delete(original);
  const loose = (edit: HostsEntryEdit) => (edit.group === name ? { ...edit, group: null } : edit);
  const sets: Record<number, HostsEntryEdit> = {};
  for (const [line, edit] of Object.entries(draft.sets)) sets[Number(line)] = loose(edit);
  return prune(
    {
      ...draft,
      renames,
      sets,
      adds: draft.adds.map((a) => ({ ...a, entry: loose(a.entry) })),
      ungroups: original === null ? draft.ungroups : [...new Set([...draft.ungroups, original])],
      created: draft.created.filter((created) => created !== name),
    },
    view,
  );
}

/** Takes back an ungroup: the markers stay, and the group's entries are in it again. */
export function restoreGroup(draft: Draft, view: HostsFileView, original: string): Draft {
  const sets = { ...draft.sets };
  for (const base of view.entries) {
    const edit = sets[base.line];
    if (edit && base.group === original && edit.group === null)
      sets[base.line] = { ...edit, group: original };
  }
  return prune(
    { ...draft, sets, ungroups: draft.ungroups.filter((name) => name !== original) },
    view,
  );
}

/** Lines of the entries in a view, by everything about them but the line. */
function linesByContent(view: HostsFileView): Map<string, number[]> {
  const lines = new Map<string, number[]>();
  for (const entry of view.entries) {
    const key = JSON.stringify(editOf(entry));
    const found = lines.get(key);
    if (found) found.push(entry.line);
    else lines.set(key, [entry.line]);
  }
  return lines;
}

/**
 * The draft carried over from the file in `from` to its newer `revision` in
 * `to`, or `null` when it no longer fits: every entry it changes or deletes
 * must be in both, listed once and the same apart from its line, and every
 * group it renames or ungroups must still be there.
 */
export function rebase(
  draft: Draft,
  from: HostsFileView,
  to: HostsFileView,
  revision: string,
): Draft | null {
  const before = linesByContent(from);
  const after = linesByContent(to);
  const moved = new Map<number, number>();
  for (const line of [...Object.keys(draft.sets).map(Number), ...draft.removes]) {
    const base = from.entries.find((entry) => entry.line === line);
    const key = base ? JSON.stringify(editOf(base)) : '';
    const target = after.get(key);
    if (!base || before.get(key)?.length !== 1 || target?.length !== 1) return null;
    moved.set(line, target[0] ?? line);
  }
  const groups = new Set(to.groups.map((group) => group.name));
  if (![...draft.renames.keys(), ...draft.ungroups].every((name) => groups.has(name))) return null;
  const at = (line: number) => moved.get(line) ?? line;
  const sets: Record<number, HostsEntryEdit> = {};
  for (const [line, edit] of Object.entries(draft.sets)) sets[at(Number(line))] = edit;
  return { ...draft, revision, sets, removes: draft.removes.map(at) };
}

export type RowStatus = 'same' | 'changed' | 'new' | 'removed';

export interface EntryRow {
  kind: 'entry';
  key: string;
  /** The entry in the file (`null` for new ones). */
  base: HostsFileEntry | null;
  /** Id of a new entry in the draft. */
  addId: number | null;
  entry: HostsEntryEdit;
  status: RowStatus;
  /** In another group than in the file, so saving moves it to the end of that group. */
  moved: boolean;
}

export interface GroupRow {
  kind: 'group';
  key: string;
  /** The name shown, after any rename. */
  name: string;
  /** The name in the file (`null` for a group only new entries use). */
  original: string | null;
  status: 'same' | 'renamed' | 'new' | 'ungrouped';
}

/** Entries shown together: a group, or the entries outside any group. */
export interface Section {
  key: string;
  /** The group's header; `null` for entries outside groups. */
  group: GroupRow | null;
  entries: EntryRow[];
}

/** The loose section's key; group sections have their own. */
export const LOOSE = 'loose';

/**
 * The file's entries by group, with the draft applied: entries outside any
 * group first, then the groups in file order, then new ones. Entries sit
 * where saving puts them: a moved or new entry at the end of its group.
 */
export function sections(view: HostsFileView, draft: Draft): Section[] {
  const loose: Section = { key: LOOSE, group: null, entries: [] };
  const inFile = view.groups.map((group, index) => {
    const renamed = draft.renames.get(group.name);
    const key = `group-${group.line}`;
    const header: GroupRow = {
      kind: 'group',
      key,
      name: renamed ?? group.name,
      original: group.name,
      status: draft.ungroups.includes(group.name) ? 'ungrouped' : renamed ? 'renamed' : 'same',
    };
    return {
      key,
      group: header,
      entries: [] as EntryRow[],
      start: group.line,
      // Without a closing marker, a group runs to the next one.
      end: group.endLine ?? view.groups[index + 1]?.line ?? Number.POSITIVE_INFINITY,
    };
  });
  const fresh: Section[] = [];
  const target = (name: string | null): Section => {
    if (name === null) return loose;
    const found = [...inFile, ...fresh].find(
      (section) => section.group?.status !== 'ungrouped' && section.group?.name === name,
    );
    if (found) return found;
    const key = `new-group-${name}`;
    const section: Section = {
      key,
      group: { kind: 'group', key, name, original: null, status: 'new' },
      entries: [],
    };
    fresh.push(section);
    return section;
  };
  for (const name of draft.created) target(name);

  const moved: EntryRow[] = [];
  for (const base of view.entries) {
    const removed = draft.removes.includes(base.line);
    const set = draft.sets[base.line];
    const entry = set ?? baseline(draft, base);
    const row: EntryRow = {
      kind: 'entry',
      key: `line-${base.line}`,
      base,
      addId: null,
      entry,
      status: removed ? 'removed' : set ? 'changed' : 'same',
      moved: !removed && entry.group !== displayGroup(draft, base.group),
    };
    if (row.moved) {
      moved.push(row);
      continue;
    }
    // Removed entries stay in their group, also when it is ungrouped.
    const home =
      base.group !== null && (removed || row.entry.group !== null)
        ? inFile.find((section) => base.line > section.start && base.line < section.end)
        : undefined;
    (home ?? loose).entries.push(row);
  }
  // Saving writes moved entries first, then new ones, at the end of their group.
  for (const row of moved) target(row.entry.group).entries.push(row);
  for (const add of draft.adds) {
    target(add.entry.group).entries.push({
      kind: 'entry',
      key: `new-${add.id}`,
      base: null,
      addId: add.id,
      entry: add.entry,
      status: 'new',
      moved: false,
    });
  }
  return [loose, ...inFile, ...fresh];
}

/**
 * `name`, or `name 2`, `name 3`… when `taken` has it, shortened to stay
 * within the longest group name.
 */
export function freeGroupName(taken: readonly string[], name: string): string {
  if (!taken.includes(name)) return name;
  for (let n = 2; ; n += 1) {
    const suffix = ` ${n}`;
    const base = [...name]
      .slice(0, MAX_GROUP_NAME - suffix.length)
      .join('')
      .trimEnd();
    if (!taken.includes(`${base}${suffix}`)) return `${base}${suffix}`;
  }
}

/**
 * Entries another computer sent, as a new group of the draft: named `name`,
 * or with a number when the file or the draft has a group of that name.
 * Returns the draft and the group's name.
 */
export function addReceived(
  draft: Draft,
  view: HostsFileView,
  name: string,
  entries: readonly HostsEntryEdit[],
): { draft: Draft; group: string } {
  const group = freeGroupName(
    [...view.groups.map((g) => g.name), ...groupNames(view, draft)],
    name,
  );
  return {
    draft: entries.reduce(
      (next, entry) => addEntry(next, { ...entry, group }),
      createGroup(draft, group),
    ),
    group,
  };
}

/** Group names the draft shows, in order: the groups an entry can be put in. */
export function groupNames(view: HostsFileView, draft: Draft): string[] {
  const names: string[] = [];
  for (const { group } of sections(view, draft)) {
    if (group && group.status !== 'ungrouped' && !names.includes(group.name))
      names.push(group.name);
  }
  return names;
}
