// Changes to the hosts file are collected here and applied together, so the
// administrator password is asked once. Existing entries are named by their
// line in the revision the draft was started on.

import type { HostsChange } from '@/bindings/HostsChange';
import type { HostsEntryEdit } from '@/bindings/HostsEntryEdit';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { HostsFileView } from '@/bindings/HostsFileView';

export interface Draft {
  /** The file revision the draft was made against. */
  revision: string;
  /** Wanted state of existing entries, by line. */
  sets: Record<number, HostsEntryEdit>;
  removes: number[];
  adds: { id: number; entry: HostsEntryEdit }[];
  /** New names of existing groups, by their name in the file. */
  renames: Record<string, string>;
  /** Existing groups whose markers go (by their name in the file). */
  ungroups: string[];
}

export const emptyDraft = (revision: string): Draft => ({
  revision,
  sets: {},
  removes: [],
  adds: [],
  renames: {},
  ungroups: [],
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
    Object.keys(draft.renames).length +
    draft.ungroups.length
  );
}

/** The draft as the backend's list of changes. */
export function toChanges(draft: Draft): HostsChange[] {
  return [
    ...Object.entries(draft.renames).map(
      ([name, to]): HostsChange => ({ kind: 'renameGroup', name, to }),
    ),
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

/** The name a group in the file has in the draft (`null` once ungrouped). */
export function displayGroup(draft: Draft, original: string | null): string | null {
  if (original === null || draft.ungroups.includes(original)) return null;
  return draft.renames[original] ?? original;
}

/** Renames a group shown as `from`: an existing one, or one only new entries use. */
export function renameGroup(draft: Draft, view: HostsFileView, from: string, to: string): Draft {
  const original =
    Object.entries(draft.renames).find(([, shown]) => shown === from)?.[0] ??
    (view.groups.some((g) => g.name === from) ? from : null);
  const renames = { ...draft.renames };
  if (original !== null) {
    if (original === to) delete renames[original];
    else renames[original] = to;
  }
  const regroup = (edit: HostsEntryEdit) => (edit.group === from ? { ...edit, group: to } : edit);
  const sets: Record<number, HostsEntryEdit> = {};
  for (const [line, edit] of Object.entries(draft.sets)) sets[Number(line)] = regroup(edit);
  return prune(
    { ...draft, renames, sets, adds: draft.adds.map((a) => ({ ...a, entry: regroup(a.entry) })) },
    view,
  );
}

/** Removes a group's markers; its entries stay, outside any group. */
export function ungroup(draft: Draft, view: HostsFileView, name: string): Draft {
  const original =
    Object.entries(draft.renames).find(([, shown]) => shown === name)?.[0] ??
    (view.groups.some((g) => g.name === name) ? name : null);
  const renames = { ...draft.renames };
  if (original !== null) delete renames[original];
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
    },
    view,
  );
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

export type Row = EntryRow | GroupRow;

/** The file's entries and groups in file order with the draft applied. */
export function rows(view: HostsFileView, draft: Draft): Row[] {
  const items: { line: number; row: Row }[] = [];
  for (const group of view.groups) {
    const ungrouped = draft.ungroups.includes(group.name);
    const renamed = draft.renames[group.name];
    items.push({
      line: group.line,
      row: {
        kind: 'group',
        key: `group-${group.line}`,
        name: renamed ?? group.name,
        original: group.name,
        status: ungrouped ? 'ungrouped' : renamed ? 'renamed' : 'same',
      },
    });
  }
  for (const base of view.entries) {
    const removed = draft.removes.includes(base.line);
    const set = draft.sets[base.line];
    items.push({
      line: base.line,
      row: {
        kind: 'entry',
        key: `line-${base.line}`,
        base,
        addId: null,
        entry: set ?? baseline(draft, base),
        status: removed ? 'removed' : set ? 'changed' : 'same',
      },
    });
  }
  items.sort((a, b) => a.line - b.line);
  const out = items.map((item) => item.row);

  const added = (add: Draft['adds'][number]): EntryRow => ({
    kind: 'entry',
    key: `new-${add.id}`,
    base: null,
    addId: add.id,
    entry: add.entry,
    status: 'new',
  });
  // Rows that sit in a group: its header, its entries in the file, and new
  // entries already placed in it.
  const inGroup = (row: Row, group: string) =>
    row.kind === 'group'
      ? row.status !== 'ungrouped' && row.name === group
      : row.base
        ? displayGroup(draft, row.base.group) === group
        : row.entry.group === group;
  const loose: EntryRow[] = [];
  const fresh = new Map<string, EntryRow[]>();
  for (const add of draft.adds) {
    const group = add.entry.group;
    if (group === null) {
      loose.push(added(add));
      continue;
    }
    // After the last row of that group, if the file has it.
    let last = -1;
    out.forEach((row, index) => {
      if (inGroup(row, group)) last = index;
    });
    if (last >= 0) out.splice(last + 1, 0, added(add));
    else fresh.set(group, [...(fresh.get(group) ?? []), added(add)]);
  }
  out.push(...loose);
  for (const [name, entries] of fresh) {
    out.push({ kind: 'group', key: `new-group-${name}`, name, original: null, status: 'new' });
    out.push(...entries);
  }
  return out;
}

/** Group names the draft shows, in order. */
export function groupNames(view: HostsFileView, draft: Draft): string[] {
  const names: string[] = [];
  for (const row of rows(view, draft)) {
    if (row.kind === 'group' && row.status !== 'ungrouped' && !names.includes(row.name))
      names.push(row.name);
  }
  return names;
}
