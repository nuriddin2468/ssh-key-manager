import { describe, expect, it } from 'vitest';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { HostsFileView } from '@/bindings/HostsFileView';
import {
  addEntry,
  changeCount,
  createGroup,
  editOf,
  emptyDraft,
  groupNames,
  removeEntry,
  renameGroup,
  restoreEntry,
  restoreGroup,
  sections,
  setEntry,
  toChanges,
  ungroup,
} from './draft';

function entry(line: number, names: string[], group: string | null = null): HostsFileEntry {
  return {
    line,
    address: `10.0.0.${line}`,
    kind: 'private',
    names,
    comment: null,
    enabled: true,
    system: false,
    shadowed: [],
    group,
    expires: null,
  };
}

const view: HostsFileView = {
  entries: [entry(1, ['loose']), entry(3, ['api'], 'Staging'), entry(4, ['db'], 'Staging')],
  invalid: [],
  groups: [{ name: 'Staging', line: 2, endLine: 5 }],
};
const [loose, api, db] = view.entries as [HostsFileEntry, HostsFileEntry, HostsFileEntry];

const keys = (draft = emptyDraft('r1')) =>
  sections(view, draft).flatMap((section) => [
    ...(section.group ? [`[${section.group.name}]`] : []),
    ...section.entries.map((row) => row.entry.names[0]),
  ]);

describe('draft', () => {
  it('drops a change that sets an entry back', () => {
    let draft = setEntry(emptyDraft('r1'), api, { ...editOf(api), enabled: false });
    expect(changeCount(draft)).toBe(1);
    draft = setEntry(draft, api, editOf(api));
    expect(changeCount(draft)).toBe(0);
  });

  it('removes and restores entries', () => {
    let draft = setEntry(emptyDraft('r1'), loose, { ...editOf(loose), comment: 'x' });
    draft = removeEntry(draft, loose.line);
    expect(toChanges(draft)).toEqual([{ kind: 'remove', line: 1 }]);
    draft = restoreEntry(draft, loose.line);
    expect(changeCount(draft)).toBe(0);
  });

  it('places new entries at the end of their group, or with the loose ones', () => {
    let draft = addEntry(emptyDraft('r1'), {
      ...editOf(loose),
      names: ['cache'],
      group: 'Staging',
    });
    draft = addEntry(draft, { ...editOf(loose), names: ['queue'], group: 'Staging' });
    draft = addEntry(draft, { ...editOf(loose), names: ['plain'], group: null });
    draft = addEntry(draft, { ...editOf(loose), names: ['demo'], group: 'Demo' });
    expect(keys(draft)).toEqual([
      'loose',
      'plain',
      '[Staging]',
      'api',
      'db',
      'cache',
      'queue',
      '[Demo]',
      'demo',
    ]);
    expect(groupNames(view, draft)).toEqual(['Staging', 'Demo']);
  });

  it('renames groups for existing and new entries alike', () => {
    let draft = addEntry(emptyDraft('r1'), {
      ...editOf(loose),
      names: ['cache'],
      group: 'Staging',
    });
    draft = setEntry(draft, api, { ...editOf(api), enabled: false });
    draft = renameGroup(draft, view, 'Staging', 'QA');
    expect(keys(draft)).toEqual(['loose', '[QA]', 'api', 'db', 'cache']);
    expect(toChanges(draft)).toEqual([
      { kind: 'renameGroup', name: 'Staging', to: 'QA' },
      { kind: 'set', line: 3, entry: { ...editOf(api), enabled: false, group: 'QA' } },
      { kind: 'add', entry: { ...editOf(loose), names: ['cache'], group: 'QA' } },
    ]);
    // Renaming back leaves only the real changes.
    draft = renameGroup(draft, view, 'QA', 'Staging');
    expect(Object.keys(draft.renames)).toEqual([]);
    expect(changeCount(draft)).toBe(2);
  });

  it('ungroups without touching the entries', () => {
    const draft = ungroup(emptyDraft('r1'), view, 'Staging');
    expect(toChanges(draft)).toEqual([{ kind: 'ungroup', name: 'Staging' }]);
    expect(sections(view, draft)[1]?.group?.status).toBe('ungrouped');
    expect(keys(draft)).toEqual(['loose', 'api', 'db', '[Staging]']);
    const dbRow = sections(view, draft)[0]?.entries.find((row) => row.base === db);
    expect(dbRow?.entry.group).toBe(null);
  });

  it('takes an ungroup back', () => {
    let draft = setEntry(emptyDraft('r1'), db, { ...editOf(db), enabled: false });
    draft = ungroup(draft, view, 'Staging');
    draft = restoreGroup(draft, view, 'Staging');
    expect(toChanges(draft)).toEqual([
      { kind: 'set', line: 4, entry: { ...editOf(db), enabled: false } },
    ]);
    expect(keys(draft)).toEqual(['loose', '[Staging]', 'api', 'db']);
  });

  it('keeps removed entries in their group', () => {
    let draft = removeEntry(emptyDraft('r1'), api.line);
    draft = ungroup(draft, view, 'Staging');
    expect(keys(draft)).toEqual(['loose', 'db', '[Staging]', 'api']);
  });

  it('shows an entry moved into a new group under that group', () => {
    const draft = setEntry(emptyDraft('r1'), loose, { ...editOf(loose), group: 'Work' });
    expect(keys(draft)).toEqual(['[Staging]', 'api', 'db', '[Work]', 'loose']);
    // Other entries can be put in it before anything is saved.
    expect(groupNames(view, draft)).toEqual(['Staging', 'Work']);
  });

  it('moves an entry taken out of a group out of it', () => {
    const draft = setEntry(emptyDraft('r1'), api, { ...editOf(api), group: null });
    expect(keys(draft)).toEqual(['loose', 'api', '[Staging]', 'db']);
    expect(toChanges(draft)).toEqual([
      { kind: 'set', line: 3, entry: { ...editOf(api), group: null } },
    ]);
  });

  it('moves entries to the end of another group, and back to their place', () => {
    let draft = setEntry(emptyDraft('r1'), loose, { ...editOf(loose), group: 'Staging' });
    draft = addEntry(draft, { ...editOf(loose), names: ['cache'], group: 'Staging' });
    expect(keys(draft)).toEqual(['[Staging]', 'api', 'db', 'loose', 'cache']);
    draft = setEntry(draft, loose, { ...editOf(loose), group: null });
    expect(keys(draft)).toEqual(['loose', '[Staging]', 'api', 'db', 'cache']);
    expect(changeCount(draft)).toBe(1);
  });

  it('keeps an empty new group until it is renamed away or dropped', () => {
    let draft = createGroup(emptyDraft('r1'), 'Work');
    expect(changeCount(draft)).toBe(0);
    expect(keys(draft)).toEqual(['loose', '[Staging]', 'api', 'db', '[Work]']);
    expect(groupNames(view, draft)).toEqual(['Staging', 'Work']);
    draft = setEntry(draft, db, { ...editOf(db), group: 'Work' });
    draft = renameGroup(draft, view, 'Work', 'Office');
    expect(keys(draft)).toEqual(['loose', '[Staging]', 'api', '[Office]', 'db']);
    expect(toChanges(draft)).toEqual([
      { kind: 'set', line: 4, entry: { ...editOf(db), group: 'Office' } },
    ]);
    draft = ungroup(draft, view, 'Office');
    expect(draft.created).toEqual([]);
    expect(keys(draft)).toEqual(['loose', 'db', '[Staging]', 'api']);
  });
});
