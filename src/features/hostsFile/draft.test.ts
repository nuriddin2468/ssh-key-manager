import { describe, expect, it } from 'vitest';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { HostsFileView } from '@/bindings/HostsFileView';
import {
  addEntry,
  addReceived,
  changeCount,
  createGroup,
  editOf,
  emptyDraft,
  freeGroupName,
  groupNames,
  rebase,
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

const keys = (draft = emptyDraft('r1'), file = view) =>
  sections(file, draft).flatMap((section) => [
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
    expect(draft.renames.size).toBe(0);
    expect(changeCount(draft)).toBe(2);
  });

  it('takes any group name, also those of object members', () => {
    for (const name of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      const file: HostsFileView = {
        entries: [entry(2, ['api'], name)],
        invalid: [],
        groups: [{ name, line: 1, endLine: 3 }],
      };
      expect(keys(emptyDraft('r1'), file)).toEqual([`[${name}]`, 'api']);
      let draft = renameGroup(emptyDraft('r1'), file, name, 'QA');
      expect(keys(draft, file)).toEqual(['[QA]', 'api']);
      expect(toChanges(draft)).toEqual([{ kind: 'renameGroup', name, to: 'QA' }]);
      draft = renameGroup(draft, file, 'QA', name);
      expect(changeCount(draft)).toBe(0);
      expect(toChanges(ungroup(emptyDraft('r1'), file, name))).toEqual([{ kind: 'ungroup', name }]);
      draft = renameGroup(emptyDraft('r1'), view, 'Staging', name);
      expect(keys(draft)).toEqual(['loose', `[${name}]`, 'api', 'db']);
      expect(toChanges(draft)).toEqual([{ kind: 'renameGroup', name: 'Staging', to: name }]);
    }
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

describe('rebase', () => {
  let draft = setEntry(emptyDraft('r1'), api, { ...editOf(api), enabled: false });
  draft = removeEntry(draft, db.line);
  draft = renameGroup(draft, view, 'Staging', 'QA');
  draft = addEntry(draft, { ...editOf(loose), names: ['cache'] });

  it('carries changes over to entries that only moved', () => {
    // Another program put two lines at the top.
    const moved: HostsFileView = {
      entries: [entry(1, ['vpn']), ...view.entries.map((e) => ({ ...e, line: e.line + 2 }))],
      invalid: [],
      groups: [{ name: 'Staging', line: 4, endLine: 7 }],
    };
    const carried = rebase(draft, view, moved, 'r2');
    expect(carried?.revision).toBe('r2');
    expect(carried && toChanges(carried)).toEqual([
      { kind: 'renameGroup', name: 'Staging', to: 'QA' },
      { kind: 'set', line: 5, entry: { ...editOf(api), enabled: false, group: 'QA' } },
      { kind: 'remove', line: 6 },
      { kind: 'add', entry: { ...editOf(loose), names: ['cache'] } },
    ]);
    // New entries fit any file.
    const added = addEntry(emptyDraft('r1'), editOf(loose));
    expect(rebase(added, view, { entries: [], invalid: [], groups: [] }, 'r2')?.revision).toBe(
      'r2',
    );
  });

  it('gives up when what it changes changed too', () => {
    const edited = view.entries.map((e) => (e.line === api.line ? { ...e, comment: 'x' } : e));
    expect(rebase(draft, view, { ...view, entries: edited }, 'r2')).toBe(null);
    const gone = view.entries.filter((e) => e.line !== db.line);
    expect(rebase(draft, view, { ...view, entries: gone }, 'r2')).toBe(null);
    // Two lines like the changed one: which is meant is unclear.
    const twice = [...view.entries, { ...api, line: 9 }];
    expect(rebase(draft, view, { ...view, entries: twice }, 'r2')).toBe(null);
    expect(rebase(draft, view, { ...view, groups: [] }, 'r2')).toBe(null);
  });
});

describe('received groups', () => {
  it('numbers a name that is taken, within the longest group name', () => {
    expect(freeGroupName([], 'dev')).toBe('dev');
    expect(freeGroupName(['dev', 'dev 2'], 'dev')).toBe('dev 3');
    const long = 'x'.repeat(64);
    expect(freeGroupName([long], long)).toBe(`${'x'.repeat(62)} 2`);
    expect(freeGroupName(['Dev'], 'dev')).toBe('dev');
  });

  it('adds the entries as a new group, beside one of the same name', () => {
    const view: HostsFileView = {
      entries: [entry(2, ['api.local'], 'dev')],
      invalid: [],
      groups: [{ name: 'dev', line: 1, endLine: 3 }],
    };
    const received = [
      {
        address: '10.0.4.12',
        names: ['db.local'],
        comment: null,
        enabled: true,
        expires: null,
        group: 'dev',
      },
      {
        address: '10.0.4.13',
        names: ['cache.local'],
        comment: null,
        enabled: false,
        expires: null,
        group: 'dev',
      },
    ];
    const first = addReceived(emptyDraft('r1'), view, 'dev', received);
    expect(first.group).toBe('dev 2');
    expect(first.draft.adds.map((a) => a.entry.group)).toEqual(['dev 2', 'dev 2']);
    expect(changeCount(first.draft)).toBe(2);
    // A group of that name only in the draft counts as taken too.
    expect(addReceived(first.draft, view, 'dev', received).group).toBe('dev 3');
    expect(toChanges(first.draft).every((change) => change.kind === 'add')).toBe(true);
  });
});
