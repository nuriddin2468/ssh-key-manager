import { describe, expect, it } from 'vitest';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { HostsFileView } from '@/bindings/HostsFileView';
import {
  addEntry,
  changeCount,
  editOf,
  emptyDraft,
  groupNames,
  removeEntry,
  renameGroup,
  restoreEntry,
  rows,
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
  rows(view, draft).map((row) => (row.kind === 'group' ? `[${row.name}]` : row.entry.names[0]));

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

  it('places new entries at the end of their group, or of the file', () => {
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
      '[Staging]',
      'api',
      'db',
      'cache',
      'queue',
      'plain',
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
    const group = rows(view, draft).find((row) => row.kind === 'group');
    expect(group?.kind === 'group' && group.status).toBe('ungrouped');
    const dbRow = rows(view, draft).find((row) => row.kind === 'entry' && row.base === db);
    expect(dbRow?.kind === 'entry' && dbRow.entry.group).toBe(null);
  });
});
