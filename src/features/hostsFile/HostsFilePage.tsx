import { useQuery } from '@tanstack/react-query';
import {
  ChevronRight,
  Clock,
  FolderInput,
  FolderOpen,
  FolderPlus,
  FolderTree,
  GripVertical,
  History,
  Lock,
  MoreHorizontal,
  Network,
  Pencil,
  Plus,
  Send,
  Signpost,
  Trash2,
  Undo2,
  Ungroup,
} from 'lucide-react';
import { type PointerEvent, useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useHostsFile } from '@/api/queries';
import { errorMessage, toastError } from '@/api/useAppMutation';
import { useLeaveGuard, useRouter } from '@/app/router';
import { useFindShortcut } from '@/app/useAppEvents';
import type { HostsAddressKind } from '@/bindings/HostsAddressKind';
import type { HostsEntryEdit } from '@/bindings/HostsEntryEdit';
import type { HostsFileView } from '@/bindings/HostsFileView';
import type { ProjectMember } from '@/bindings/ProjectMember';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import {
  Menu,
  MenuContent,
  MenuItem,
  MenuSeparator,
  MenuSub,
  MenuTrigger,
} from '@/components/ui/Menu';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Switch } from '@/components/ui/Switch';
import { Tile } from '@/components/ui/Tile';
import { Tooltip } from '@/components/ui/Tooltip';
import { SendDialog } from '@/features/nearby/SendDialog';
import { BackToProject } from '@/features/projects/BackToProject';
import { ProjectDots, useProjectMenu } from '@/features/projects/ProjectMenu';
import { cn } from '@/lib/cn';
import { fileManagerName } from '@/lib/platform';
import { BackupsDialog } from './BackupsDialog';
import {
  addEntry,
  addReceived,
  baseline,
  changeCount,
  createGroup,
  type Draft,
  sections as draftSections,
  type EntryRow,
  editOf,
  emptyDraft,
  type GroupRow,
  LOOSE,
  moveEntry,
  rebase,
  removeAdded,
  removeEntry,
  renameGroup,
  restoreEntry,
  restoreGroup,
  type Section,
  setEntry,
  toChanges,
  ungroup,
  updateAdded,
} from './draft';
import { EntryDialog, GroupDialog } from './EntryDialog';
import { LookupDialog } from './LookupDialog';
import {
  isExpired,
  isSystemName,
  isValidName,
  KIND_STYLE,
  listsSystemName,
  normalizeName,
} from './model';
import { type ReceivedNote, ReviewDialog } from './ReviewDialog';
import { useEntryDrag } from './useEntryDrag';

type Filter = 'all' | 'on' | 'off' | 'blocked';

const GRID =
  'grid grid-cols-[20px_minmax(0,1.25fr)_minmax(0,2fr)_minmax(0,1.1fr)_112px_84px] items-center gap-x-3';

/** Block lists run to six figures; rows past this wait for a narrower search. */
const ROW_LIMIT = 500;

/** The drop target that makes a new group for the dropped entry. */
const NEW_GROUP = 'new-group';

/** A drop target with an entry over it. */
const DROP =
  'border-[rgb(var(--accent-rgb)/0.55)] bg-[rgb(var(--accent-rgb)/0.07)] shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.12)]';

const EMPTY_VIEW: HostsFileView = { entries: [], invalid: [], groups: [] };

const TOAST_ACTION =
  '!h-7 !rounded-lg !border !border-ink/15 !bg-ink/10 !px-2.5 !text-[12.5px] !font-medium !text-fg hover:!bg-ink/15';

type OpenDialog =
  | { kind: 'lookup' }
  | { kind: 'entry'; row: EntryRow | null; group: string | null }
  | { kind: 'rename'; name: string }
  | { kind: 'create'; move: EntryRow | null }
  // The draft and the file it was made on, kept while the password prompt is
  // open, so the review stays put if the file changes meanwhile.
  | {
      kind: 'review';
      draft: Draft;
      view: HostsFileView;
      conflict: boolean;
      /** The review opened for a group another computer sent. */
      received?: ReceivedNote;
    }
  | { kind: 'backups' }
  | { kind: 'send'; group: string };

/**
 * Received groups already added to a draft, by pairing: the page may mount
 * again with the same route, and must not add one twice.
 */
const shownGroups = new Set<number>();

/** What an entry row's address points at, also for entries not yet saved. */
function kindOf(row: EntryRow): HostsAddressKind {
  if (row.base && row.base.address === row.entry.address) return row.base.kind;
  if (row.entry.address === '0.0.0.0' || row.entry.address === '::') return 'blocked';
  if (row.entry.address === '::1' || row.entry.address.startsWith('127.')) return 'loopback';
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd]|fe[89ab])/i.test(row.entry.address)
    ? 'private'
    : 'public';
}

/** The draft edits build on: changes made against an older revision no longer fit the file. */
function current(state: Draft | null, revision: string): Draft {
  if (state && changeCount(state) > 0 && state.revision === revision) return state;
  // Groups made empty don't name lines, so they outlive a new revision.
  return { ...emptyDraft(revision), created: state?.created ?? [] };
}

const rowId = (row: EntryRow) =>
  row.base ? `hosts-line-${row.base.line}` : `hosts-new-${row.addId}`;

/**
 * For menus whose items open dialogs: the closing menu would hand focus back
 * to its button, away from the dialog's first field.
 */
function useDialogItems() {
  const opening = useRef(false);
  return {
    open: (show: () => void) => () => {
      opening.current = true;
      show();
    },
    onCloseAutoFocus: (event: Event) => {
      if (opening.current) event.preventDefault();
      opening.current = false;
    },
  };
}

/** Entries a group's switch and delete act on: the system's own lines stay. */
const editableEntries = (section: Section) =>
  section.entries.filter((row) => row.status !== 'removed' && !row.base?.system);

export function HostsFilePage({ line, received }: { line?: number; received?: number }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const hostsFile = useHostsFile();
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');
  const [dialog, setDialog] = useState<OpenDialog | null>(null);
  const [draftState, setDraftState] = useState<Draft | null>(null);
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(new Set());
  const [flash, setFlash] = useState<string | null>(null);
  const search = useRef<HTMLInputElement>(null);
  const table = useRef<HTMLDivElement>(null);
  useFindShortcut(search);

  const info = hostsFile.data;
  const revision = info?.revision ?? '';
  const view = info?.view ?? EMPTY_VIEW;
  const editable = info?.readOnly === null;
  const pending = draftState ? changeCount(draftState) : 0;
  const stale = pending > 0 && draftState?.revision !== revision;
  const draft = useMemo(() => current(draftState, revision), [draftState, revision]);
  // A toast's undo runs later, against the draft as it is then.
  const revisionNow = useRef(revision);
  useEffect(() => {
    revisionNow.current = revision;
  }, [revision]);
  const update = (change: (draft: Draft) => Draft) =>
    setDraftState((state) => change(current(state, revisionNow.current)));
  const discard = () => setDraftState(null);
  // Unsaved changes would be lost on another page, so leaving asks first.
  const guard = useLeaveGuard(pending > 0);
  const all = useMemo(() => draftSections(view, draft), [view, draft]);
  const groups = useMemo(
    () => [
      ...new Set(
        all.flatMap(({ group }) => (group && group.status !== 'ungrouped' ? [group.name] : [])),
      ),
    ],
    [all],
  );

  const loaded = info !== undefined;

  // A group another computer sent: added to the draft and shown for review,
  // so nothing is written before the administrator password.
  const incoming = useQuery({
    queryKey: ['nearby', 'received', received],
    queryFn: () => api.nearbyReceivedGroup(received ?? 0),
    enabled: received !== undefined && !shownGroups.has(received),
    staleTime: Number.POSITIVE_INFINITY,
  });
  useEffect(() => {
    const group = incoming.data;
    if (!group || !loaded || shownGroups.has(group.id)) return;
    shownGroups.add(group.id);
    const added = addReceived(current(draftState, revision), view, group.name, group.entries);
    setDraftState(added.draft);
    setDialog({
      kind: 'review',
      draft: added.draft,
      view,
      conflict: false,
      received: {
        group: added.group,
        from: group.from ?? t('nearby.send.anotherComputer'),
        count: group.entries.length,
      },
    });
  }, [incoming.data, loaded, draftState, revision, view, t]);

  // Opened from an audit finding or a lookup: bring that line into view.
  useEffect(() => {
    if (line === undefined || !loaded) return;
    document.getElementById(`hosts-line-${line}`)?.scrollIntoView({ block: 'center' });
  }, [line, loaded]);

  // A moved entry lights up where it landed.
  useEffect(() => {
    if (!flash) return;
    document.getElementById(flash)?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    const timer = setTimeout(() => setFlash(null), 1600);
    return () => clearTimeout(timer);
  }, [flash]);

  const reveal = () => {
    api.revealPlace({ kind: 'hostsFile' }).catch((error: unknown) => toastError(t, error));
  };

  // Draft edits.
  const setRow = (row: EntryRow, edit: HostsEntryEdit) =>
    update((d) =>
      row.base
        ? setEntry(d, row.base, edit)
        : row.addId !== null
          ? updateAdded(d, row.addId, edit)
          : d,
    );
  const removeRow = (row: EntryRow) =>
    update((d) =>
      row.base ? removeEntry(d, row.base.line) : row.addId !== null ? removeAdded(d, row.addId) : d,
    );
  const undoRow = (row: EntryRow) =>
    update((d) =>
      row.base
        ? row.status === 'removed'
          ? restoreEntry(d, row.base.line)
          : setEntry(d, row.base, baseline(d, row.base))
        : d,
    );
  /** Moves an entry, says where it went, and offers to take it back. */
  const moveRow = (row: EntryRow, to: string | null, prepare = (d: Draft) => d) => {
    const from = row.entry.group;
    if (to === from) return;
    update((d) => moveEntry(prepare(d), row, to));
    setFlash(rowId(row));
    const name = row.entry.names[0] ?? row.entry.address;
    const at = revision;
    toast.success(
      to === null
        ? t('hostsFile.movedOut', { name, group: from ?? '' })
        : t('hostsFile.moved', { name, group: to }),
      {
        action: {
          label: t('hostsFile.undo'),
          onClick: () => {
            if (revisionNow.current === at) update((d) => moveEntry(d, row, from));
          },
        },
        classNames: { actionButton: TOAST_ACTION },
      },
    );
  };
  const toggleGroup = (section: Section, enabled: boolean) =>
    update((d) =>
      editableEntries(section).reduce(
        (next, row) =>
          row.base
            ? setEntry(next, row.base, { ...row.entry, enabled })
            : row.addId !== null
              ? updateAdded(next, row.addId, { ...row.entry, enabled })
              : next,
        d,
      ),
    );
  const deleteGroup = (section: Section, group: GroupRow) =>
    update((d) =>
      ungroup(
        editableEntries(section).reduce(
          (acc, row) =>
            row.base
              ? removeEntry(acc, row.base.line)
              : row.addId !== null
                ? removeAdded(acc, row.addId)
                : acc,
          d,
        ),
        view,
        group.name,
      ),
    );
  // Takes back an ungroup, or a delete: the markers and the entries return.
  const restoreSection = (section: Section, group: GroupRow) =>
    update((d) =>
      section.entries.reduce(
        (acc, row) =>
          row.base && row.status === 'removed' ? restoreEntry(acc, row.base.line) : acc,
        group.original === null ? d : restoreGroup(d, view, group.original),
      ),
    );

  const { drag, ghost, start } = useEntryDrag(table, (row, target) => {
    if (target === NEW_GROUP) {
      setDialog({ kind: 'create', move: row });
      return;
    }
    const section = all.find((s) => s.key === target);
    if (section) moveRow(row, section.group?.name ?? null);
  });
  const dragFrom = drag
    ? all.find((s) => s.entries.some((row) => row.key === drag.row.key))?.key
    : undefined;
  /** The section under a drag, when dropping there would move the entry. */
  const over = drag && drag.target !== dragFrom ? drag.target : null;

  // Filters and search.
  const tests: Record<Filter, (row: EntryRow) => boolean> = {
    all: () => true,
    on: (row) => row.entry.enabled,
    off: (row) => !row.entry.enabled,
    blocked: (row) => kindOf(row) === 'blocked',
  };
  const needle = useDeferredValue(query).trim().toLowerCase();
  const filtering = filter !== 'all' || needle !== '';
  const matches = (row: EntryRow) =>
    tests[filter](row) &&
    (!needle ||
      row.entry.address.toLowerCase().includes(needle) ||
      row.entry.names.some((name) => name.toLowerCase().includes(needle)) ||
      (row.entry.comment?.toLowerCase().includes(needle) ?? false));
  const entryRows = all.flatMap((section) => section.entries);
  const anyGroup = all.some((section) => section.group !== null);
  // Search looks inside closed groups; an ungrouped one has no toggle to open it.
  const isOpen = (section: Section) =>
    filtering || section.group?.status === 'ungrouped' || !collapsed.has(section.key);
  let budget = ROW_LIMIT;
  let matched = 0;
  const visible = all.flatMap((section) => {
    const found = filtering ? section.entries.filter(matches) : section.entries;
    matched += found.length;
    // Loose entries only need room when there are some, or one could land there.
    const empty = found.length === 0;
    if (section.group === null ? empty && !drag : filtering && empty) return [];
    const open = isOpen(section);
    const rows = open ? found.slice(0, budget) : [];
    budget -= rows.length;
    return [{ section, found: found.length, rows, hidden: open ? found.length - rows.length : 0 }];
  });
  const rendered = ROW_LIMIT - budget;
  const limited = visible.some((v) => v.hidden > 0);
  const invalid = view.invalid;
  const setOpen = (key: string, open: boolean) =>
    setCollapsed((keys) => {
      const next = new Set(keys);
      if (open) next.delete(key);
      else next.add(key);
      return next;
    });

  const chips: { id: Filter; label: string }[] = [
    { id: 'all', label: t('hostsFile.filterAll') },
    { id: 'on', label: t('hostsFile.filterOn') },
    { id: 'off', label: t('hostsFile.filterOff') },
    { id: 'blocked', label: t('hostsFile.filterBlocked') },
  ];

  const ghostTarget =
    drag?.target === NEW_GROUP
      ? t('hostsFile.newGroup')
      : drag?.target === LOOSE
        ? t('hostsFile.groupNone')
        : (all.find((s) => s.key === drag?.target)?.group?.name ?? null);

  return (
    <>
      <Toolbar
        leading={<BackToProject />}
        title={t('hostsFile.title')}
        meta={
          info ? t('hostsFile.meta', { count: view.entries.length, path: info.path }) : undefined
        }
      >
        <SearchField
          ref={search}
          value={query}
          onChange={setQuery}
          label={t('hostsFile.searchLabel')}
          placeholder={t('hostsFile.searchPlaceholder')}
          className="w-[230px]"
        />
        <IconButton
          label={t('keys.showIn', { app: fileManagerName })}
          variant="secondary"
          icon={<FolderOpen className="size-[15px]" strokeWidth={1.75} />}
          onClick={reveal}
        />
        {editable ? (
          <>
            <IconButton
              label={t('hostsFile.backups')}
              variant="secondary"
              icon={<History className="size-[15px]" strokeWidth={1.75} />}
              onClick={() => setDialog({ kind: 'backups' })}
            />
            <IconButton
              label={t('hostsFile.newGroup')}
              variant="secondary"
              icon={<FolderPlus className="size-[15px]" strokeWidth={1.75} />}
              onClick={() => setDialog({ kind: 'create', move: null })}
            />
            <Button
              variant="primary"
              icon={<Plus className="size-4" strokeWidth={2.2} />}
              onClick={() => setDialog({ kind: 'entry', row: null, group: null })}
            >
              {t('hostsFile.addEntry')}
            </Button>
          </>
        ) : null}
      </Toolbar>

      <PageBody>
        <div className="flex flex-wrap items-center gap-x-[18px] gap-y-3 rounded-[18px] banner px-[18px] py-4">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-[rgb(var(--accent-rgb)/0.35)] bg-[color-mix(in_srgb,var(--accent-2)_15%,transparent)] text-[var(--accent-text)]">
            <Signpost aria-hidden="true" className="size-[19px]" strokeWidth={2} />
          </span>
          <span className="flex min-w-[300px] flex-1 flex-col gap-0.5">
            <span className="font-semibold text-[var(--banner-title)]">
              {t('hostsFile.bannerTitle')}
            </span>
            <span className="text-[12.5px] leading-[19px] text-[var(--banner-text)]">
              {t('hostsFile.bannerText')}
            </span>
          </span>
          <Button variant="soft" onClick={() => setDialog({ kind: 'lookup' })}>
            {t('hostsFile.lookUp')}
          </Button>
        </div>

        {info?.readOnly ? (
          <p className="flex items-start gap-2.5 rounded-xl border border-info-solid/30 bg-info-solid/[0.09] px-3 py-2.5 text-[12.5px] text-info">
            <Lock aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" strokeWidth={2} />
            {info.readOnly === 'notUtf8'
              ? t('hostsFile.readOnlyNotUtf8')
              : info.readOnly === 'link'
                ? t('hostsFile.readOnlyLink')
                : t('hostsFile.readOnlyNoElevation')}
          </p>
        ) : null}

        {hostsFile.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : hostsFile.isError ? (
          <EmptyState
            icon={
              <Tile tone="rose" size={52} glow>
                <Network className="size-6" strokeWidth={2} />
              </Tile>
            }
            title={t('hostsFile.errorTitle')}
            description={errorMessage(t, hostsFile.error)}
            action={<Button onClick={() => void hostsFile.refetch()}>{t('common.retry')}</Button>}
          />
        ) : entryRows.length === 0 && !anyGroup ? (
          <EmptyState
            icon={
              <Tile tone="indigo" size={52} glow>
                <Network className="size-6" strokeWidth={2} />
              </Tile>
            }
            title={t('hostsFile.emptyTitle')}
            description={t('hostsFile.emptyText')}
          />
        ) : (
          <>
            <div className="flex flex-wrap gap-1.5">
              {chips.map((chip) => (
                <Chip
                  key={chip.id}
                  label={chip.label}
                  count={entryRows.filter(tests[chip.id]).length}
                  pressed={filter === chip.id}
                  onClick={() => setFilter(chip.id)}
                />
              ))}
            </div>

            {/* The list scrolls on its own, under the filters, with its column names kept in view. */}
            <div ref={table} className="glass min-h-[260px] overflow-auto rounded-2xl">
              <div className="flex min-w-[720px] flex-col gap-1.5 p-1.5 pt-0">
                <div
                  className={cn(
                    GRID,
                    'sticky top-0 z-10 -mx-1.5 h-9 bg-sticky/94 pr-[18px] pl-3 text-[11.5px] font-medium tracking-[0.02em] text-subtle backdrop-blur',
                  )}
                >
                  <span />
                  <span>{t('hostsFile.colAddress')}</span>
                  <span>{t('hostsFile.colNames')}</span>
                  <span>{t('hostsFile.colComment')}</span>
                  <span>{t('hostsFile.colExpires')}</span>
                  <span className="sr-only">{t('hostsFile.colActions')}</span>
                </div>
                {visible.map(({ section, found, rows, hidden }) => {
                  const group = section.group;
                  const droppable = editable && group?.status !== 'ungrouped';
                  const open = isOpen(section);
                  const lines = rows.map((row) => (
                    <EntryLine
                      key={row.key}
                      row={row}
                      highlighted={row.base !== null && row.base.line === line}
                      flashing={flash === rowId(row)}
                      dragging={drag?.row.key === row.key}
                      editable={editable}
                      groups={groups}
                      onDragStart={(event) => start(event, row)}
                      onToggle={(enabled) => setRow(row, { ...row.entry, enabled })}
                      onEdit={() => setDialog({ kind: 'entry', row, group: row.entry.group })}
                      onMove={(to) => moveRow(row, to)}
                      onMoveNew={() => setDialog({ kind: 'create', move: row })}
                      onRemove={() => removeRow(row)}
                      onUndo={() => undoRow(row)}
                    />
                  ));
                  return group === null ? (
                    <section
                      key={section.key}
                      aria-label={anyGroup ? t('hostsFile.groupNone') : undefined}
                      data-drop={droppable ? section.key : undefined}
                      className={cn(
                        'rounded-xl border border-transparent transition-colors duration-150',
                        over === section.key && DROP,
                      )}
                    >
                      {anyGroup ? (
                        <div className="flex h-8 items-center gap-2 pr-3 pl-[38px] text-[12px]">
                          <span className="font-medium text-fg-2">{t('hostsFile.groupNone')}</span>
                          <span className="text-subtle">
                            {t('hostsFile.entries', { count: found })}
                          </span>
                        </div>
                      ) : null}
                      {lines}
                      {found === 0 && drag ? (
                        <DropHint active={over === section.key}>{t('hostsFile.dragOut')}</DropHint>
                      ) : null}
                    </section>
                  ) : (
                    <section
                      key={section.key}
                      aria-label={group.name}
                      data-drop={droppable ? section.key : undefined}
                      className={cn(
                        'rounded-xl border border-ink/[0.07] bg-ink/[0.025] transition-colors duration-150',
                        group.status === 'ungrouped' && 'border-dashed bg-transparent',
                        over === section.key && DROP,
                      )}
                    >
                      <GroupHeader
                        group={group}
                        entries={editableEntries(section)}
                        count={section.entries.filter((row) => row.status !== 'removed').length}
                        deleted={section.entries.some((row) => row.status === 'removed')}
                        open={open}
                        collapsible={!filtering}
                        editable={editable}
                        onOpenChange={(next) => setOpen(section.key, next)}
                        onToggle={(enabled) => toggleGroup(section, enabled)}
                        onAdd={() => setDialog({ kind: 'entry', row: null, group: group.name })}
                        onRename={() => setDialog({ kind: 'rename', name: group.name })}
                        onUngroup={() => update((d) => ungroup(d, view, group.name))}
                        onDelete={() => deleteGroup(section, group)}
                        onRestore={() => restoreSection(section, group)}
                        // What is sent is read from the file, so only with nothing unsaved.
                        onSend={
                          group.original !== null && pending === 0
                            ? () => setDialog({ kind: 'send', group: group.name })
                            : undefined
                        }
                      />
                      {open ? (
                        <div className="flex flex-col pb-1">
                          {lines}
                          {section.entries.length === 0 && group.status === 'new' ? (
                            <DropHint active={over === section.key}>
                              {t('hostsFile.groupEmpty')}
                            </DropHint>
                          ) : null}
                          {hidden > 0 ? (
                            <p className="px-[38px] py-2 text-[12px] text-subtle">
                              {t('hostsFile.moreEntries', { count: hidden })}
                            </p>
                          ) : null}
                        </div>
                      ) : null}
                    </section>
                  );
                })}
                {filtering && matched === 0 ? (
                  <p className="px-4 py-8 text-center text-subtle">{t('hostsFile.noMatches')}</p>
                ) : null}
                {editable && (!filtering || drag) ? (
                  <button
                    type="button"
                    data-drop={NEW_GROUP}
                    onClick={() => setDialog({ kind: 'create', move: null })}
                    className={cn(
                      'pressable-soft flex h-11 items-center justify-center gap-2 rounded-xl border border-dashed border-ink/[0.12] text-[12.5px] font-medium text-subtle transition-colors duration-150 hover:border-ink/20 hover:bg-fill-subtle hover:text-fg-2',
                      drag && 'border-ink/20 text-fg-2',
                      over === NEW_GROUP && DROP,
                    )}
                  >
                    <FolderPlus aria-hidden="true" className="size-4" strokeWidth={1.9} />
                    {drag ? t('hostsFile.dragNew') : t('hostsFile.newGroup')}
                  </button>
                ) : null}
              </div>
            </div>
            <p className="text-[12.5px] text-subtle">
              {limited
                ? t('hostsFile.footerLimited', { shown: rendered, total: matched })
                : t('hostsFile.footer', { shown: matched, total: entryRows.length })}
              {editable ? ` ${t('hostsFile.editNote')}` : ''}
              {invalid.length > 0
                ? ` ${t('hostsFile.invalid', {
                    count: invalid.length,
                    lines: invalid.map((issue) => issue.line).join(', '),
                  })}`
                : ''}
            </p>
          </>
        )}
      </PageBody>

      {pending > 0 ? (
        <section
          aria-label={t('hostsFile.pending', { count: pending })}
          className="flex flex-wrap items-center gap-3 border-t border-ink/[0.07] bg-surface/72 px-6 py-3"
        >
          {stale ? (
            <span role="alert" className="min-w-0 flex-1 text-[12.5px] text-warning">
              {t('hostsFile.pendingStale')}
            </span>
          ) : (
            <span className="inline-flex min-w-0 flex-1 items-center gap-2 text-[12.5px] text-warning">
              <span aria-hidden="true" className="size-[7px] rounded-full bg-warning" />
              {t('hostsFile.pending', { count: pending })}
            </span>
          )}
          <Button onClick={discard}>{t('common.discard')}</Button>
          {!stale ? (
            <Button
              variant="primary"
              icon={<Lock className="size-4" strokeWidth={2} />}
              onClick={() => setDialog({ kind: 'review', draft, view, conflict: false })}
            >
              {t('hostsFile.review')}
            </Button>
          ) : null}
        </section>
      ) : null}

      {drag ? (
        <div
          ref={ghost}
          aria-hidden="true"
          style={{ transform: `translate(${drag.x + 14}px, ${drag.y + 12}px)` }}
          className="pointer-events-none fixed top-0 left-0 z-[60] flex max-w-[300px] items-center gap-2.5 rounded-xl border border-ink/[0.12] bg-popover/95 py-2 pr-3.5 pl-2.5 shadow-drag backdrop-blur"
        >
          <DragTile row={drag.row} />
          <span className="flex min-w-0 flex-col">
            <span className="truncate font-mono text-[12.5px] font-medium">
              {drag.row.entry.names[0] ?? drag.row.entry.address}
            </span>
            <span
              className={cn(
                'inline-flex min-w-0 items-center gap-1 truncate text-[11.5px]',
                over && ghostTarget ? 'text-[var(--accent-text)]' : 'text-subtle',
              )}
            >
              {over && ghostTarget ? (
                <>
                  <FolderInput aria-hidden="true" className="size-3 shrink-0" strokeWidth={2} />
                  <span className="truncate">{ghostTarget}</span>
                </>
              ) : (
                <span className="truncate font-mono">{drag.row.entry.address}</span>
              )}
            </span>
          </span>
        </div>
      ) : null}

      <Dialog open={dialog !== null} onOpenChange={(open) => (open ? undefined : setDialog(null))}>
        {dialog?.kind === 'lookup' ? (
          <LookupDialog
            entries={view.entries}
            initialName={needle && !/\s/.test(needle) ? needle : ''}
            onShowLine={(target) => {
              setDialog(null);
              setFilter('all');
              setQuery('');
              navigate({ page: 'hostsFile', line: target });
            }}
            onDone={() => setDialog(null)}
          />
        ) : dialog?.kind === 'entry' ? (
          <EntryDialog
            initial={dialog.row?.entry ?? null}
            groups={groups}
            defaultGroup={dialog.group}
            onSave={(edit) => {
              // A group named here stays, like one made with the button, if its entry moves on.
              const made = (d: Draft) =>
                edit.group !== null && !groups.includes(edit.group)
                  ? createGroup(d, edit.group)
                  : d;
              if (!dialog.row) update((d) => addEntry(made(d), edit));
              else if (dialog.row.base) {
                const base = dialog.row.base;
                update((d) => setEntry(made(d), base, edit));
              } else {
                const id = dialog.row.addId;
                if (id !== null) update((d) => updateAdded(made(d), id, edit));
              }
            }}
            onDone={() => setDialog(null)}
          />
        ) : dialog?.kind === 'rename' ? (
          <GroupDialog
            name={dialog.name}
            taken={groups.filter((name) => name !== dialog.name)}
            onSave={(to) => update((d) => renameGroup(d, view, dialog.name, to))}
            onDone={() => setDialog(null)}
          />
        ) : dialog?.kind === 'create' ? (
          <GroupDialog
            name={null}
            taken={groups}
            onSave={(name) =>
              dialog.move
                ? moveRow(dialog.move, name, (d) => createGroup(d, name))
                : update((d) => createGroup(d, name))
            }
            onDone={() => setDialog(null)}
          />
        ) : dialog?.kind === 'review' ? (
          <ReviewDialog
            revision={dialog.draft.revision}
            changes={toChanges(dialog.draft)}
            conflict={dialog.conflict}
            received={dialog.received}
            onApplied={() => {
              discard();
              setDialog(null);
            }}
            onStale={(file) => {
              // Changes that still fit the file are shown against it again.
              const carried = rebase(dialog.draft, dialog.view, file.view, file.revision);
              if (carried) {
                setDraftState(carried);
                setDialog({
                  kind: 'review',
                  draft: carried,
                  view: file.view,
                  conflict: true,
                  received: dialog.received,
                });
              } else {
                toast.error(t('hostsFile.stale'));
                discard();
                setDialog(null);
              }
            }}
            onDone={() => setDialog(null)}
          />
        ) : dialog?.kind === 'backups' ? (
          <BackupsDialog onDone={() => setDialog(null)} />
        ) : dialog?.kind === 'send' ? (
          <SendDialog
            what={{ type: 'hostsGroup', name: dialog.group }}
            name={dialog.group}
            onStarted={() => setDialog(null)}
          />
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={guard.pending !== null}
        onOpenChange={(open) => (open ? undefined : guard.stay())}
        title={t('hostsFile.leaveTitle')}
        description={t('hostsFile.leaveText', { count: pending })}
        confirmLabel={t('hostsFile.leaveConfirm')}
        cancelLabel={t('hostsFile.leaveCancel')}
        destructive
        onConfirm={() => {
          discard();
          guard.leave();
        }}
      />
    </>
  );
}

function DragTile({ row }: { row: EntryRow }) {
  const style = KIND_STYLE[kindOf(row)];
  return (
    <Tile tone={row.entry.enabled ? style.tone : 'slate'} size={26}>
      <style.Icon className="size-3.5" strokeWidth={2} />
    </Tile>
  );
}

/** Where a dragged entry can land in a section that has none. */
function DropHint({ active, children }: { active: boolean; children: string }) {
  return (
    <p
      className={cn(
        'mx-1.5 mb-1 flex h-11 items-center justify-center rounded-lg border border-dashed px-3 text-center text-[12.5px] transition-colors duration-150',
        active
          ? 'border-[rgb(var(--accent-rgb)/0.5)] text-[var(--accent-text)]'
          : 'border-line-strong text-subtle',
      )}
    >
      {children}
    </p>
  );
}

interface GroupHeaderProps {
  group: GroupRow;
  /** Entries the switch acts on. */
  entries: EntryRow[];
  /** Entries in the group once saved. */
  count: number;
  /** Some of its entries will be deleted; with an ungroup, the whole group goes. */
  deleted: boolean;
  open: boolean;
  collapsible: boolean;
  editable: boolean;
  onOpenChange: (open: boolean) => void;
  onToggle: (enabled: boolean) => void;
  onAdd: () => void;
  onRename: () => void;
  onUngroup: () => void;
  onDelete: () => void;
  onRestore: () => void;
  /** Sends the group to a computer nearby; missing while it can't be sent. */
  onSend: (() => void) | undefined;
}

function GroupHeader({
  group,
  entries,
  count,
  deleted,
  open,
  collapsible,
  editable,
  onOpenChange,
  onToggle,
  onAdd,
  onRename,
  onUngroup,
  onDelete,
  onRestore,
  onSend,
}: GroupHeaderProps) {
  const { t } = useTranslation();
  const dialogs = useDialogItems();
  const on = entries.length > 0 && entries.every((row) => row.entry.enabled);
  const off = entries.filter((row) => !row.entry.enabled).length;
  const ungrouped = group.status === 'ungrouped';
  const status =
    group.status === 'renamed'
      ? t('hostsFile.groupRenamed')
      : group.status === 'new'
        ? t('hostsFile.groupNew')
        : ungrouped
          ? deleted
            ? t('hostsFile.groupDeleted')
            : t('hostsFile.groupUngrouped')
          : null;
  return (
    <div className="flex min-h-11 items-center gap-3 py-1.5 pr-3 pl-1.5">
      {collapsible && !ungrouped ? (
        <button
          type="button"
          aria-expanded={open}
          aria-label={group.name}
          onClick={() => onOpenChange(!open)}
          className="pressable grid size-5 shrink-0 place-items-center rounded-md text-subtle hover:bg-ink/[0.08] hover:text-fg"
        >
          <ChevronRight
            aria-hidden="true"
            className={cn('size-4 transition-transform duration-150', open && 'rotate-90')}
            strokeWidth={2}
          />
        </button>
      ) : (
        <span className="w-5 shrink-0" />
      )}
      <span className="flex min-w-0 items-center gap-2.5">
        <Tile tone={ungrouped ? 'slate' : 'indigo'} size={28}>
          <FolderTree className="size-3.5" strokeWidth={2} />
        </Tile>
        <span
          className={cn('truncate font-semibold', ungrouped && 'text-muted line-through')}
          title={group.name}
        >
          {group.name}
        </span>
      </span>
      <span className="shrink-0 text-[12px] text-subtle">
        {t('hostsFile.entries', { count })}
        {off > 0 && off < entries.length ? ` · ${t('hostsFile.entriesOff', { count: off })}` : ''}
      </span>
      {status ? (
        <Badge tone={ungrouped ? 'warning' : 'accent'} pill>
          {status}
        </Badge>
      ) : null}
      <span className="flex-1" />
      {!editable ? null : ungrouped ? (
        <Button size="sm" variant="ghost" icon={<Undo2 className="size-3.5" />} onClick={onRestore}>
          {t('hostsFile.undo')}
        </Button>
      ) : (
        <>
          <Switch
            checked={on}
            disabled={entries.length === 0}
            onCheckedChange={onToggle}
            aria-label={t('hostsFile.groupToggle', { name: group.name })}
          />
          <Menu>
            <MenuTrigger asChild>
              <IconButton
                label={t('hostsFile.groupMore', { name: group.name })}
                icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
              />
            </MenuTrigger>
            <MenuContent onCloseAutoFocus={dialogs.onCloseAutoFocus}>
              <MenuItem icon={<Plus className="size-4" />} onSelect={dialogs.open(onAdd)}>
                {t('hostsFile.groupAdd')}
              </MenuItem>
              <MenuItem icon={<Pencil className="size-4" />} onSelect={dialogs.open(onRename)}>
                {t('hostsFile.groupRename')}
              </MenuItem>
              {group.original !== null ? (
                <MenuItem icon={<Ungroup className="size-4" />} onSelect={onUngroup}>
                  {t('hostsFile.groupUngroup')}
                </MenuItem>
              ) : null}
              {group.original !== null ? (
                <MenuItem
                  icon={<Send className="size-4" />}
                  disabled={!onSend}
                  onSelect={dialogs.open(() => onSend?.())}
                >
                  {t('hostsFile.groupSend')}
                </MenuItem>
              ) : null}
              <MenuSeparator />
              <MenuItem destructive icon={<Trash2 className="size-4" />} onSelect={onDelete}>
                {t('hostsFile.groupDelete')}
              </MenuItem>
            </MenuContent>
          </Menu>
        </>
      )}
    </div>
  );
}

interface EntryLineProps {
  row: EntryRow;
  highlighted: boolean;
  flashing: boolean;
  dragging: boolean;
  editable: boolean;
  /** Groups the entry can be moved to. */
  groups: string[];
  onDragStart: (event: PointerEvent) => void;
  onToggle: (enabled: boolean) => void;
  onEdit: () => void;
  onMove: (group: string | null) => void;
  onMoveNew: () => void;
  onRemove: () => void;
  onUndo: () => void;
}

function EntryLine({
  row,
  highlighted,
  flashing,
  dragging,
  editable,
  groups,
  onDragStart,
  onToggle,
  onEdit,
  onMove,
  onMoveNew,
  onRemove,
  onUndo,
}: EntryLineProps) {
  const { t, i18n } = useTranslation();
  const dialogs = useDialogItems();
  const { entry, base, status } = row;
  const style = KIND_STYLE[kindOf(row)];
  const shadowed = new Set(status === 'same' ? (base?.shadowed ?? []) : []);
  const removed = status === 'removed';
  const movable = editable && !removed && !base?.system;
  const name = entry.names[0] ?? entry.address;
  // A line joins a project by its first name of its own, as the file has it.
  const projectName =
    // A line that lists a system name can't be switched: none of its names join.
    base && status !== 'new' && !listsSystemName(base) && base.kind !== 'blocked'
      ? base.names.map(normalizeName).find((n) => isValidName(n) && !isSystemName(n))
      : undefined;
  const projectMember: ProjectMember | null = projectName
    ? { type: 'hostsFile', name: projectName }
    : null;
  const projectMenu = useProjectMenu(projectMember);
  const expires = entry.expires ? new Date(entry.expires) : null;
  const today = expires?.toDateString() === new Date().toDateString();
  const until = expires
    ? new Intl.DateTimeFormat(
        i18n.language,
        today
          ? { timeStyle: 'short' }
          : { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' },
      ).format(expires)
    : null;
  const expired = entry.enabled && isExpired(entry.expires);
  // A move alone is not an edit; the badge says which happened.
  const edited =
    status === 'changed' &&
    base !== null &&
    JSON.stringify({ ...editOf(base), group: null }) !== JSON.stringify({ ...entry, group: null });
  const targets = groups.filter((group) => group !== entry.group);
  return (
    <div
      id={rowId(row)}
      aria-current={highlighted ? 'true' : undefined}
      className={cn(
        GRID,
        'group/row min-h-12 rounded-xl py-1 pr-3 pl-1.5 transition-opacity duration-150 hover:bg-fill-subtle',
        highlighted && 'bg-[rgb(var(--accent-rgb)/0.1)] ring-1 ring-[rgb(var(--accent-rgb)/0.55)]',
        status === 'new' && 'bg-ok/[0.05]',
        flashing && 'animate-flash',
        dragging && 'opacity-35',
      )}
    >
      {movable ? (
        <Tooltip content={t('hostsFile.dragHandle')}>
          <span
            aria-hidden="true"
            onPointerDown={onDragStart}
            className="grid h-8 w-5 cursor-grab touch-none place-items-center rounded-md text-faint transition-colors duration-100 group-hover/row:text-muted hover:bg-ink/[0.07] hover:text-fg"
          >
            <GripVertical className="size-4" strokeWidth={1.9} />
          </span>
        </Tooltip>
      ) : (
        <span />
      )}
      <span className="flex min-w-0 items-center gap-2.5">
        <Tile tone={entry.enabled && !removed ? style.tone : 'slate'} size={28}>
          <style.Icon className="size-3.5" strokeWidth={2} />
        </Tile>
        <span className="flex min-w-0 flex-col">
          <span
            className={cn(
              'selectable truncate font-mono text-[12.5px] font-medium',
              (!entry.enabled || removed) && 'text-muted',
              removed && 'line-through',
            )}
          >
            {entry.address}
          </span>
          <span className="truncate text-[11.5px] text-subtle">{t(style.label)}</span>
        </span>
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        {entry.names.map((n, index) => (
          <span
            // biome-ignore lint/suspicious/noArrayIndexKey: a line may list a name twice
            key={index}
            className={cn(
              'selectable font-mono text-[12.5px] break-all',
              !entry.enabled || removed || shadowed.has(n) ? 'text-subtle' : 'text-fg',
              removed && 'line-through',
            )}
          >
            {n}
          </span>
        ))}
        {status === 'new' ? (
          <Badge tone="accent" pill>
            {t('hostsFile.statusNew')}
          </Badge>
        ) : removed ? (
          <Badge tone="critical" pill>
            {t('hostsFile.statusRemoved')}
          </Badge>
        ) : null}
        {row.moved ? (
          <Badge tone="accent" pill>
            {t('hostsFile.statusMoved')}
          </Badge>
        ) : null}
        {edited ? (
          <Badge tone="accent" pill>
            {t('hostsFile.statusChanged')}
          </Badge>
        ) : null}
        {!entry.enabled && !removed ? <Badge pill>{t('hostsFile.off')}</Badge> : null}
        <ProjectDots member={projectMember} />
        {base?.system ? (
          <Badge tone="info" pill>
            {t('hostsFile.system')}
          </Badge>
        ) : null}
        {shadowed.size > 0 ? (
          <Badge tone="warning" pill>
            {t('hostsFile.shadowed', { names: [...shadowed].join(', ') })}
          </Badge>
        ) : null}
      </span>
      <span className="truncate text-[12.5px] text-muted" title={entry.comment ?? undefined}>
        {entry.comment ?? ''}
      </span>
      <span
        className={cn(
          'inline-flex min-w-0 items-center gap-1.5 text-[12.5px] tabular-nums',
          expired
            ? 'font-medium text-warning'
            : entry.enabled && !removed
              ? 'text-fg-2'
              : 'text-subtle',
        )}
      >
        {until ? (
          <>
            <Clock aria-hidden="true" className="size-3.5 shrink-0" strokeWidth={2} />
            <span className="truncate">{expired ? t('hostsFile.expired') : until}</span>
          </>
        ) : null}
      </span>
      <span className="flex items-center justify-end gap-1">
        {base?.system ? (
          <Tooltip content={t('hostsFile.systemLocked')}>
            <span
              role="img"
              aria-label={t('hostsFile.systemLocked')}
              className="grid size-[30px] place-items-center text-subtle"
            >
              <Lock aria-hidden="true" className="size-3.5" strokeWidth={2} />
            </span>
          </Tooltip>
        ) : !editable ? null : removed ? (
          <Button size="sm" variant="ghost" icon={<Undo2 className="size-3.5" />} onClick={onUndo}>
            {t('hostsFile.undo')}
          </Button>
        ) : (
          <>
            <Switch
              checked={entry.enabled}
              onCheckedChange={onToggle}
              aria-label={t('hostsFile.toggle', { name })}
            />
            <Menu>
              <MenuTrigger asChild>
                <IconButton
                  label={t('hostsFile.more', { name })}
                  icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
                />
              </MenuTrigger>
              <MenuContent onCloseAutoFocus={dialogs.onCloseAutoFocus}>
                <MenuItem icon={<Pencil className="size-4" />} onSelect={dialogs.open(onEdit)}>
                  {t('hostsFile.edit')}
                </MenuItem>
                <MenuSub icon={<FolderInput className="size-4" />} label={t('hostsFile.moveTo')}>
                  {entry.group !== null ? (
                    <MenuItem icon={<Ungroup className="size-4" />} onSelect={() => onMove(null)}>
                      {t('hostsFile.groupNone')}
                    </MenuItem>
                  ) : null}
                  {targets.map((group) => (
                    <MenuItem
                      key={group}
                      icon={<FolderTree className="size-4" />}
                      onSelect={() => onMove(group)}
                    >
                      <span className="truncate">{group}</span>
                    </MenuItem>
                  ))}
                  {entry.group !== null || targets.length > 0 ? <MenuSeparator /> : null}
                  <MenuItem
                    icon={<FolderPlus className="size-4" />}
                    onSelect={dialogs.open(onMoveNew)}
                  >
                    {t('hostsFile.groupCreate')}
                  </MenuItem>
                </MenuSub>
                {status === 'changed' ? (
                  <MenuItem icon={<Undo2 className="size-4" />} onSelect={onUndo}>
                    {t('hostsFile.undoChanges')}
                  </MenuItem>
                ) : null}
                {projectMenu.sub}
                <MenuSeparator />
                <MenuItem destructive icon={<Trash2 className="size-4" />} onSelect={onRemove}>
                  {t('hostsFile.delete')}
                </MenuItem>
              </MenuContent>
            </Menu>
          </>
        )}
      </span>
      {projectMenu.dialog}
    </div>
  );
}
