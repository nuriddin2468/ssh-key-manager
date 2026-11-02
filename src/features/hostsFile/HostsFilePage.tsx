import { isTauri } from '@tauri-apps/api/core';
import { revealItemInDir } from '@tauri-apps/plugin-opener';
import {
  Clock,
  FolderOpen,
  FolderTree,
  History,
  Lock,
  MoreHorizontal,
  Network,
  Pencil,
  Plus,
  Signpost,
  Trash2,
  Undo2,
  Ungroup,
} from 'lucide-react';
import { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEnvironment, useHostsFile } from '@/api/queries';
import { errorMessage, toastError } from '@/api/useAppMutation';
import { useLeaveGuard, useRouter } from '@/app/router';
import { useFindShortcut } from '@/app/useAppEvents';
import type { HostsAddressKind } from '@/bindings/HostsAddressKind';
import type { HostsEntryEdit } from '@/bindings/HostsEntryEdit';
import type { HostsFileView } from '@/bindings/HostsFileView';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/components/ui/Menu';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Switch } from '@/components/ui/Switch';
import { Tile } from '@/components/ui/Tile';
import { Tooltip } from '@/components/ui/Tooltip';
import { cn } from '@/lib/cn';
import { fileManagerName } from '@/lib/platform';
import { BackupsDialog } from './BackupsDialog';
import {
  addEntry,
  baseline,
  changeCount,
  type Draft,
  rows as draftRows,
  type EntryRow,
  emptyDraft,
  type GroupRow,
  groupNames,
  type Row,
  removeAdded,
  removeEntry,
  renameGroup,
  restoreEntry,
  setEntry,
  toChanges,
  ungroup,
  updateAdded,
} from './draft';
import { EntryDialog, GroupDialog } from './EntryDialog';
import { LookupDialog } from './LookupDialog';
import { isExpired, KIND_STYLE } from './model';
import { ReviewDialog } from './ReviewDialog';

type Filter = 'all' | 'on' | 'off' | 'blocked';

const GRID =
  'grid grid-cols-[minmax(0,1.25fr)_minmax(0,2fr)_minmax(0,1.1fr)_112px_84px] items-center gap-3';

/** Block lists run to six figures; rows past this wait for a narrower search. */
const ROW_LIMIT = 500;

const EMPTY_VIEW: HostsFileView = { entries: [], invalid: [], groups: [] };

type OpenDialog =
  | { kind: 'lookup' }
  | { kind: 'entry'; row: EntryRow | null; group: string | null }
  | { kind: 'rename'; name: string }
  | { kind: 'review' }
  | { kind: 'backups' };

/** What an entry row's address points at, also for entries not yet saved. */
function kindOf(row: EntryRow): HostsAddressKind {
  if (row.base && row.base.address === row.entry.address) return row.base.kind;
  if (row.entry.address === '0.0.0.0' || row.entry.address === '::') return 'blocked';
  if (row.entry.address === '::1' || row.entry.address.startsWith('127.')) return 'loopback';
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd]|fe[89ab])/i.test(row.entry.address)
    ? 'private'
    : 'public';
}

export function HostsFilePage({ line }: { line?: number }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const hostsFile = useHostsFile();
  const environment = useEnvironment();
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');
  const [dialog, setDialog] = useState<OpenDialog | null>(null);
  const [draftState, setDraftState] = useState<Draft | null>(null);
  const search = useRef<HTMLInputElement>(null);
  useFindShortcut(search);

  const info = hostsFile.data;
  const revision = info?.revision ?? '';
  const view = info?.view ?? EMPTY_VIEW;
  const editable = info?.readOnly === null;
  const pending = draftState ? changeCount(draftState) : 0;
  // Changes made against an older revision no longer fit the file.
  const stale = pending > 0 && draftState?.revision !== revision;
  const draft = useMemo(
    () => (draftState && pending > 0 && !stale ? draftState : emptyDraft(revision)),
    [draftState, pending, stale, revision],
  );
  const update = (change: (draft: Draft) => Draft) => setDraftState(change(draft));
  const discard = () => setDraftState(null);
  // Unsaved changes would be lost on another page, so leaving asks first.
  const guard = useLeaveGuard(pending > 0);
  const allRows = useMemo(() => draftRows(view, draft), [view, draft]);
  const groups = useMemo(() => groupNames(view, draft), [view, draft]);

  const loaded = info !== undefined;
  // Opened from an audit finding or a lookup: bring that line into view.
  useEffect(() => {
    if (line === undefined || !loaded) return;
    document.getElementById(`hosts-line-${line}`)?.scrollIntoView({ block: 'center' });
  }, [line, loaded]);

  const reveal = async () => {
    const path = environment.data?.hostsFile;
    if (!path || !isTauri()) return;
    try {
      await revealItemInDir(path);
    } catch (error) {
      toastError(t, error);
    }
  };

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
  const entryRows = allRows.filter((row): row is EntryRow => row.kind === 'entry');
  const visible: Row[] = [];
  let header: GroupRow | null = null;
  for (const row of allRows) {
    if (row.kind === 'group') {
      header = row;
      if (!filtering) visible.push(row);
    } else if (matches(row)) {
      if (filtering && header && row.entry.group === header.name) {
        visible.push(header);
        header = null;
      }
      visible.push(row);
    }
  }
  const shown = visible.slice(0, ROW_LIMIT);
  const shownEntries = visible.filter((row) => row.kind === 'entry').length;
  const invalid = view.invalid;

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
  const groupEntries = (name: string) =>
    entryRows.filter(
      (row) => row.entry.group === name && row.status !== 'removed' && !row.base?.system,
    );
  const toggleGroup = (name: string, enabled: boolean) =>
    update((d) =>
      groupEntries(name).reduce(
        (next, row) =>
          row.base
            ? setEntry(next, row.base, { ...row.entry, enabled })
            : row.addId !== null
              ? updateAdded(next, row.addId, { ...row.entry, enabled })
              : next,
        d,
      ),
    );
  const deleteGroup = (group: GroupRow) =>
    update((d) => {
      const next = groupEntries(group.name).reduce(
        (acc, row) =>
          row.base
            ? removeEntry(acc, row.base.line)
            : row.addId !== null
              ? removeAdded(acc, row.addId)
              : acc,
        d,
      );
      return group.original === null ? next : ungroup(next, view, group.name);
    });

  const chips: { id: Filter; label: string }[] = [
    { id: 'all', label: t('hostsFile.filterAll') },
    { id: 'on', label: t('hostsFile.filterOn') },
    { id: 'off', label: t('hostsFile.filterOff') },
    { id: 'blocked', label: t('hostsFile.filterBlocked') },
  ];

  return (
    <>
      <Toolbar
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
          onClick={() => void reveal()}
        />
        {editable ? (
          <>
            <IconButton
              label={t('hostsFile.backups')}
              variant="secondary"
              icon={<History className="size-[15px]" strokeWidth={1.75} />}
              onClick={() => setDialog({ kind: 'backups' })}
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
        <div className="flex flex-wrap items-center gap-x-[18px] gap-y-3 rounded-[18px] border border-indigo-300/25 bg-[linear-gradient(135deg,rgb(99_102_241/0.16),rgb(255_255_255/0.03)_70%)] px-[18px] py-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.05)]">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-indigo-400/35 bg-indigo-500/15 text-indigo-200">
            <Signpost aria-hidden="true" className="size-[19px]" strokeWidth={2} />
          </span>
          <span className="flex min-w-[300px] flex-1 flex-col gap-0.5">
            <span className="font-semibold text-indigo-100">{t('hostsFile.bannerTitle')}</span>
            <span className="text-[12.5px] leading-[19px] text-[#C9CCEB]">
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
        ) : allRows.length === 0 ? (
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

            <div className="glass overflow-x-auto rounded-2xl">
              <div className="min-w-[700px] p-1.5">
                <div
                  className={cn(
                    GRID,
                    'h-[34px] px-3 text-[11.5px] font-medium tracking-[0.02em] text-subtle',
                  )}
                >
                  <span>{t('hostsFile.colAddress')}</span>
                  <span>{t('hostsFile.colNames')}</span>
                  <span>{t('hostsFile.colComment')}</span>
                  <span>{t('hostsFile.colExpires')}</span>
                  <span className="sr-only">{t('hostsFile.colActions')}</span>
                </div>
                {shown.map((row, index) =>
                  row.kind === 'group' ? (
                    <GroupHeader
                      key={row.key}
                      group={row}
                      entries={groupEntries(row.name)}
                      editable={editable}
                      onToggle={(enabled) => toggleGroup(row.name, enabled)}
                      onAdd={() => setDialog({ kind: 'entry', row: null, group: row.name })}
                      onRename={() => setDialog({ kind: 'rename', name: row.name })}
                      onUngroup={() => update((d) => ungroup(d, view, row.name))}
                      onDelete={() => deleteGroup(row)}
                    />
                  ) : (
                    <EntryLine
                      key={row.key}
                      row={row}
                      striped={index % 2 === 1}
                      highlighted={row.base !== null && row.base.line === line}
                      editable={editable}
                      onToggle={(enabled) => setRow(row, { ...row.entry, enabled })}
                      onEdit={() => setDialog({ kind: 'entry', row, group: row.entry.group })}
                      onRemove={() => removeRow(row)}
                      onUndo={() => undoRow(row)}
                    />
                  ),
                )}
                {shownEntries === 0 ? (
                  <p className="px-4 py-8 text-center text-subtle">{t('hostsFile.noMatches')}</p>
                ) : null}
              </div>
            </div>
            <p className="text-[12.5px] text-subtle">
              {visible.length > shown.length
                ? t('hostsFile.footerLimited', { shown: shown.length, total: visible.length })
                : t('hostsFile.footer', { shown: shownEntries, total: entryRows.length })}
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
          className="flex flex-wrap items-center gap-3 border-t border-white/[0.07] bg-[rgb(11_15_23/0.72)] px-6 py-3 backdrop-blur-xl"
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
              onClick={() => setDialog({ kind: 'review' })}
            >
              {t('hostsFile.review')}
            </Button>
          ) : null}
        </section>
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
            onSave={(edit) =>
              dialog.row ? setRow(dialog.row, edit) : update((d) => addEntry(d, edit))
            }
            onDone={() => setDialog(null)}
          />
        ) : dialog?.kind === 'rename' ? (
          <GroupDialog
            name={dialog.name}
            taken={groups.filter((name) => name !== dialog.name)}
            onSave={(to) => update((d) => renameGroup(d, view, dialog.name, to))}
            onDone={() => setDialog(null)}
          />
        ) : dialog?.kind === 'review' ? (
          <ReviewDialog
            revision={draft.revision}
            changes={toChanges(draft)}
            onApplied={() => {
              discard();
              setDialog(null);
            }}
            onStale={() => {
              discard();
              setDialog(null);
            }}
            onDone={() => setDialog(null)}
          />
        ) : dialog?.kind === 'backups' ? (
          <BackupsDialog onDone={() => setDialog(null)} />
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

interface GroupHeaderProps {
  group: GroupRow;
  entries: EntryRow[];
  editable: boolean;
  onToggle: (enabled: boolean) => void;
  onAdd: () => void;
  onRename: () => void;
  onUngroup: () => void;
  onDelete: () => void;
}

function GroupHeader({
  group,
  entries,
  editable,
  onToggle,
  onAdd,
  onRename,
  onUngroup,
  onDelete,
}: GroupHeaderProps) {
  const { t } = useTranslation();
  const on = entries.length > 0 && entries.every((row) => row.entry.enabled);
  const status =
    group.status === 'renamed'
      ? t('hostsFile.groupRenamed')
      : group.status === 'new'
        ? t('hostsFile.groupNew')
        : group.status === 'ungrouped'
          ? t('hostsFile.groupUngrouped')
          : null;
  return (
    <div
      className={cn(
        'mt-1.5 flex min-h-11 items-center gap-2.5 rounded-xl border border-white/[0.06] bg-white/[0.035] px-3 py-1.5',
        group.status === 'ungrouped' && 'opacity-70',
      )}
    >
      <FolderTree
        aria-hidden="true"
        className="size-4 shrink-0 text-indigo-300"
        strokeWidth={1.9}
      />
      <span className="truncate font-semibold">{group.name}</span>
      <span className="text-[12px] text-subtle">
        {t('hostsFile.entries', { count: entries.length })}
      </span>
      {status ? (
        <Badge tone={group.status === 'ungrouped' ? 'warning' : 'accent'} pill>
          {status}
        </Badge>
      ) : null}
      <span className="flex-1" />
      {editable && group.status !== 'ungrouped' ? (
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
            <MenuContent>
              <MenuItem icon={<Plus className="size-4" />} onSelect={onAdd}>
                {t('hostsFile.groupAdd')}
              </MenuItem>
              <MenuItem icon={<Pencil className="size-4" />} onSelect={onRename}>
                {t('hostsFile.groupRename')}
              </MenuItem>
              {group.original !== null ? (
                <MenuItem icon={<Ungroup className="size-4" />} onSelect={onUngroup}>
                  {t('hostsFile.groupUngroup')}
                </MenuItem>
              ) : null}
              <MenuSeparator />
              <MenuItem destructive icon={<Trash2 className="size-4" />} onSelect={onDelete}>
                {t('hostsFile.groupDelete')}
              </MenuItem>
            </MenuContent>
          </Menu>
        </>
      ) : null}
    </div>
  );
}

interface EntryLineProps {
  row: EntryRow;
  striped: boolean;
  highlighted: boolean;
  editable: boolean;
  onToggle: (enabled: boolean) => void;
  onEdit: () => void;
  onRemove: () => void;
  onUndo: () => void;
}

function EntryLine({
  row,
  striped,
  highlighted,
  editable,
  onToggle,
  onEdit,
  onRemove,
  onUndo,
}: EntryLineProps) {
  const { t, i18n } = useTranslation();
  const { entry, base, status } = row;
  const style = KIND_STYLE[kindOf(row)];
  const shadowed = new Set(status === 'same' ? (base?.shadowed ?? []) : []);
  const removed = status === 'removed';
  const name = entry.names[0] ?? entry.address;
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
  const movedTo =
    base && status === 'changed' && entry.group !== null && entry.group !== base.group
      ? entry.group
      : null;
  return (
    <div
      id={base ? `hosts-line-${base.line}` : undefined}
      aria-current={highlighted ? 'true' : undefined}
      className={cn(
        GRID,
        'min-h-12 rounded-xl px-3 py-1',
        striped && 'bg-white/[0.02]',
        highlighted && 'bg-[rgb(var(--accent-rgb)/0.1)] ring-1 ring-[rgb(var(--accent-rgb)/0.55)]',
        status === 'new' && 'bg-ok/[0.05]',
      )}
    >
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
        ) : status === 'changed' ? (
          <Badge tone="accent" pill>
            {t('hostsFile.statusChanged')}
          </Badge>
        ) : removed ? (
          <Badge tone="critical" pill>
            {t('hostsFile.statusRemoved')}
          </Badge>
        ) : null}
        {movedTo ? <Badge pill>{t('hostsFile.movedTo', { group: movedTo })}</Badge> : null}
        {!entry.enabled && !removed ? <Badge pill>{t('hostsFile.off')}</Badge> : null}
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
              <MenuContent>
                <MenuItem icon={<Pencil className="size-4" />} onSelect={onEdit}>
                  {t('hostsFile.edit')}
                </MenuItem>
                {status === 'changed' ? (
                  <MenuItem icon={<Undo2 className="size-4" />} onSelect={onUndo}>
                    {t('hostsFile.undoChanges')}
                  </MenuItem>
                ) : null}
                <MenuSeparator />
                <MenuItem destructive icon={<Trash2 className="size-4" />} onSelect={onRemove}>
                  {t('hostsFile.delete')}
                </MenuItem>
              </MenuContent>
            </Menu>
          </>
        )}
      </span>
    </div>
  );
}
