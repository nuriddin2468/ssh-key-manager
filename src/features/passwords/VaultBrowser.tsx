import {
  FileInput,
  FileOutput,
  LockKeyhole,
  MoreHorizontal,
  Plus,
  RectangleEllipsis,
  Trash2,
} from 'lucide-react';
import { type KeyboardEvent, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultEntries } from '@/api/queries';
import { useRouter } from '@/app/router';
import { useFindShortcut } from '@/app/useAppEvents';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntrySummary } from '@/bindings/EntrySummary';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/components/ui/Menu';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { formatRelative, shortFingerprint } from '@/lib/format';
import { EntryEditor } from './EntryEditor';
import { EntryPane } from './EntryPane';
import { ExportDialog, ImportDialog } from './files';
import {
  avatar,
  type EntryFilter,
  FILTERS,
  filterCounts,
  filterEntries,
  filterShowing,
  matchesFilter,
  matchesQuery,
  urlLabel,
} from './model';
import { takeSearchFocusRequest, useVaultMutation } from './vault';

const GRID =
  'grid grid-cols-[minmax(0,2.2fr)_minmax(0,1fr)_minmax(0,1.4fr)_minmax(0,1.2fr)] gap-3.5';

const FILTER_LABEL = {
  all: 'passwords.filterAll',
  login: 'passwords.filterLogin',
  host: 'passwords.filterHost',
  key: 'passwords.filterKey',
  otp: 'passwords.filterOtp',
  trash: 'passwords.filterTrash',
} as const;

const KIND_LABEL = {
  login: 'passwords.kindLogin',
  host: 'passwords.kindHost',
  key: 'passwords.kindKey',
} as const;

/** The unlocked vault: search, filters, the entry list and the selected entry. */
export function VaultBrowser({ entryId }: { entryId?: string }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const entries = useVaultEntries();
  const [filter, setFilter] = useState<EntryFilter>('all');
  const [query, setQuery] = useState('');
  const [editing, setEditing] = useState<{ entry: EntryDetail | null } | null>(null);
  const [fileDialog, setFileDialog] = useState<'import' | 'export' | null>(null);
  const [confirmEmpty, setConfirmEmpty] = useState(false);
  const search = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  useFindShortcut(search);

  useEffect(() => {
    if (takeSearchFocusRequest()) search.current?.focus();
  }, []);

  const all = entries.data ?? [];
  const counts = useMemo(() => filterCounts(all), [all]);
  const visible = useMemo(() => filterEntries(all, filter, query), [all, filter, query]);
  const selected = visible.find((entry) => entry.id === entryId) ?? visible[0];

  // An entry chosen from elsewhere (a link, a new entry, Undo) must be listed.
  const handled = useRef<string | undefined>(undefined);
  useEffect(() => {
    if (!entryId || handled.current === entryId || !entries.data) return;
    const target = entries.data.find((entry) => entry.id === entryId);
    if (!target) return;
    handled.current = entryId;
    if (!matchesFilter(target, filter)) setFilter(filterShowing(target, filter));
    if (!matchesQuery(target, query)) setQuery('');
  }, [entryId, entries.data, filter, query]);

  const lock = useVaultMutation(api.vaultLock);
  const emptyTrash = useVaultMutation(api.vaultEmptyTrash, {
    success: (count) => t('passwords.trashEmptied', { count }),
    onSuccess: () => setConfirmEmpty(false),
  });

  const select = (entry: EntrySummary) => navigate({ page: 'passwords', entryId: entry.id });
  // The row is already rendered (rows are keyed by id), so focus it right away.
  const focusRow = (id: string) =>
    list.current?.querySelector<HTMLElement>(`[data-entry="${CSS.escape(id)}"]`)?.focus();
  // After the selected entry leaves the list, select its neighbour.
  const selectNeighbour = (gone: EntrySummary) => {
    const index = visible.findIndex((entry) => entry.id === gone.id);
    const next = visible[index + 1] ?? visible[index - 1];
    handled.current = next?.id;
    navigate({ page: 'passwords', entryId: next?.id });
    if (next) focusRow(next.id);
  };

  // Arrow keys move through the list, like a native source list.
  const onListKey = (event: KeyboardEvent) => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return;
    const index = visible.findIndex((entry) => entry.id === selected?.id);
    const next = visible[index + (event.key === 'ArrowDown' ? 1 : -1)];
    if (!next) return;
    event.preventDefault();
    select(next);
    focusRow(next.id);
  };

  const openNew = () => setEditing({ entry: null });

  return (
    <>
      <Toolbar
        title={t('passwords.title')}
        meta={entries.data ? t('passwords.meta', { count: counts.all }) : undefined}
      >
        <SearchField
          ref={search}
          value={query}
          onChange={setQuery}
          label={t('passwords.searchLabel')}
          placeholder={t('passwords.searchPlaceholder')}
          className="w-[230px]"
        />
        <Button
          size="sm"
          title={t('passwords.lockHint')}
          icon={<LockKeyhole className="size-[15px]" strokeWidth={1.9} />}
          loading={lock.isPending}
          onClick={() => lock.mutate(undefined)}
        >
          {t('passwords.lock')}
        </Button>
        <Menu>
          <MenuTrigger asChild>
            <IconButton
              label={t('passwords.more')}
              variant="secondary"
              icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
            />
          </MenuTrigger>
          <MenuContent>
            <MenuItem
              icon={<FileInput className="size-[15px]" strokeWidth={1.9} />}
              onSelect={() => setFileDialog('import')}
            >
              {t('passwords.importCsv')}
            </MenuItem>
            <MenuItem
              icon={<FileOutput className="size-[15px]" strokeWidth={1.9} />}
              onSelect={() => setFileDialog('export')}
            >
              {t('passwords.exportVault')}
            </MenuItem>
          </MenuContent>
        </Menu>
        <Button
          variant="primary"
          size="sm"
          icon={<Plus className="size-3.5" strokeWidth={2.5} />}
          onClick={openNew}
        >
          {t('passwords.newEntry')}
        </Button>
      </Toolbar>

      <PageBody>
        {entries.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : all.length === 0 ? (
          <EmptyState
            className="my-auto"
            icon={
              <Tile tone="indigo" size={52} glow>
                <RectangleEllipsis className="size-6" strokeWidth={2} />
              </Tile>
            }
            title={t('passwords.emptyTitle')}
            description={t('passwords.emptyText')}
            action={
              <div className="flex flex-wrap justify-center gap-2">
                <Button
                  variant="primary"
                  icon={<Plus className="size-4" strokeWidth={2.25} />}
                  onClick={openNew}
                >
                  {t('passwords.newEntry')}
                </Button>
                <Button
                  icon={<FileInput className="size-4" strokeWidth={1.9} />}
                  onClick={() => setFileDialog('import')}
                >
                  {t('passwords.emptyImport')}
                </Button>
              </div>
            }
          />
        ) : (
          <>
            <div className="flex flex-wrap items-center gap-2">
              <fieldset className="flex flex-wrap gap-1.5">
                <legend className="sr-only">{t('passwords.filterLabel')}</legend>
                {FILTERS.map((id) => (
                  <Chip
                    key={id}
                    label={t(FILTER_LABEL[id])}
                    count={counts[id]}
                    pressed={filter === id}
                    onClick={() => setFilter(id)}
                  />
                ))}
              </fieldset>
              {filter === 'trash' && counts.trash > 0 ? (
                <Button
                  variant="danger"
                  size="sm"
                  className="ml-auto"
                  icon={<Trash2 className="size-[15px]" strokeWidth={1.75} />}
                  onClick={() => setConfirmEmpty(true)}
                >
                  {t('passwords.emptyTrash')}
                </Button>
              ) : null}
            </div>

            <div className="flex min-h-0 flex-1 items-stretch gap-4">
              <section
                aria-label={t('passwords.listLabel')}
                className="glass flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl"
              >
                <div className="min-h-0 flex-1 overflow-auto">
                  <div className="min-w-[520px]">
                    <div
                      className={cn(
                        GRID,
                        'sticky top-0 z-[1] h-[38px] items-center border-b border-white/[0.07] bg-[rgb(14_18_27/0.92)] px-[18px] text-[11.5px] font-medium tracking-[0.02em] text-subtle backdrop-blur',
                      )}
                    >
                      <span>{t('passwords.colName')}</span>
                      <span>{t('passwords.colKind')}</span>
                      <span>{t('passwords.colLink')}</span>
                      <span>{t('passwords.colModified')}</span>
                    </div>
                    {/* biome-ignore lint/a11y/noStaticElementInteractions: arrow keys on the focused row button bubble here */}
                    <div ref={list} onKeyDown={onListKey} className="flex flex-col gap-0.5 p-1.5">
                      {visible.map((entry) => (
                        <EntryRow
                          key={entry.id}
                          entry={entry}
                          selected={entry.id === selected?.id}
                          onSelect={() => select(entry)}
                        />
                      ))}
                      {visible.length === 0 ? (
                        <p className="px-4 py-10 text-center text-subtle">
                          {filter === 'trash' && !query
                            ? t('passwords.trashEmpty')
                            : t('passwords.noMatches')}
                        </p>
                      ) : null}
                    </div>
                  </div>
                </div>
              </section>

              {selected ? (
                <EntryPane
                  key={selected.id}
                  entry={selected}
                  onEdit={(entry) => setEditing({ entry })}
                  onGone={() => selectNeighbour(selected)}
                />
              ) : (
                <div className="glass grid w-[340px] shrink-0 place-items-center rounded-2xl px-6 text-center text-subtle xl:w-[380px]">
                  {visible.length > 0 ? t('passwords.selectPrompt') : null}
                </div>
              )}
            </div>
          </>
        )}
      </PageBody>

      <Dialog
        open={editing !== null}
        onOpenChange={(open) => (open ? undefined : setEditing(null))}
      >
        {editing ? (
          <EntryEditor
            entry={editing.entry}
            onDone={(savedId) => {
              setEditing(null);
              if (savedId) navigate({ page: 'passwords', entryId: savedId });
            }}
          />
        ) : null}
      </Dialog>

      <Dialog
        open={fileDialog !== null}
        onOpenChange={(open) => (open ? undefined : setFileDialog(null))}
      >
        {fileDialog === 'import' ? <ImportDialog onDone={() => setFileDialog(null)} /> : null}
        {fileDialog === 'export' ? <ExportDialog onDone={() => setFileDialog(null)} /> : null}
      </Dialog>

      <ConfirmDialog
        open={confirmEmpty}
        onOpenChange={setConfirmEmpty}
        title={t('passwords.emptyTrashTitle')}
        description={t('passwords.emptyTrashText', { count: counts.trash })}
        confirmLabel={t('passwords.emptyTrash')}
        destructive
        busy={emptyTrash.isPending}
        onConfirm={() => emptyTrash.mutate(undefined)}
      />
    </>
  );
}

interface EntryRowProps {
  entry: EntrySummary;
  selected: boolean;
  onSelect: () => void;
}

function EntryRow({ entry, selected, onSelect }: EntryRowProps) {
  const { t, i18n } = useTranslation();
  const mark = avatar(entry.title);
  const link =
    entry.kind === 'host' && entry.host ? (
      <span className="truncate font-mono text-[12px] text-blue-200">{entry.host}</span>
    ) : entry.kind === 'key' && entry.keyFingerprint ? (
      <span className="truncate font-mono text-[12px] text-muted">
        {shortFingerprint(entry.keyFingerprint)}
      </span>
    ) : entry.url ? (
      <span className="truncate text-[12.5px] text-muted">{urlLabel(entry.url)}</span>
    ) : (
      <span className="text-subtle">—</span>
    );

  return (
    <button
      type="button"
      data-entry={entry.id}
      aria-current={selected ? 'true' : undefined}
      onClick={onSelect}
      className={cn(
        GRID,
        'pressable-soft min-h-[54px] w-full items-center rounded-xl px-3 py-2 text-left active:bg-white/[0.06]',
        selected ? 'selected-row' : 'hover:bg-white/[0.04]',
      )}
    >
      <span className="flex min-w-0 items-center gap-3">
        <Tile tone={mark.tone} size={34}>
          <span className="text-[14px] font-semibold">{mark.letter}</span>
        </Tile>
        <span className="flex min-w-0 flex-col">
          <span className="truncate text-[13px] font-medium">{entry.title}</span>
          <span className="truncate text-[12px] leading-[18px] text-subtle">
            {entry.username || '—'}
          </span>
        </span>
      </span>
      <span className="flex min-w-0 items-center gap-1.5">
        <Badge>{t(KIND_LABEL[entry.kind])}</Badge>
        {entry.hasOtp ? (
          <Badge tone="accent" pill>
            <span aria-hidden="true">{t('passwords.otpBadge')}</span>
            <span className="sr-only">{t('passwords.otpBadgeLabel')}</span>
          </Badge>
        ) : null}
      </span>
      {link}
      <span className="truncate text-[12px] text-subtle">
        {entry.modified ? formatRelative(new Date(entry.modified), i18n.language) : '—'}
      </span>
    </button>
  );
}
