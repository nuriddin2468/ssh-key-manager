import { isTauri } from '@tauri-apps/api/core';
import { revealItemInDir } from '@tauri-apps/plugin-opener';
import { FolderOpen, Network, Signpost } from 'lucide-react';
import { useDeferredValue, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useEnvironment, useHostsFile } from '@/api/queries';
import { errorMessage, toastError } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import { useFindShortcut } from '@/app/useAppEvents';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { fileManagerName } from '@/lib/platform';
import { LookupDialog } from './LookupDialog';
import { KIND_STYLE } from './model';

type Filter = 'all' | 'on' | 'off' | 'blocked';

const GRID = 'grid grid-cols-[minmax(0,1.3fr)_minmax(0,2fr)_minmax(0,1.4fr)_52px] gap-3.5';

/** Block lists run to six figures; rows past this wait for a narrower search. */
const ROW_LIMIT = 500;

export function HostsFilePage({ line }: { line?: number }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const hostsFile = useHostsFile();
  const environment = useEnvironment();
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');
  const [lookingUp, setLookingUp] = useState(false);
  const search = useRef<HTMLInputElement>(null);
  useFindShortcut(search);

  const loaded = hostsFile.data !== undefined;
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

  const entries = hostsFile.data?.view.entries ?? [];
  const tests: Record<Filter, (entry: HostsFileEntry) => boolean> = {
    all: () => true,
    on: (entry) => entry.enabled,
    off: (entry) => !entry.enabled,
    blocked: (entry) => entry.kind === 'blocked',
  };
  const needle = useDeferredValue(query).trim().toLowerCase();
  const visible = entries.filter(
    (entry) =>
      tests[filter](entry) &&
      (!needle ||
        entry.address.toLowerCase().includes(needle) ||
        entry.names.some((name) => name.toLowerCase().includes(needle)) ||
        (entry.comment?.toLowerCase().includes(needle) ?? false)),
  );
  const shown = visible.slice(0, ROW_LIMIT);
  const invalid = hostsFile.data?.view.invalid ?? [];

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
          hostsFile.data
            ? t('hostsFile.meta', { count: entries.length, path: hostsFile.data.path })
            : undefined
        }
      >
        <SearchField
          ref={search}
          value={query}
          onChange={setQuery}
          label={t('hostsFile.searchLabel')}
          placeholder={t('hostsFile.searchPlaceholder')}
          className="w-[250px]"
        />
        <IconButton
          label={t('keys.showIn', { app: fileManagerName })}
          variant="secondary"
          icon={<FolderOpen className="size-[15px]" strokeWidth={1.75} />}
          onClick={() => void reveal()}
        />
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
          <Button variant="primary" onClick={() => setLookingUp(true)}>
            {t('hostsFile.lookUp')}
          </Button>
        </div>

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
        ) : entries.length === 0 ? (
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
                  count={entries.filter(tests[chip.id]).length}
                  pressed={filter === chip.id}
                  onClick={() => setFilter(chip.id)}
                />
              ))}
            </div>

            <div className="glass overflow-x-auto rounded-2xl">
              <div className="min-w-[640px] p-1.5">
                <div
                  className={cn(
                    GRID,
                    'h-[34px] items-center px-3 text-[11.5px] font-medium tracking-[0.02em] text-subtle',
                  )}
                >
                  <span>{t('hostsFile.colAddress')}</span>
                  <span>{t('hostsFile.colNames')}</span>
                  <span>{t('hostsFile.colComment')}</span>
                  <span>{t('hostsFile.colLine')}</span>
                </div>
                {shown.map((entry, index) => (
                  <Row
                    key={entry.line}
                    entry={entry}
                    striped={index % 2 === 1}
                    highlighted={entry.line === line}
                  />
                ))}
                {visible.length === 0 ? (
                  <p className="px-4 py-8 text-center text-subtle">{t('hostsFile.noMatches')}</p>
                ) : null}
              </div>
            </div>
            <p className="text-[12.5px] text-subtle">
              {visible.length > shown.length
                ? t('hostsFile.footerLimited', { shown: shown.length, total: visible.length })
                : t('hostsFile.footer', { shown: visible.length, total: entries.length })}{' '}
              {t('hostsFile.readOnly')}
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

      <Dialog open={lookingUp} onOpenChange={setLookingUp}>
        {lookingUp ? (
          <LookupDialog
            entries={entries}
            initialName={needle && !/\s/.test(needle) ? needle : ''}
            onShowLine={(target) => {
              setLookingUp(false);
              setFilter('all');
              setQuery('');
              navigate({ page: 'hostsFile', line: target });
            }}
            onDone={() => setLookingUp(false)}
          />
        ) : null}
      </Dialog>
    </>
  );
}

function Row({
  entry,
  striped,
  highlighted,
}: {
  entry: HostsFileEntry;
  striped: boolean;
  highlighted: boolean;
}) {
  const { t } = useTranslation();
  const style = KIND_STYLE[entry.kind];
  const shadowed = new Set(entry.shadowed);
  return (
    <div
      id={`hosts-line-${entry.line}`}
      aria-current={highlighted ? 'true' : undefined}
      className={cn(
        GRID,
        'min-h-12 items-center rounded-xl px-3 py-1',
        striped && 'bg-white/[0.02]',
        highlighted && 'bg-[rgb(var(--accent-rgb)/0.1)] ring-1 ring-[rgb(var(--accent-rgb)/0.55)]',
      )}
    >
      <span className="flex min-w-0 items-center gap-2.5">
        <Tile tone={entry.enabled ? style.tone : 'slate'} size={28}>
          <style.Icon className="size-3.5" strokeWidth={2} />
        </Tile>
        <span className="flex min-w-0 flex-col">
          <span
            className={cn(
              'selectable truncate font-mono text-[12.5px] font-medium',
              !entry.enabled && 'text-muted',
            )}
          >
            {entry.address}
          </span>
          <span className="truncate text-[11.5px] text-subtle">{t(style.label)}</span>
        </span>
      </span>
      <span className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
        {entry.names.map((name, index) => (
          <span
            // A line may list the same name twice.
            // biome-ignore lint/suspicious/noArrayIndexKey: names are not unique
            key={index}
            className={cn(
              'selectable font-mono text-[12.5px] break-all',
              !entry.enabled || shadowed.has(name) ? 'text-subtle' : 'text-fg',
            )}
          >
            {name}
          </span>
        ))}
        {!entry.enabled ? <Badge pill>{t('hostsFile.off')}</Badge> : null}
        {entry.system ? (
          <Badge tone="info" pill>
            {t('hostsFile.system')}
          </Badge>
        ) : null}
        {shadowed.size > 0 ? (
          <Badge tone="warning" pill>
            {t('hostsFile.shadowed', { names: entry.shadowed.join(', ') })}
          </Badge>
        ) : null}
      </span>
      <span className="truncate text-[12.5px] text-muted" title={entry.comment ?? undefined}>
        {entry.comment ?? ''}
      </span>
      <span className="font-mono text-[12px] text-subtle tabular-nums">{entry.line}</span>
    </div>
  );
}
