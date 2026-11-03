import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Globe, Hash, Trash2 } from 'lucide-react';
import { useDeferredValue, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useKnownHosts } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useFindShortcut } from '@/app/useAppEvents';
import type { KnownHostEntry } from '@/bindings/KnownHostEntry';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { fileChangeError } from '@/features/hosts/fileErrors';
import { cn } from '@/lib/cn';
import { CheckHostKeyDialog } from './CheckHostKeyDialog';
import type { KnownHostsRemoval } from './removal';

type Filter = 'all' | 'named' | 'hashed' | 'rsa';

const GRID = 'grid grid-cols-[minmax(0,2fr)_96px_minmax(0,2.2fr)_52px_36px] gap-3.5';

/** Splits `host` or `[host]:port` typed in the search box. */
function parseHost(query: string): { host: string; port: number | null } | null {
  const value = query.trim();
  if (!value || /\s/.test(value)) return null;
  const bracketed = /^\[(.+)\]:(\d+)$/.exec(value);
  if (bracketed?.[1]) return { host: bracketed[1], port: Number(bracketed[2]) };
  return { host: value, port: null };
}

export function KnownHostsPage() {
  const { t } = useTranslation();
  const known = useKnownHosts();
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');
  const [checking, setChecking] = useState(false);
  const [toRemove, setToRemove] = useState<KnownHostsRemoval | null>(null);
  const search = useRef<HTMLInputElement>(null);
  useFindShortcut(search);

  // Hashed entries can only be matched by the backend, which knows the salt.
  const deferred = useDeferredValue(query);
  const target = parseHost(deferred);
  const hashedMatches = useQuery({
    queryKey: ['known-hosts', 'find', target?.host, target?.port],
    queryFn: () => api.findKnownHosts(target?.host ?? '', target?.port ?? null),
    enabled: target !== null,
  });

  const remove = useAppMutation(api.removeKnownHosts, {
    success: (_, { lines }) => t('known.removed', { line: lines.join(', ') }),
    onSuccess: () => setToRemove(null),
    // Changed on disk: the list is read again for the user to pick again.
    onError: (error) => {
      if (!fileChangeError(error, t('known.changedOnDisk'))) return false;
      setToRemove(null);
      return true;
    },
  });

  const entries = known.data?.view.entries ?? [];
  const tests: Record<Filter, (entry: KnownHostEntry) => boolean> = {
    all: () => true,
    named: (entry) => !entry.hashed,
    hashed: (entry) => entry.hashed,
    rsa: (entry) => entry.keyType === 'ssh-rsa',
  };
  const needle = deferred.trim().toLowerCase();
  const matchedLines = new Set(hashedMatches.data ?? []);
  const visible = entries.filter(
    (entry) =>
      tests[filter](entry) &&
      (!needle ||
        matchedLines.has(entry.line) ||
        entry.hosts.some((host) => host.toLowerCase().includes(needle)) ||
        entry.fingerprint.toLowerCase().includes(needle)),
  );
  const invalid = known.data?.view.invalid.length ?? 0;

  const chips: { id: Filter; label: string }[] = [
    { id: 'all', label: t('known.filterAll') },
    { id: 'named', label: t('known.filterNamed') },
    { id: 'hashed', label: t('known.filterHashed') },
    { id: 'rsa', label: t('known.filterRsa') },
  ];

  return (
    <>
      <Toolbar
        title={t('known.title')}
        meta={known.data ? t('known.meta', { count: entries.length }) : undefined}
      >
        <SearchField
          ref={search}
          value={query}
          onChange={setQuery}
          label={t('known.searchLabel')}
          placeholder={t('known.searchPlaceholder')}
          className="w-[250px]"
        />
      </Toolbar>

      <PageBody>
        <div className="flex flex-wrap items-center gap-x-[18px] gap-y-3 rounded-[18px] border border-amber-300/25 bg-[linear-gradient(135deg,rgb(245_158_11/0.16),rgb(255_255_255/0.03)_70%)] px-[18px] py-4 shadow-[inset_0_1px_0_rgb(255_255_255/0.05)]">
          <span className="grid size-10 shrink-0 place-items-center rounded-xl border border-warning-solid/35 bg-warning-solid/15 text-warning">
            <AlertTriangle aria-hidden="true" className="size-[19px]" strokeWidth={2} />
          </span>
          <span className="flex min-w-[300px] flex-1 flex-col gap-0.5">
            <span className="font-semibold text-amber-200">{t('known.bannerTitle')}</span>
            <span className="text-[12.5px] leading-[19px] text-[#D9C9A6]">
              {t('known.bannerText')}
            </span>
          </span>
          <Button variant="primary" onClick={() => setChecking(true)}>
            {t('known.checkHostKey')}
          </Button>
        </div>

        {known.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : entries.length === 0 ? (
          <EmptyState
            icon={
              <Tile tone="amber" size={52} glow>
                <Globe className="size-6" strokeWidth={2} />
              </Tile>
            }
            title={t('known.emptyTitle')}
            description={t('known.emptyText')}
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
                  <span>{t('known.colHost')}</span>
                  <span>{t('known.colType')}</span>
                  <span>{t('known.colFingerprint')}</span>
                  <span>{t('known.colLine')}</span>
                  <span className="sr-only">{t('known.colActions')}</span>
                </div>
                {visible.map((entry, index) => (
                  <Row
                    key={entry.line}
                    entry={entry}
                    striped={index % 2 === 1}
                    onRemove={() =>
                      known.data &&
                      setToRemove({ lines: [entry.line], revision: known.data.view.revision })
                    }
                  />
                ))}
                {visible.length === 0 ? (
                  <p className="px-4 py-8 text-center text-subtle">{t('known.noMatches')}</p>
                ) : null}
              </div>
            </div>
            <p className="text-[12.5px] text-subtle">
              {t('known.footer', { shown: visible.length, total: entries.length })}
              {invalid > 0 ? ` ${t('known.invalid', { count: invalid })}` : ''}
            </p>
          </>
        )}
      </PageBody>

      <Dialog open={checking} onOpenChange={setChecking}>
        {checking ? (
          <CheckHostKeyDialog
            initialHost={target?.host ?? ''}
            onRemove={setToRemove}
            onDone={() => setChecking(false)}
          />
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={toRemove !== null}
        onOpenChange={(open) => (open ? undefined : setToRemove(null))}
        title={t('known.removeTitle')}
        description={t('known.removeText')}
        confirmLabel={t('common.delete')}
        destructive
        busy={remove.isPending}
        onConfirm={() => toRemove && remove.mutate(toRemove)}
      />
    </>
  );
}

function Row({
  entry,
  striped,
  onRemove,
}: {
  entry: KnownHostEntry;
  striped: boolean;
  onRemove: () => void;
}) {
  const { t } = useTranslation();
  const rsa = entry.keyType === 'ssh-rsa';
  const tone = entry.hashed ? 'slate' : entry.marker === 'certAuthority' ? 'blue' : 'amber';
  return (
    <div
      className={cn(
        GRID,
        'min-h-12 items-center rounded-xl px-3 py-1',
        striped && 'bg-white/[0.02]',
      )}
    >
      <span className="flex min-w-0 items-center gap-2.5">
        <Tile tone={tone} size={28}>
          {entry.hashed ? (
            <Hash className="size-3.5" strokeWidth={2} />
          ) : (
            <Globe className="size-3.5" strokeWidth={2} />
          )}
        </Tile>
        {entry.hashed ? (
          <span className="text-muted italic">{t('known.hashed')}</span>
        ) : (
          <span className="selectable truncate font-mono text-[12.5px] font-medium">
            {entry.hosts.join(', ')}
          </span>
        )}
        {entry.marker === 'certAuthority' ? (
          <Badge tone="info" pill>
            {t('known.certAuthority')}
          </Badge>
        ) : entry.marker === 'revoked' ? (
          <Badge tone="critical" pill>
            {t('known.revoked')}
          </Badge>
        ) : null}
      </span>
      <span>
        <Badge mono tone={rsa ? 'warning' : 'neutral'}>
          {entry.keyType
            .replace(/^ssh-/, '')
            .replace(/^ecdsa-sha2-nistp/, 'ecdsa-')
            .toUpperCase()}
        </Badge>
      </span>
      <span className="selectable truncate font-mono text-[12px] text-muted">
        {entry.fingerprint}
      </span>
      <span className="font-mono text-[12px] text-subtle tabular-nums">{entry.line}</span>
      <IconButton
        label={t('known.remove', { line: entry.line })}
        icon={<Trash2 className="size-[15px]" strokeWidth={1.75} />}
        onClick={onRemove}
      />
    </div>
  );
}
