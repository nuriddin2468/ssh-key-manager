import { AlertTriangle, Cpu, Download, KeyRound, Lock, LockOpen, Plus } from 'lucide-react';
import { useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAudit, useKeys } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import { useFindShortcut } from '@/app/useAppEvents';
import type { KeyView } from '@/bindings/KeyView';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Chip } from '@/components/ui/Chip';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { findingsByKey } from '@/features/audit/model';
import { BackToProject } from '@/features/projects/BackToProject';
import { ProjectDots, RowProjectButton } from '@/features/projects/ProjectMenu';
import { cn } from '@/lib/cn';
import { shortFingerprint } from '@/lib/format';
import { modLabel } from '@/lib/platform';
import { KeyDetail } from './KeyDetail';
import { algorithmBadge, hasPrivate, isPlain, isProtected, isWeak, keyTone } from './model';

type Filter = 'all' | 'unlocked' | 'plain' | 'issues' | 'hardware';

const GRID =
  'grid grid-cols-[minmax(0,2.3fr)_minmax(0,1fr)_minmax(0,1.6fr)_60px_minmax(0,1.1fr)] gap-3.5';

export function KeysPage({ keyId }: { keyId?: string }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const keys = useKeys();
  const audit = useAudit();
  const [filter, setFilter] = useState<Filter>('all');
  const [query, setQuery] = useState('');
  const search = useRef<HTMLInputElement>(null);
  useFindShortcut(search);

  const all = keys.data?.keys ?? [];
  const byKey = useMemo(() => findingsByKey(audit.data), [audit.data]);
  const needsCare = (key: KeyView) => (byKey.get(key.id) ?? []).some((f) => f.severity !== 'info');

  const tests: Record<Filter, (key: KeyView) => boolean> = {
    all: () => true,
    unlocked: (key) => key.inAgent,
    plain: isPlain,
    issues: needsCare,
    hardware: (key) => key.hardware,
  };
  const needle = query.trim().toLowerCase();
  const visible = all.filter(
    (key) =>
      tests[filter](key) &&
      (!needle ||
        key.name.toLowerCase().includes(needle) ||
        key.comment.toLowerCase().includes(needle) ||
        (key.fingerprint ?? '').toLowerCase().includes(needle)),
  );
  const selected = all.find((key) => key.id === keyId) ?? visible[0];
  const unlocked = all.filter((key) => key.inAgent).length;

  const chips: { id: Filter; label: string }[] = [
    { id: 'all', label: t('keys.filterAll') },
    { id: 'unlocked', label: t('keys.filterUnlocked') },
    { id: 'plain', label: t('keys.filterPlain') },
    { id: 'issues', label: t('keys.filterIssues') },
    { id: 'hardware', label: t('keys.filterHardware') },
  ];

  return (
    <>
      <Toolbar
        leading={<BackToProject />}
        title={t('keys.title')}
        meta={keys.data ? t('keys.meta', { count: all.length, unlocked }) : undefined}
      >
        <SearchField
          ref={search}
          value={query}
          onChange={setQuery}
          label={t('keys.searchLabel')}
          placeholder={t('keys.searchPlaceholder')}
          className="w-[230px]"
        />
        <IconButton
          label={t('keys.import')}
          shortcut={`${modLabel}O`}
          variant="secondary"
          icon={<Download className="size-[15px]" strokeWidth={1.9} />}
          onClick={() => void dialogs.importKey()}
        />
        <Button
          variant="primary"
          size="sm"
          icon={<Plus className="size-3.5" strokeWidth={2.5} />}
          onClick={dialogs.generateKey}
        >
          {t('keys.newKey')}
        </Button>
      </Toolbar>

      <PageBody>
        {keys.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : all.length === 0 ? (
          <EmptyState
            className="my-auto"
            icon={
              <Tile tone="teal" size={52} glow>
                <KeyRound className="size-6" strokeWidth={2} />
              </Tile>
            }
            title={t('keys.emptyTitle')}
            description={t('keys.emptyText')}
            action={
              <div className="flex gap-2">
                <Button onClick={() => void dialogs.importKey()}>{t('keys.import')}</Button>
                <Button variant="primary" onClick={dialogs.generateKey}>
                  {t('keys.newKey')}
                </Button>
              </div>
            }
          />
        ) : (
          <>
            <fieldset className="flex flex-wrap gap-1.5">
              <legend className="sr-only">{t('keys.filterLabel')}</legend>
              {chips.map((chip) => (
                <Chip
                  key={chip.id}
                  label={chip.label}
                  count={all.filter(tests[chip.id]).length}
                  pressed={filter === chip.id}
                  onClick={() => setFilter(chip.id)}
                />
              ))}
            </fieldset>

            <div className="flex min-h-0 flex-1 items-stretch gap-4">
              <section
                aria-label={t('keys.listLabel')}
                className="glass flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl"
              >
                <div className="min-h-0 flex-1 overflow-auto">
                  <div className="min-w-[580px]">
                    <div
                      className={cn(
                        GRID,
                        'sticky top-0 z-[1] h-[38px] items-center border-b border-white/[0.07] bg-[rgb(14_18_27/0.97)] px-[18px] text-[11.5px] font-medium tracking-[0.02em] text-subtle',
                      )}
                    >
                      <span>{t('keys.colName')}</span>
                      <span>{t('keys.colType')}</span>
                      <span>{t('keys.colFingerprint')}</span>
                      <span>{t('keys.colStatus')}</span>
                      <span>{t('keys.colUsedBy')}</span>
                    </div>
                    <div className="flex flex-col gap-0.5 p-1.5">
                      {visible.map((key) => (
                        <div key={key.id} className="group relative">
                          <KeyRow
                            keyView={key}
                            selected={key.id === selected?.id}
                            attention={needsCare(key)}
                            onSelect={() => navigate({ page: 'keys', keyId: key.id })}
                          />
                          {key.fingerprint ? (
                            <RowProjectButton
                              member={{ type: 'key', fingerprint: key.fingerprint }}
                              name={key.name}
                            />
                          ) : null}
                        </div>
                      ))}
                      {visible.length === 0 ? (
                        <p className="px-4 py-10 text-center text-subtle">{t('keys.noMatches')}</p>
                      ) : null}
                    </div>
                  </div>
                </div>
                {keys.data && keys.data.skipped.length > 0 ? (
                  <p className="border-t border-white/[0.06] px-[18px] py-2.5 text-[12px] text-subtle">
                    {t('keys.skipped', { count: keys.data.skipped.length })}
                  </p>
                ) : null}
              </section>

              {selected ? (
                <KeyDetail keyView={selected} findings={byKey.get(selected.id) ?? []} />
              ) : null}
            </div>
          </>
        )}
      </PageBody>
    </>
  );
}

interface KeyRowProps {
  keyView: KeyView;
  selected: boolean;
  attention: boolean;
  onSelect: () => void;
}

function KeyRow({ keyView: key, selected, attention, onSelect }: KeyRowProps) {
  const { t } = useTranslation();
  const usedBy = key.usedBy.flatMap((u) => u.patterns);
  const weak = isWeak(key);
  return (
    <button
      type="button"
      aria-current={selected ? 'true' : undefined}
      onClick={onSelect}
      className={cn(
        GRID,
        'pressable-soft min-h-[58px] w-full items-center rounded-xl px-3 py-2 text-left active:bg-white/[0.06]',
        selected ? 'selected-row' : 'hover:bg-white/[0.04]',
      )}
    >
      <span className="flex min-w-0 items-center gap-3">
        <Tile tone={keyTone(key)} size={34}>
          <KeyRound className="size-[17px]" strokeWidth={2} />
        </Tile>
        <span className="flex min-w-0 flex-col">
          <span className="flex min-w-0 items-center gap-1.5">
            <span className="truncate font-mono text-[13px] font-medium">{key.name}</span>
            {attention ? (
              <AlertTriangle
                role="img"
                aria-label={t('keys.needsAttention')}
                className="size-3.5 shrink-0 text-warning"
                strokeWidth={2}
              />
            ) : null}
          </span>
          <span className="truncate text-[12px] leading-[18px] text-subtle">
            {key.comment || '—'}
          </span>
          <ProjectDots
            member={key.fingerprint ? { type: 'key', fingerprint: key.fingerprint } : null}
            className="mt-0.5"
          />
        </span>
      </span>
      <span>
        <Badge mono tone={weak ? 'warning' : 'neutral'}>
          {algorithmBadge(key)}
        </Badge>
      </span>
      <span className="truncate font-mono text-[12px] text-muted">
        {shortFingerprint(key.fingerprint)}
      </span>
      <span className="flex items-center gap-2.5">
        {hasPrivate(key) ? (
          <>
            <Cpu
              role="img"
              aria-label={key.inAgent ? t('keys.statusUnlocked') : t('keys.statusLocked')}
              className={cn(
                'size-4',
                key.inAgent
                  ? 'text-violet-300 drop-shadow-[0_0_6px_rgb(167_139_250/0.7)]'
                  : 'text-faint',
              )}
              strokeWidth={1.75}
            />
            {isProtected(key) ? (
              <Lock
                role="img"
                aria-label={t('keys.statusProtected')}
                className="size-4 text-ok"
                strokeWidth={1.75}
              />
            ) : (
              <LockOpen
                role="img"
                aria-label={t('keys.statusPlain')}
                className="size-4 text-warning"
                strokeWidth={1.75}
              />
            )}
          </>
        ) : (
          <span className="text-[11.5px] text-subtle">{t('keys.statusPublic')}</span>
        )}
      </span>
      <span className="truncate text-[12.5px] text-muted">
        {usedBy.length === 0
          ? '—'
          : usedBy.length === 1
            ? usedBy[0]
            : `${usedBy[0]} +${usedBy.length - 1}`}
      </span>
    </button>
  );
}
