import { AlertTriangle, Code2, KeyRound, LockKeyhole, Plus, Server } from 'lucide-react';
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useConfig, useVaultEntries } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import { useFindShortcut } from '@/app/useAppEvents';
import type { HostEntry } from '@/bindings/HostEntry';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { HostEditor } from './HostEditor';
import { hostLabel, hostMethod, hostMonogram, hostTarget, type SignInMethod } from './model';
import { RawConfigDialog } from './RawConfigDialog';
import { findHostEntry, hostAliases } from './vault';

export function HostsPage({ hostId }: { hostId?: number }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const config = useConfig();
  const [query, setQuery] = useState('');
  const [rawOpen, setRawOpen] = useState(false);
  const search = useRef<HTMLInputElement>(null);
  useFindShortcut(search);

  const hosts = config.data?.view.hosts ?? [];
  const vaultEntries = useVaultEntries().data;
  const missing = new Set(
    (config.data?.usage ?? []).filter((u) => u.resolved && !u.exists).map((u) => u.hostId),
  );
  const needle = query.trim().toLowerCase();
  const visible = hosts.filter(
    (host) =>
      !needle ||
      hostLabel(host).toLowerCase().includes(needle) ||
      (host.hostName ?? '').toLowerCase().includes(needle) ||
      (host.user ?? '').toLowerCase().includes(needle),
  );
  const selected = hosts.find((h) => h.id === hostId) ?? visible[0] ?? null;
  const issues = config.data?.view.issues.length ?? 0;
  const includes = config.data?.view.includes ?? [];

  return (
    <>
      <Toolbar
        title={t('hosts.title')}
        meta={config.data ? t('hosts.meta', { count: hosts.length }) : undefined}
      >
        <IconButton
          label={t('hosts.editRaw')}
          variant="secondary"
          icon={<Code2 className="size-[15px]" strokeWidth={1.9} />}
          onClick={() => setRawOpen(true)}
        />
        <Button
          variant="primary"
          size="sm"
          icon={<Plus className="size-3.5" strokeWidth={2.5} />}
          onClick={dialogs.addHost}
        >
          {t('hosts.addHost')}
        </Button>
      </Toolbar>

      <PageBody>
        {config.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : hosts.length === 0 ? (
          <EmptyState
            className="my-auto"
            icon={
              <Tile tone="blue" size={52} glow>
                <Server className="size-6" strokeWidth={2} />
              </Tile>
            }
            title={t('hosts.emptyTitle')}
            description={t('hosts.emptyText')}
            action={
              <Button
                variant="primary"
                icon={<Plus className="size-4" strokeWidth={2.25} />}
                onClick={dialogs.addHost}
              >
                {t('hosts.addHost')}
              </Button>
            }
          />
        ) : (
          <div className="flex min-h-0 flex-1 items-stretch gap-4">
            <section
              aria-label={t('hosts.listLabel')}
              className="glass flex w-[300px] shrink-0 flex-col overflow-hidden rounded-2xl"
            >
              <div className="p-2.5">
                <SearchField
                  ref={search}
                  value={query}
                  onChange={setQuery}
                  label={t('hosts.filterLabel')}
                  placeholder={t('hosts.filterPlaceholder')}
                  className="h-9 w-full rounded-[10px]"
                />
              </div>
              <div className="flex min-h-0 flex-1 flex-col gap-0.5 overflow-y-auto px-1.5 pb-2">
                {visible.map((host) => (
                  <HostRow
                    method={hostMethod(
                      host,
                      findHostEntry(vaultEntries, hostAliases(host)) !== undefined,
                    )}
                    key={host.id}
                    host={host}
                    selected={host.id === selected?.id}
                    broken={missing.has(host.id)}
                    onSelect={() => navigate({ page: 'hosts', hostId: host.id })}
                  />
                ))}
                {visible.length === 0 ? (
                  <p className="px-3 py-8 text-center text-subtle">{t('hosts.noMatches')}</p>
                ) : null}
              </div>
              {issues > 0 || includes.length > 0 ? (
                <div className="flex flex-col gap-1 border-t border-white/[0.06] px-3.5 py-2.5 text-[12px] text-subtle">
                  {includes.length > 0 ? (
                    <p>{t('hosts.includes', { files: includes.join(', ') })}</p>
                  ) : null}
                  {issues > 0 ? (
                    <p className="text-warning">{t('hosts.issues', { count: issues })}</p>
                  ) : null}
                </div>
              ) : null}
            </section>

            {selected ? (
              <HostEditor
                key={`${selected.id}-${selected.lineStart}`}
                host={selected}
                hosts={hosts}
              />
            ) : (
              <div className="glass grid flex-1 place-items-center rounded-2xl text-subtle">
                {t('hosts.selectPrompt')}
              </div>
            )}
          </div>
        )}
      </PageBody>

      <Dialog open={rawOpen} onOpenChange={setRawOpen}>
        {rawOpen ? <RawConfigDialog onDone={() => setRawOpen(false)} /> : null}
      </Dialog>
    </>
  );
}

interface HostRowProps {
  host: HostEntry;
  method: SignInMethod | null;
  selected: boolean;
  broken: boolean;
  onSelect: () => void;
}

function HostRow({ host, method, selected, broken, onSelect }: HostRowProps) {
  const { t } = useTranslation();
  const mono = hostMonogram(host);
  const isDefaults = host.kind === 'host' && host.patterns.length === 1 && host.patterns[0] === '*';
  return (
    <button
      type="button"
      aria-current={selected ? 'true' : undefined}
      onClick={onSelect}
      className={cn(
        'pressable-soft flex w-full items-center gap-[11px] rounded-xl px-2.5 py-2 text-left active:bg-white/[0.06]',
        selected ? 'selected-row' : 'hover:bg-white/[0.04]',
      )}
    >
      <Tile tone={mono.tone} size={34}>
        <span className="font-mono text-[12px] font-semibold">{mono.text}</span>
      </Tile>
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="flex items-center gap-1.5">
          <span className="truncate font-mono text-[13px] font-medium">{hostLabel(host)}</span>
          {isDefaults ? (
            <Badge pill className="text-fg-2">
              {t('hosts.defaults')}
            </Badge>
          ) : null}
          {broken ? (
            <AlertTriangle
              role="img"
              aria-label={t('hosts.missingKey')}
              className="size-3.5 shrink-0 text-warning"
              strokeWidth={2}
            />
          ) : null}
        </span>
        <span className="truncate text-[12px] leading-[18px] text-subtle">
          {isDefaults
            ? t('hosts.appliesToAll')
            : broken
              ? t('hosts.missingKey')
              : hostTarget(host, (jump) => t('hosts.via', { jump }))}
        </span>
      </span>
      {method ? <MethodIcons method={method} /> : null}
    </button>
  );
}

/** The sign-in method as small icons: a key, a lock, or both. */
function MethodIcons({ method }: { method: SignInMethod }) {
  const { t } = useTranslation();
  const label = t('hosts.signIn.listLabel', { method: t(`hosts.signIn.${method}`) });
  return (
    <span title={label} className="flex shrink-0 items-center gap-1 text-subtle">
      {method !== 'password' ? (
        <KeyRound aria-hidden="true" className="size-3.5" strokeWidth={1.9} />
      ) : null}
      {method !== 'key' ? (
        <LockKeyhole aria-hidden="true" className="size-3.5" strokeWidth={1.9} />
      ) : null}
      <span className="sr-only">{label}</span>
    </span>
  );
}
