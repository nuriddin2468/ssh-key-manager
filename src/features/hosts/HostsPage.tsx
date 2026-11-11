import { Code2, Plus, Server } from 'lucide-react';
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useConfig, useConnectionHistory, useEnvironment, useVaultEntries } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import { useFindShortcut } from '@/app/useAppEvents';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { SearchField } from '@/components/ui/SearchField';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { BackToProject } from '@/features/projects/BackToProject';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { cn } from '@/lib/cn';
import { withViewTransition } from '@/lib/viewTransition';
import { AddHostDialog } from './AddHostDialog';
import { HostCard } from './HostCard';
import { HostEditor } from './HostEditor';
import { type HostForm, hostLabel, hostMethod } from './model';
import { RawConfigDialog } from './RawConfigDialog';
import { ShellHistorySuggestions } from './ShellHistorySuggestions';
import { hostEvents } from './status';
import { findHostEntry, hostAliases } from './vault';

export function HostsPage({ hostId }: { hostId?: number }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const config = useConfig();
  const [query, setQuery] = useState('');
  const [rawOpen, setRawOpen] = useState(false);
  // A host from the shell history, open in the Add Host dialog.
  const [suggested, setSuggested] = useState<HostForm | null>(null);
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
  const selected = hosts.find((h) => h.id === hostId) ?? null;
  const history = useConnectionHistory().data;
  const { tabs } = useTerminals();
  const liveTabs = tabs.map((tab) => ({ key: tab.key, alias: tab.alias, phase: tab.state.phase }));
  const sshMissing = useEnvironment().data?.opensshVersion === null;
  const list = useRef<HTMLUListElement>(null);
  const card = (id: number) => document.querySelector<HTMLElement>(`[data-host="${id}"]`);
  // Opening and closing the editor animate: the cards move between the grid
  // and the column, the editor slides. Going from host to host doesn't.
  const openEditor = (id: number) => {
    const show = () => navigate({ page: 'hosts', hostId: id });
    if (selected) show();
    else animate(list.current, show, () => card(id)?.scrollIntoView({ block: 'nearest' }));
  };
  // Focus goes back to the host's card, as the close button goes away.
  const closeEditor = (id: number) => {
    animate(
      list.current,
      () => navigate({ page: 'hosts' }),
      () => {
        card(id)?.focus({ preventScroll: true });
        card(id)?.scrollIntoView({ block: 'nearest' });
      },
    );
  };
  const issues = config.data?.view.issues.length ?? 0;
  const includes = config.data?.view.includes ?? [];

  return (
    <>
      <Toolbar
        leading={<BackToProject />}
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
        {config.data && !selected ? <ShellHistorySuggestions onAdd={setSuggested} /> : null}
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
              // With a host open the cards make one column and the editor takes the rest.
              className={cn(
                'flex min-w-0 flex-col gap-3',
                selected ? 'w-[300px] shrink-0' : 'flex-1',
              )}
            >
              <SearchField
                ref={search}
                value={query}
                onChange={setQuery}
                label={t('hosts.filterLabel')}
                placeholder={t('hosts.filterPlaceholder')}
                className="h-9 w-full max-w-[340px] shrink-0 rounded-[10px] [view-transition-name:host-search]"
              />
              <ul
                ref={list}
                className={cn(
                  'grid min-h-0 flex-1 content-start gap-3 overflow-y-auto pb-1',
                  selected ? 'grid-cols-1' : 'grid-cols-[repeat(auto-fill,minmax(250px,1fr))]',
                )}
              >
                {visible.map((host) => (
                  <HostCard
                    method={hostMethod(
                      host,
                      findHostEntry(vaultEntries, hostAliases(host)) !== undefined,
                    )}
                    key={host.id}
                    host={host}
                    selected={host.id === selected?.id}
                    broken={missing.has(host.id)}
                    events={hostEvents(history, hostAliases(host))}
                    tabs={liveTabs}
                    blocked={sshMissing ? t('hosts.editor.noSsh') : null}
                    onSelect={() => openEditor(host.id)}
                  />
                ))}
                {visible.length === 0 ? (
                  <li className="col-span-full px-3 py-8 text-center text-subtle">
                    {t('hosts.noMatches')}
                  </li>
                ) : null}
              </ul>
              {issues > 0 || includes.length > 0 ? (
                <div className="flex shrink-0 flex-col gap-1 text-[12px] text-subtle">
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
              <div className="flex min-w-0 flex-1 [view-transition-name:host-editor]">
                <HostEditor
                  key={`${selected.id}-${selected.lineStart}`}
                  host={selected}
                  hosts={hosts}
                  onClose={() => closeEditor(selected.id)}
                />
              </div>
            ) : null}
          </div>
        )}
      </PageBody>

      <Dialog open={rawOpen} onOpenChange={setRawOpen}>
        {rawOpen ? <RawConfigDialog onDone={() => setRawOpen(false)} /> : null}
      </Dialog>
      <Dialog
        open={suggested !== null}
        onOpenChange={(open) => (open ? undefined : setSuggested(null))}
      >
        {suggested ? (
          <AddHostDialog
            initial={suggested}
            description={t('historyHosts.addDescription')}
            onDone={() => setSuggested(null)}
          />
        ) : null}
      </Dialog>
    </>
  );
}

/**
 * A view transition in which only the cards in view move. Moving cards are
 * drawn above the page, so ones scrolled out of the list would show over the
 * toolbar; those just appear in their new place.
 */
function animate(list: HTMLUListElement | null, update: () => void, after: () => void) {
  const bounds = list?.getBoundingClientRect();
  const hidden = [...(list?.children ?? [])]
    .filter((item): item is HTMLElement => item instanceof HTMLElement)
    .filter((item) => {
      const box = item.getBoundingClientRect();
      return !bounds || box.bottom <= bounds.top || box.top >= bounds.bottom;
    })
    .map((item) => [item, item.style.viewTransitionName] as const);
  for (const [item] of hidden) item.style.viewTransitionName = 'none';
  const restore = () => {
    for (const [item, name] of hidden) item.style.viewTransitionName = name;
  };
  const transition = withViewTransition(update, after);
  if (transition) void transition.finished.finally(restore);
  else restore();
}
