import { Plus, SquareTerminal } from 'lucide-react';
import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useConfig } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import { FIND_EVENT } from '@/app/useAppEvents';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { PromptAsk } from '@/bindings/PromptAsk';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { CheckHostKeyDialog } from '@/features/known/CheckHostKeyDialog';
import { formatRelative } from '@/lib/format';
import { HostPicker } from './HostPicker';
import { hostIdOf, isConnectable, isLive, phaseLabel, type Tab } from './model';
import { PromptDialog } from './PromptDialog';
import { panelId, SessionTabs, tabId } from './SessionTabs';
import { FindBar, LoginBanner, SessionView, StatusBar } from './SessionView';
import { useTerminals } from './TerminalProvider';

/** Connect requests already started, by nonce: each starts one session. */
const started = new Set<number>();

export function TerminalPage({ connect, nonce }: { connect?: string; nonce?: number }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  const config = useConfig();
  const { tabs, active } = terminals;
  const tab = tabs.find((item) => item.key === active) ?? null;
  const [closing, setClosing] = useState<{ tab: Tab; keepTab: boolean } | null>(null);
  const [findOpen, setFindOpen] = useState(false);
  const [checking, setChecking] = useState<string | null>(null);
  const [toRemove, setToRemove] = useState<number[] | null>(null);

  const remove = useAppMutation(api.removeKnownHosts, {
    success: (_, lines) => t('known.removed', { line: lines.join(', ') }),
    onSuccess: () => setToRemove(null),
  });

  // Another screen asked for a session (useConnect): start it once.
  useEffect(() => {
    if (!connect) return;
    const request = nonce ?? 0;
    if (!started.has(request)) {
      started.add(request);
      if (isConnectable(connect)) terminals.open(connect);
    }
    navigate({ page: 'terminal' });
  }, [connect, nonce, terminals, navigate]);

  // ⌘F finds in the output.
  useEffect(() => {
    const open = () => setFindOpen(true);
    window.addEventListener(FIND_EVENT, open);
    return () => window.removeEventListener(FIND_EVENT, open);
  }, []);

  const requestClose = useCallback(
    (key: string) => {
      const target = terminals.tabs.find((item) => item.key === key);
      if (!target) return;
      if (isLive(target)) setClosing({ tab: target, keepTab: false });
      else terminals.close(key);
    },
    [terminals],
  );

  // ⌃Tab / ⌃⇧Tab anywhere on the page; the terminal handles its own.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!event.ctrlKey || event.key !== 'Tab') return;
      event.preventDefault();
      terminals.cycle(event.shiftKey ? -1 : 1);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [terminals]);

  const screen = tab ? terminals.screen(tab.key) : undefined;
  const hostId = tab ? hostIdOf(config.data?.view.hosts, tab.alias) : undefined;
  const prompt = tab?.prompt && tab.promptOpen ? tab.prompt : null;

  return (
    <>
      <Toolbar title={t('terminal.title')} meta={t('terminal.meta', { count: tabs.length })}>
        <Button
          variant="primary"
          size="sm"
          icon={<Plus aria-hidden="true" className="size-4" strokeWidth={2.2} />}
          onClick={() => terminals.setPickerOpen(true)}
        >
          {t('terminal.connect')}
        </Button>
      </Toolbar>

      {tab ? (
        <div className="flex min-h-0 flex-1 flex-col px-5 pt-3 pb-5">
          <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-2xl border border-terminal-line bg-terminal">
            <SessionTabs
              tabs={tabs}
              active={active}
              onSelect={terminals.setActive}
              onClose={requestClose}
              onNew={() => terminals.setPickerOpen(true)}
              describe={(item) => phaseLabel(t, item)}
            />
            <LoginBanner tab={tab} onDismiss={() => terminals.dismissBanner(tab.key)} />
            <div
              role="tabpanel"
              id={panelId(tab.key)}
              aria-labelledby={tabId(tab.key)}
              className="relative flex min-h-0 flex-1 flex-col"
            >
              <SessionView
                key={tab.key}
                tab={tab}
                screen={screen}
                onShowPrompt={() => terminals.setPromptOpen(tab.key, true)}
                onReconnect={(options) => terminals.reconnect(tab.key, options)}
                onCloseTab={() => terminals.close(tab.key)}
                onCompare={() => setChecking(tab.info?.host ?? tab.alias)}
              />
              {findOpen && screen ? (
                <FindBar screen={screen} onClose={() => setFindOpen(false)} />
              ) : null}
            </div>
            <StatusBar
              tab={tab}
              onFind={() => setFindOpen(true)}
              onOpenHost={
                hostId === undefined ? undefined : () => navigate({ page: 'hosts', hostId })
              }
              onDisconnect={() => setClosing({ tab, keepTab: true })}
            />
          </div>
        </div>
      ) : (
        <PageBody className="items-center justify-center">
          <EmptySessions
            onConnect={(alias) => terminals.open(alias)}
            onAllHosts={() => terminals.setPickerOpen(true)}
          />
        </PageBody>
      )}

      <Dialog open={terminals.pickerOpen} onOpenChange={(open) => terminals.setPickerOpen(open)}>
        {terminals.pickerOpen ? (
          <HostPicker
            onPick={(alias) => {
              terminals.setPickerOpen(false);
              terminals.open(alias);
            }}
            onCancel={() => terminals.setPickerOpen(false)}
          />
        ) : null}
      </Dialog>

      <Dialog
        open={prompt !== null}
        onOpenChange={(open) => {
          // The close button and Escape are Cancel ("Don't connect" for a key).
          if (!open && tab && prompt) {
            terminals.answer(tab.key, prompt.id, cancelOf(prompt.ask));
          }
        }}
      >
        {prompt && tab ? (
          <PromptDialog
            key={prompt.id}
            tab={tab}
            ask={prompt.ask}
            onAnswer={(answer) => terminals.answer(tab.key, prompt.id, answer)}
          />
        ) : null}
      </Dialog>

      <ConfirmDialog
        open={closing !== null}
        onOpenChange={(open) => (open ? undefined : setClosing(null))}
        title={t('terminal.close.title', { alias: closing?.tab.alias ?? '' })}
        description={t('terminal.close.text')}
        confirmLabel={t('terminal.close.confirm')}
        destructive
        onConfirm={() => {
          if (closing) {
            // "Disconnect" keeps the tab (its scrollback); closing the tab doesn't.
            if (closing.keepTab) terminals.disconnect(closing.tab.key);
            else terminals.close(closing.tab.key);
          }
          setClosing(null);
        }}
      />

      <ConfirmDialog
        open={tab?.keyChanged === true && prompt === null}
        onOpenChange={(open) => (open || !tab ? undefined : terminals.dismissKeyChanged(tab.key))}
        title={t('terminal.prompt.changedTitle', { alias: tab?.alias ?? '' })}
        description={t('terminal.prompt.changedText')}
        cancelLabel={t('common.close')}
        confirmLabel={t('terminal.failed.compare')}
        destructive
        alert
        onConfirm={() => {
          if (!tab) return;
          terminals.dismissKeyChanged(tab.key);
          setChecking(tab.info?.host ?? tab.alias);
        }}
      />

      <Dialog
        open={checking !== null}
        onOpenChange={(open) => (open ? undefined : setChecking(null))}
      >
        {checking !== null ? (
          <CheckHostKeyDialog
            initialHost={checking}
            onRemove={(lines) => setToRemove(lines)}
            onDone={() => setChecking(null)}
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

/** What closing a prompt's dialog answers. */
function cancelOf(ask: PromptAsk): PromptAnswer {
  return ask.type === 'hostKey' ? { type: 'trust', trust: false } : { type: 'cancel' };
}

/** No tabs: where to start, with the hosts connected to recently. */
function EmptySessions({
  onConnect,
  onAllHosts,
}: {
  onConnect: (alias: string) => void;
  onAllHosts: () => void;
}) {
  const { t, i18n } = useTranslation();
  const { recent } = useTerminals();
  return (
    <div className="glass flex w-full max-w-[420px] flex-col items-center gap-3 rounded-[18px] px-[18px] py-[26px] text-center">
      <Tile tone="green" size={52} glow>
        <SquareTerminal className="size-6" strokeWidth={2} />
      </Tile>
      <h2 className="text-[15px] font-semibold">{t('terminal.empty.title')}</h2>
      <p className="max-w-[300px] text-muted">{t('terminal.empty.text')}</p>
      <div className="mt-1.5 flex w-full flex-col gap-1 text-left">
        {recent.length > 0 ? <h3 className="sr-only">{t('terminal.empty.recent')}</h3> : null}
        {recent.slice(0, 5).map((host) => (
          <button
            key={host.alias}
            type="button"
            aria-label={t('terminal.empty.connectTo', { alias: host.alias })}
            onClick={() => onConnect(host.alias)}
            className="pressable-soft flex h-[38px] min-w-0 items-center gap-2.5 rounded-[10px] bg-white/[0.04] px-2.5 hover:bg-white/[0.07]"
          >
            <span className="truncate font-mono">{host.alias}</span>
            <span className="shrink-0 text-subtle">
              {formatRelative(new Date(host.at), i18n.language)}
            </span>
            <span className="ml-auto shrink-0 text-[var(--accent-1)]">
              {t('terminal.empty.connect')}
            </span>
          </button>
        ))}
        <button
          type="button"
          onClick={onAllHosts}
          className="pressable-soft flex h-[38px] items-center rounded-[10px] px-2.5 text-muted hover:bg-white/[0.05] hover:text-fg"
        >
          {t('terminal.empty.allHosts')}
        </button>
      </div>
    </div>
  );
}
