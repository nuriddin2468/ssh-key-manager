import { createContext, type ReactNode, use, useCallback, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api, type TerminalMessage } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { errorMessage } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { TerminalEvent } from '@/bindings/TerminalEvent';
import { AppError } from '@/lib/ipc';
import {
  afterClose,
  announcement,
  applyEvent,
  cycle,
  isLive,
  loadRecent,
  newTab,
  type RecentHost,
  rememberRecent,
  saveRecent,
  type Tab,
} from './model';
import { Screen } from './screen';

interface OpenOptions {
  /** Ask for the password instead of giving the saved one. */
  askPassword?: boolean;
}

interface TerminalsValue {
  tabs: Tab[];
  active: string | null;
  setActive: (key: string) => void;
  /** Opens a session to `alias` in a new tab and shows it. */
  open: (alias: string, options?: OpenOptions) => void;
  /** Starts the tab's session again, in the same tab. */
  reconnect: (key: string, options?: OpenOptions) => void;
  /** Disconnects (if live) and removes the tab. Ask first for live tabs. */
  close: (key: string) => void;
  /** Ends the session and keeps the tab. */
  disconnect: (key: string) => void;
  /** Answers prompt `promptId` of the tab, if it still waits. */
  answer: (key: string, promptId: number, answer: PromptAnswer) => void;
  /** Opens or hides the waiting prompt's dialog. */
  setPromptOpen: (key: string, open: boolean) => void;
  dismissBanner: (key: string) => void;
  dismissKeyChanged: (key: string) => void;
  cycle: (step: 1 | -1) => void;
  screen: (key: string) => Screen | undefined;
  recent: RecentHost[];
  pickerOpen: boolean;
  setPickerOpen: (open: boolean) => void;
}

const TerminalsContext = createContext<TerminalsValue | null>(null);

const storage = typeof localStorage === 'undefined' ? undefined : localStorage;

/**
 * Owns the terminal sessions and their xterms, above the pages, so sessions
 * keep running and keep their scrollback while other sections show.
 */
export function TerminalProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const { route, navigate } = useRouter();
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [active, setActiveKey] = useState<string | null>(null);
  const [recent, setRecent] = useState<RecentHost[]>(() => loadRecent(storage));
  const [pickerOpen, setPickerOpen] = useState(false);
  const [message, setMessage] = useState('');

  const screens = useRef(new Map<string, Screen>());
  /** The backend session behind each tab, set once `terminal_open` returns. */
  const sessions = useRef(new Map<string, number>());
  /** Bumped on every (re)connect, so a previous session's late events are dropped. */
  const generations = useRef(new Map<string, number>());
  /**
   * The prompt waiting in each tab, kept outside React's state so an answer
   * (or a dialog closing) acts on exactly that prompt, even before a render.
   */
  const waiting = useRef(new Map<string, number>());
  const tabsRef = useRef(tabs);
  tabsRef.current = tabs;
  const front = useRef({ active, visible: route.page === 'terminal' });
  front.current = { active, visible: route.page === 'terminal' };

  const update = useCallback((key: string, change: (tab: Tab) => Tab) => {
    setTabs((list) => list.map((tab) => (tab.key === key ? change(tab) : tab)));
  }, []);

  const announce = useCallback((text: string | null) => {
    if (text) setMessage(text);
  }, []);

  const onEvent = useCallback(
    (key: string, event: TerminalEvent) => {
      const tab = tabsRef.current.find((item) => item.key === key);
      if (!tab) return;
      if (event.type === 'saved') {
        if (event.error) {
          toast.error(t('terminal.toast.saveFailed'), {
            description: errorMessage(t, new AppError(event.error, '')),
          });
        } else {
          toast.success(
            event.target === 'password'
              ? t('terminal.toast.passwordSaved', { alias: tab.alias })
              : t('terminal.toast.passphraseSaved'),
          );
          void invalidateAll();
        }
        return;
      }
      const inFront = front.current.visible && front.current.active === key;
      if (event.type === 'prompt' && !inFront) {
        toast(t('terminal.toast.waiting', { alias: tab.alias }), {
          action: {
            label: t('terminal.toast.show'),
            onClick: () => {
              setActiveKey(key);
              navigate({ page: 'terminal' });
              update(key, (current) => ({ ...current, promptOpen: current.prompt !== null }));
            },
          },
        });
      }
      if (event.type === 'prompt') waiting.current.set(key, event.prompt.id);
      if (event.type === 'promptClosed' && waiting.current.get(key) === event.id) {
        waiting.current.delete(key);
      }
      if (event.type === 'state') {
        if (event.state.phase !== 'connecting') waiting.current.delete(key);
        if (event.state.phase === 'ended' || event.state.phase === 'failed') {
          sessions.current.delete(key);
        }
        announce(announcement(t, tab, event.state));
      }
      update(key, (current) => applyEvent(current, event, inFront));
    },
    [t, update, announce, navigate],
  );

  const start = useCallback(
    (key: string, alias: string, options: OpenOptions) => {
      const generation = (generations.current.get(key) ?? 0) + 1;
      generations.current.set(key, generation);
      const screen = screens.current.get(key);
      const size = screen?.proposedSize() ?? { cols: 100, rows: 30 };
      const onMessage = (message: TerminalMessage) => {
        if (generations.current.get(key) !== generation) return;
        if (message instanceof ArrayBuffer)
          screens.current.get(key)?.write(new Uint8Array(message));
        else onEvent(key, message);
      };
      api
        .terminalOpen(alias, size, { askPassword: options.askPassword ?? false }, onMessage)
        .then((info) => {
          if (generations.current.get(key) !== generation) {
            void api.terminalClose(info.id);
            return;
          }
          sessions.current.set(key, info.id);
          update(key, (tab) => ({
            ...tab,
            id: info.id,
            // Events may have moved it on already.
            info: { ...info, phase: tab.state.phase },
          }));
        })
        .catch((error: unknown) => {
          if (generations.current.get(key) !== generation) return;
          const failure = { reason: 'openFailed' as const, message: errorMessage(t, error) };
          const appError = AppError.from(error);
          const detail =
            appError.code === 'not_found' || appError.code === 'unsupported'
              ? appError.message
              : failure.message;
          update(key, (tab) => ({
            ...tab,
            state: { phase: 'failed', failure: { ...failure, message: detail } },
          }));
        });
    },
    [onEvent, update, t],
  );

  const ensureScreen = useCallback(
    (key: string) => {
      let screen = screens.current.get(key);
      if (!screen) {
        screen = new Screen({
          onInput: (data) => {
            const id = sessions.current.get(key);
            if (id !== undefined) void api.terminalWrite(id, data).catch(() => undefined);
          },
          onResize: (cols, rows) => {
            update(key, (tab) =>
              tab.cols === cols && tab.rows === rows ? tab : { ...tab, cols, rows },
            );
            const id = sessions.current.get(key);
            if (id !== undefined) void api.terminalResize(id, cols, rows).catch(() => undefined);
          },
          onCycle: (step) => {
            const next = cycle(tabsRef.current, front.current.active, step);
            if (next) setActiveKey(next);
          },
        });
        screens.current.set(key, screen);
      }
      return screen;
    },
    [update],
  );

  const open = useCallback(
    (alias: string, options: OpenOptions = {}) => {
      const tab = newTab(alias);
      ensureScreen(tab.key);
      setTabs((list) => [...list, tab]);
      setActiveKey(tab.key);
      setRecent((list) => {
        const next = rememberRecent(list, alias, Date.now());
        saveRecent(storage, next);
        return next;
      });
      start(tab.key, alias, options);
    },
    [ensureScreen, start],
  );

  const disconnect = useCallback((key: string) => {
    const id = sessions.current.get(key);
    if (id !== undefined) void api.terminalClose(id).catch(() => undefined);
  }, []);

  const reconnect = useCallback(
    (key: string, options: OpenOptions = {}) => {
      const tab = tabsRef.current.find((item) => item.key === key);
      if (!tab) return;
      disconnect(key);
      sessions.current.delete(key);
      waiting.current.delete(key);
      screens.current.get(key)?.write('\r\n\x1b[2m────────\x1b[0m\r\n');
      update(key, (current) => ({
        ...current,
        id: null,
        state: { phase: 'connecting' },
        prompt: null,
        promptOpen: false,
        banner: null,
        keyChanged: false,
      }));
      start(key, tab.alias, options);
      screens.current.get(key)?.focus();
    },
    [disconnect, start, update],
  );

  const close = useCallback(
    (key: string) => {
      disconnect(key);
      sessions.current.delete(key);
      waiting.current.delete(key);
      generations.current.delete(key);
      screens.current.get(key)?.dispose();
      screens.current.delete(key);
      const next = afterClose(tabsRef.current, key, front.current.active);
      setTabs(next.tabs);
      setActiveKey(next.active);
    },
    [disconnect],
  );

  const answer = useCallback(
    (key: string, promptId: number, reply: PromptAnswer) => {
      const id = sessions.current.get(key);
      // Answered already, or replaced by the next prompt meanwhile.
      if (waiting.current.get(key) !== promptId || id === undefined) return;
      waiting.current.delete(key);
      update(key, (current) =>
        current.prompt?.id === promptId ? { ...current, prompt: null, promptOpen: false } : current,
      );
      void api.terminalAnswer(id, promptId, reply).catch(() => undefined);
    },
    [update],
  );

  // The provider lives as long as the page; when the page reloads, the
  // backend ends the sessions (their channels are gone).

  const value = useMemo<TerminalsValue>(
    () => ({
      tabs,
      active,
      setActive: setActiveKey,
      open,
      reconnect,
      close,
      disconnect,
      answer,
      setPromptOpen: (key, open) =>
        update(key, (tab) => ({ ...tab, promptOpen: open && tab.prompt !== null })),
      dismissBanner: (key) => update(key, (tab) => ({ ...tab, banner: null })),
      dismissKeyChanged: (key) => update(key, (tab) => ({ ...tab, keyChanged: false })),
      cycle: (step) => {
        const next = cycle(tabs, active, step);
        if (next) setActiveKey(next);
      },
      screen: (key) => screens.current.get(key),
      recent,
      pickerOpen,
      setPickerOpen,
    }),
    [tabs, active, open, reconnect, close, disconnect, answer, update, recent, pickerOpen],
  );

  return (
    <TerminalsContext value={value}>
      {children}
      <div aria-live="polite" className="sr-only">
        {message}
      </div>
    </TerminalsContext>
  );
}

export function useTerminals(): TerminalsValue {
  const value = use(TerminalsContext);
  if (!value) throw new Error('useTerminals must be used inside <TerminalProvider>');
  return value;
}

/** How many session tabs there are, how many run and how many are signed in. */
export function useSessionCounts(): { tabs: number; live: number; connected: number } {
  const { tabs } = useTerminals();
  return {
    tabs: tabs.length,
    live: tabs.filter(isLive).length,
    connected: tabs.filter((tab) => tab.state.phase === 'connected').length,
  };
}
