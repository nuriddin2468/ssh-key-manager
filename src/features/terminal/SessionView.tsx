import { Check, ChevronDown, ChevronUp, Search, X } from 'lucide-react';
import { type KeyboardEvent, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Failure } from '@/bindings/Failure';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import { cn } from '@/lib/cn';
import { formatDuration } from '@/lib/format';
import {
  type FailureView,
  type Fix,
  failureView,
  type OpenFailure,
  signInText,
  statusLine,
  type Tab,
  waitingText,
} from './model';
import { StatusDot } from './SessionTabs';
import type { Screen } from './screen';

interface SessionViewProps {
  tab: Tab;
  screen: Screen | undefined;
  onShowPrompt: () => void;
  onReconnect: (options?: { askPassword?: boolean }) => void;
  onCloseTab: () => void;
  onCompare: () => void;
}

/** The active tab's terminal and whatever covers it while it isn't usable. */
export function SessionView({
  tab,
  screen,
  onShowPrompt,
  onReconnect,
  onCloseTab,
  onCompare,
}: SessionViewProps) {
  const { t, i18n } = useTranslation();
  const host = useRef<HTMLDivElement>(null);
  const label = t('terminal.terminalLabel', { alias: tab.alias });
  const phase = tab.state.phase;

  const labelRef = useRef(label);
  labelRef.current = label;

  // The xterm moves into this tab's area while it shows.
  useEffect(() => {
    const container = host.current;
    if (!screen || !container) return;
    screen.attach(container, labelRef.current);
    return () => screen.detach();
  }, [screen]);

  useEffect(() => {
    screen?.setLabel(label);
  }, [screen, label]);

  // Into the terminal once it signs in; not when its tab is merely shown,
  // so arrow keys in the tab bar keep focus there.
  const previous = useRef(phase);
  useEffect(() => {
    if (phase === 'connected' && previous.current === 'connecting') screen?.focus();
    previous.current = phase;
  }, [phase, screen]);

  return (
    <div className="relative flex min-h-0 flex-1 flex-col">
      <div
        ref={host}
        className={cn(
          'min-h-0 flex-1 px-3 pt-2.5 pb-1 transition-opacity',
          phase === 'ended' && 'opacity-60',
          (phase === 'connecting' || phase === 'failed') && 'invisible',
        )}
      />
      {phase === 'connecting' ? <Connecting tab={tab} onShowPrompt={onShowPrompt} /> : null}
      {tab.state.phase === 'failed' ? (
        <Failed
          tab={tab}
          failure={tab.state.failure}
          onReconnect={onReconnect}
          onCompare={onCompare}
        />
      ) : null}
      {tab.state.phase === 'ended' ? (
        <div className="flex flex-wrap items-center gap-2.5 border-t border-white/[0.06] bg-white/[0.03] px-4 py-3">
          <span className="text-fg-2">
            {[
              t('terminal.ended.title'),
              tab.state.exitCode !== null
                ? t('terminal.ended.exitCode', { code: tab.state.exitCode })
                : null,
              tab.state.durationSecs > 0
                ? formatDuration(tab.state.durationSecs, i18n.language)
                : null,
            ]
              .filter(Boolean)
              .join(' · ')}
          </span>
          <span className="flex-1" />
          <Button variant="primary" size="sm" onClick={() => onReconnect()}>
            {t('terminal.ended.reconnect')}
          </Button>
          <Button size="sm" onClick={onCloseTab}>
            {t('terminal.ended.closeTab')}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

function Connecting({ tab, onShowPrompt }: { tab: Tab; onShowPrompt: () => void }) {
  const { t } = useTranslation();
  return (
    <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-terminal p-6 text-center">
      <span
        aria-hidden="true"
        className="size-7 animate-spin rounded-full border-[3px] border-warning/25 border-t-warning motion-reduce:animate-none"
      />
      <p className="text-[14px] font-semibold">{t('terminal.connecting', { alias: tab.alias })}</p>
      {tab.prompt ? (
        <>
          <p className="max-w-[420px] text-muted">
            {t('terminal.waitingFor', { what: waitingText(t, tab, tab.prompt.ask) })}
          </p>
          <Button onClick={onShowPrompt}>{t('terminal.showPrompt')}</Button>
        </>
      ) : null}
    </div>
  );
}

const FIX_LABELS = {
  enterPassword: 'terminal.failed.enterPassword',
  retry: 'terminal.failed.retry',
  compare: 'terminal.failed.compare',
} as const satisfies Record<Exclude<Fix, 'output'>, string>;

function Failed({
  tab,
  failure,
  onReconnect,
  onCompare,
}: {
  tab: Tab;
  failure: Failure | OpenFailure;
  onReconnect: (options?: { askPassword?: boolean }) => void;
  onCompare: () => void;
}) {
  const { t } = useTranslation();
  const view: FailureView = failureView(t, tab, failure);
  const [outputShown, setOutputShown] = useState(false);
  const output = 'output' in failure ? failure.output : '';
  const run = (fix: Fix) => {
    if (fix === 'enterPassword') onReconnect({ askPassword: true });
    else if (fix === 'retry') onReconnect();
    else if (fix === 'compare') onCompare();
    else setOutputShown((shown) => !shown);
  };
  return (
    <div className="absolute inset-0 overflow-y-auto bg-terminal p-6">
      <div className="mx-auto mt-[8vh] flex max-w-[520px] flex-col gap-3 rounded-[18px] border border-white/[0.07] bg-white/[0.02] p-[18px]">
        <div className="flex items-center gap-2">
          <StatusDot tab={tab} />
          <span className="font-mono">{tab.alias}</span>
        </div>
        <h2 className="text-[14px] font-semibold">{view.title}</h2>
        <p className="text-muted">{view.detail}</p>
        <div className="flex flex-wrap gap-2">
          {view.fixes.map((fix, index) =>
            fix === 'output' ? (
              <Button
                key={fix}
                variant="ghost"
                size="sm"
                aria-expanded={outputShown}
                onClick={() => run(fix)}
                icon={
                  outputShown ? (
                    <ChevronUp aria-hidden="true" className="size-3.5" />
                  ) : (
                    <ChevronDown aria-hidden="true" className="size-3.5" />
                  )
                }
              >
                {t('terminal.failed.output')}
              </Button>
            ) : (
              <Button
                key={fix}
                variant={index === 0 ? (fix === 'compare' ? 'danger' : 'primary') : 'secondary'}
                size="sm"
                className={fix === 'compare' ? 'bg-critical-solid/[0.14] font-semibold' : undefined}
                onClick={() => run(fix)}
              >
                {t(FIX_LABELS[fix])}
              </Button>
            ),
          )}
        </div>
        {outputShown && output ? (
          <pre className="selectable max-h-[240px] overflow-auto rounded-[11px] border border-white/[0.07] bg-black/30 px-3 py-2.5 font-mono text-[12px] leading-[1.55] whitespace-pre-wrap text-fg-2">
            {output}
          </pre>
        ) : null}
      </div>
    </div>
  );
}

/** "Signed in: …", for a few seconds after signing in. */
export function LoginBanner({ tab, onDismiss }: { tab: Tab; onDismiss: () => void }) {
  const { t, i18n } = useTranslation();
  const signIn = tab.banner;
  useEffect(() => {
    if (!signIn) return;
    const timer = setTimeout(onDismiss, 8000);
    return () => clearTimeout(timer);
  }, [signIn, onDismiss]);
  if (!signIn) return null;
  return (
    <div
      role="status"
      className="mx-3 mt-2.5 flex animate-fade-in items-center gap-2.5 rounded-[11px] border border-[rgb(74_222_128/0.22)] bg-[rgb(74_222_128/0.08)] px-3 py-2 text-[var(--accent-text)]"
    >
      <Check aria-hidden="true" className="size-[15px] shrink-0 text-online" strokeWidth={2.4} />
      <span className="min-w-0 flex-1">{signInText(t, signIn, i18n.language)}</span>
      <button
        type="button"
        aria-label={t('terminal.banner.dismiss')}
        onClick={onDismiss}
        className="pressable grid size-6 shrink-0 place-items-center rounded-md text-[#86efac] hover:bg-white/[0.06]"
      >
        <X aria-hidden="true" className="size-3.5" strokeWidth={2.2} />
      </button>
    </div>
  );
}

interface StatusBarProps {
  tab: Tab;
  onFind: () => void;
  onOpenHost: (() => void) | undefined;
  onDisconnect: () => void;
}

export function StatusBar({ tab, onFind, onOpenHost, onDisconnect }: StatusBarProps) {
  const { t } = useTranslation();
  const live = tab.state.phase === 'connecting' || tab.state.phase === 'connected';
  return (
    <div className="flex min-h-8 flex-wrap items-center gap-x-3.5 gap-y-1 border-t border-white/[0.06] px-3.5 py-1.5 text-[12px] text-subtle">
      <span className="min-w-0 truncate font-mono" title={statusLine(t, tab)}>
        {statusLine(t, tab)}
      </span>
      <span className="ml-auto tabular-nums">
        {t('terminal.status.size', { cols: tab.cols, rows: tab.rows })}
      </span>
      <button
        type="button"
        aria-label={t('terminal.status.findLabel')}
        onClick={onFind}
        disabled={tab.state.phase !== 'connected' && tab.state.phase !== 'ended'}
        className="rounded px-1 text-muted hover:text-fg disabled:opacity-40"
      >
        {t('terminal.status.find')}
      </button>
      {onOpenHost ? (
        <button
          type="button"
          onClick={onOpenHost}
          className="rounded px-1 text-muted hover:text-fg"
        >
          {t('terminal.status.openHost')}
        </button>
      ) : null}
      {live ? (
        <button
          type="button"
          onClick={onDisconnect}
          className="rounded px-1 text-critical hover:text-[#ffbdbd]"
        >
          {t('terminal.status.disconnect')}
        </button>
      ) : null}
    </div>
  );
}

/** xterm's search, over the terminal's top right corner. */
export function FindBar({ screen, onClose }: { screen: Screen; onClose: () => void }) {
  const { t } = useTranslation();
  const [query, setQuery] = useState('');
  const [missing, setMissing] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    input.current?.focus();
    return () => screen.search.clearDecorations();
  }, [screen]);

  const find = (backwards: boolean) => {
    if (!query) return;
    const found = backwards
      ? screen.search.findPrevious(query, { incremental: false })
      : screen.search.findNext(query, { incremental: false });
    setMissing(!found);
  };

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === 'Enter') find(event.shiftKey);
    else if (event.key === 'Escape') {
      onClose();
      screen.focus();
    } else return;
    event.preventDefault();
    event.stopPropagation();
  };

  return (
    <search className="absolute top-2 right-3 z-10 flex items-center gap-1 rounded-[10px] border border-white/10 bg-popover p-1 shadow-xl shadow-black/40">
      <label className="flex items-center gap-1.5 pl-1.5">
        <Search aria-hidden="true" className="size-3.5 text-subtle" />
        <span className="sr-only">{t('terminal.find.placeholder')}</span>
        <input
          ref={input}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setMissing(false);
            if (event.target.value) {
              setMissing(!screen.search.findNext(event.target.value, { incremental: true }));
            }
          }}
          onKeyDown={onKeyDown}
          placeholder={t('terminal.find.placeholder')}
          spellCheck={false}
          className="h-7 w-[180px] bg-transparent text-[12.5px] text-fg outline-none"
        />
      </label>
      <span aria-live="polite" className="px-1 text-[11.5px] text-critical empty:hidden">
        {missing ? t('terminal.find.none') : ''}
      </span>
      <IconButton
        label={t('terminal.find.previous')}
        shortcut="⇧↵"
        icon={<ChevronUp className="size-4" />}
        onClick={() => find(true)}
      />
      <IconButton
        label={t('terminal.find.next')}
        shortcut="↵"
        icon={<ChevronDown className="size-4" />}
        onClick={() => find(false)}
      />
      <IconButton
        label={t('terminal.find.close')}
        icon={<X className="size-4" />}
        onClick={() => {
          onClose();
          screen.focus();
        }}
      />
    </search>
  );
}
