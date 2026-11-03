import { Plus, X } from 'lucide-react';
import { type KeyboardEvent, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { Tooltip } from '@/components/ui/Tooltip';
import { cn } from '@/lib/cn';
import { platform } from '@/lib/platform';
import type { Tab } from './model';

/** The 7 px dot that says where a session is; always paired with text. */
export function StatusDot({ tab, className }: { tab: Tab; className?: string }) {
  const waiting = tab.state.phase === 'connecting';
  return (
    <span
      aria-hidden="true"
      className={cn(
        'size-[7px] shrink-0 rounded-full',
        tab.state.phase === 'connected' && 'bg-online',
        waiting && 'animate-pulse-dot bg-warning',
        tab.state.phase === 'ended' && 'bg-faint',
        tab.state.phase === 'failed' && 'bg-critical-solid',
        className,
      )}
    />
  );
}

export const tabId = (key: string) => `session-tab-${key}`;
export const panelId = (key: string) => `session-panel-${key}`;

interface SessionTabsProps {
  tabs: Tab[];
  active: string | null;
  onSelect: (key: string) => void;
  /** Asks first when the session is live. */
  onClose: (key: string) => void;
  onNew: () => void;
  /** The state each tab's name is read with, e.g. "connected". */
  describe: (tab: Tab) => string;
}

/** Pill tabs, one per session; the bar wraps when full. */
export function SessionTabs({
  tabs,
  active,
  onSelect,
  onClose,
  onNew,
  describe,
}: SessionTabsProps) {
  const { t } = useTranslation();
  const list = useRef<HTMLDivElement>(null);

  const focusTab = (key: string) => {
    onSelect(key);
    list.current?.querySelector<HTMLElement>(`#${CSS.escape(tabId(key))}`)?.focus();
  };

  const onKeyDown = (event: KeyboardEvent, tab: Tab, index: number) => {
    const move = (to: number) => {
      const next = tabs[(to + tabs.length) % tabs.length];
      if (next) focusTab(next.key);
    };
    const closeKey =
      event.key === 'Delete' ||
      event.key === 'Backspace' ||
      (event.key.toLowerCase() === 'w' && (platform === 'macos' ? event.metaKey : event.ctrlKey));
    if (event.key === 'ArrowRight') move(index + 1);
    else if (event.key === 'ArrowLeft') move(index - 1);
    else if (event.key === 'Home') move(0);
    else if (event.key === 'End') move(tabs.length - 1);
    else if (closeKey) onClose(tab.key);
    else return;
    event.preventDefault();
  };

  return (
    <div className="flex flex-wrap items-center gap-1 border-b border-terminal-line bg-terminal-bar px-2 py-1.5">
      <div
        ref={list}
        role="tablist"
        aria-label={t('terminal.tabs')}
        className="flex min-w-0 flex-wrap items-center gap-1"
      >
        {tabs.map((tab, index) => {
          const selected = tab.key === active;
          const name = (
            <button
              type="button"
              role="tab"
              id={tabId(tab.key)}
              aria-selected={selected}
              // Only the selected tab's panel exists.
              aria-controls={selected ? panelId(tab.key) : undefined}
              aria-keyshortcuts="Delete"
              aria-label={`${tab.alias}, ${describe(tab)}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onSelect(tab.key)}
              onKeyDown={(event) => onKeyDown(event, tab, index)}
              className="inline-flex h-full min-w-0 items-center gap-2 rounded-l-[8px] pr-1 pl-2.5 font-mono text-[12.5px] outline-offset-[-2px]"
            >
              <StatusDot tab={tab} />
              <span className="max-w-[180px] truncate">{tab.alias}</span>
            </button>
          );
          return (
            <div
              key={tab.key}
              className={cn(
                'inline-flex h-[30px] max-w-full items-center rounded-[9px] border transition-[background-color,border-color] duration-[120ms] ease-out',
                selected
                  ? 'border-[rgb(74_222_128/0.45)] bg-[rgb(74_222_128/0.13)] text-[#dcfce7]'
                  : 'border-transparent text-muted hover:bg-white/[0.05]',
              )}
            >
              {tab.alias.length > 22 ? <Tooltip content={tab.alias}>{name}</Tooltip> : name}
              <button
                type="button"
                tabIndex={-1}
                aria-label={t('terminal.closeSession', { alias: tab.alias })}
                onClick={() => onClose(tab.key)}
                className={cn(
                  'pressable mr-1 grid size-[22px] shrink-0 place-items-center rounded-md hover:bg-white/[0.08]',
                  selected ? 'text-[#86efac]' : 'text-subtle',
                )}
              >
                <X aria-hidden="true" className="size-3.5" strokeWidth={2.2} />
              </button>
            </div>
          );
        })}
      </div>
      <Tooltip
        content={t('terminal.newSession')}
        shortcut={platform === 'macos' ? '⌘T' : 'Ctrl+Shift+T'}
      >
        <button
          type="button"
          aria-label={t('terminal.newSession')}
          onClick={onNew}
          className="pressable ml-0.5 grid size-7 place-items-center rounded-lg text-muted hover:bg-white/[0.06] hover:text-fg"
        >
          <Plus aria-hidden="true" className="size-4" strokeWidth={2} />
        </button>
      </Tooltip>
    </div>
  );
}
