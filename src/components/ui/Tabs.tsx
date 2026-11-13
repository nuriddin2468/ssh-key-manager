import { type KeyboardEvent, type ReactNode, useRef } from 'react';
import { cn } from '@/lib/cn';

export interface TabItem<T extends string> {
  value: T;
  label: string;
  /** A count next to the label, e.g. unread messages; hidden when 0. */
  count?: number;
  /** What the count means, for screen readers ("3 unread"). */
  countLabel?: string;
}

interface TabsProps<T extends string> {
  /** Names the tab list for screen readers. */
  label: string;
  tabs: TabItem<T>[];
  value: T;
  onChange: (value: T) => void;
  /** The id of a tab's panel, for `aria-controls`. */
  panelId: (value: T) => string;
}

/**
 * A page's views as a segmented tab list in its toolbar (as Environments
 * has them): arrow keys, Home and End move between the tabs.
 */
export function Tabs<T extends string>({ label, tabs, value, onChange, panelId }: TabsProps<T>) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = tabs.findIndex((tab) => tab.value === value);
    const last = tabs.length - 1;
    const next =
      event.key === 'ArrowRight'
        ? index === last
          ? 0
          : index + 1
        : event.key === 'ArrowLeft'
          ? index === 0
            ? last
            : index - 1
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? last
              : null;
    const target = next === null ? undefined : tabs[next];
    if (next === null || !target) return;
    event.preventDefault();
    onChange(target.value);
    refs.current[next]?.focus();
  };
  return (
    <div
      role="tablist"
      aria-label={label}
      onKeyDown={onKeyDown}
      className="flex h-[30px] items-center rounded-[10px] border border-line bg-ink/[0.04] p-[3px]"
    >
      {tabs.map((tab, index) => {
        const selected = tab.value === value;
        return (
          <button
            key={tab.value}
            ref={(node) => {
              refs.current[index] = node;
            }}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={selected ? panelId(tab.value) : undefined}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.value)}
            className={cn(
              'pressable inline-flex h-6 items-center gap-1.5 rounded-[7px] px-2.5 text-[12.5px] font-medium',
              selected ? 'bg-ink/[0.11] text-fg shadow-sm' : 'text-muted hover:text-fg-2',
            )}
          >
            {tab.label}
            {tab.count ? <Count count={tab.count} label={tab.countLabel} /> : null}
          </button>
        );
      })}
    </div>
  );
}

function Count({ count, label }: { count: number; label?: string }): ReactNode {
  return (
    <>
      <span
        aria-hidden="true"
        className="grid h-4 min-w-4 place-items-center rounded-full bg-[rgb(var(--accent-rgb)/0.2)] px-1 text-[10.5px] font-semibold text-[var(--accent-text)] tabular-nums"
      >
        {count}
      </span>
      {label ? <span className="sr-only">{label}</span> : null}
    </>
  );
}
