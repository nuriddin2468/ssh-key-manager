import { Search } from 'lucide-react';
import {
  type KeyboardEvent,
  type ReactNode,
  type Ref,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { Kbd } from '@/components/ui/Kbd';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import type { PaletteItem } from './items';
import type { Section } from './sections';

/** Rows PageUp and PageDown move by. */
const PAGE = 8;

interface PaletteSearchProps {
  query: string;
  onQueryChange: (query: string) => void;
  sections: readonly Section[];
  onRun: (item: PaletteItem) => void;
  placeholder: string;
  /** Instead of the list when it is empty. */
  empty: ReactNode;
  /** The prefixes the footer explains. */
  prefixes: readonly ('>' | '@' | '#')[];
  /** An item that is running: its row shows a spinner. */
  busy?: string | null;
  /** Above the footer: what went wrong with the last item run. */
  notice?: ReactNode;
  inputRef?: Ref<HTMLInputElement>;
  className?: string;
}

const PREFIX_LABEL = {
  '>': 'palette.hints.actions',
  '@': 'palette.hints.hosts',
  '#': 'palette.hints.passwords',
} as const;

/**
 * A search field over a list of actions, keyboard first: the field is a
 * combobox that keeps the focus, the arrow keys move through the listbox
 * (`aria-activedescendant`) and Enter runs the highlighted row.
 */
export function PaletteSearch({
  query,
  onQueryChange,
  sections,
  onRun,
  placeholder,
  empty,
  prefixes,
  busy,
  notice,
  inputRef,
  className,
}: PaletteSearchProps) {
  const { t } = useTranslation();
  const listId = useId();
  const statusId = useId();
  const rows = useMemo(() => sections.flatMap((section) => section.items), [sections]);
  const [active, setActive] = useState(0);
  const list = useRef<HTMLDivElement>(null);
  const current = rows[Math.min(active, rows.length - 1)];
  const optionId = (index: number) => `${listId}-${index}`;
  const activeIndex = current ? rows.indexOf(current) : -1;

  // A new query starts at the best match.
  useEffect(() => {
    void query;
    setActive(0);
  }, [query]);

  useEffect(() => {
    if (activeIndex < 0) return;
    list.current
      ?.querySelector(`[id="${CSS.escape(optionId(activeIndex))}"]`)
      ?.scrollIntoView({ block: 'nearest' });
  });

  const move = (to: number) => {
    if (rows.length === 0) return;
    setActive(((to % rows.length) + rows.length) % rows.length);
  };
  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.nativeEvent.isComposing) return;
    if (event.key === 'ArrowDown') move(activeIndex + 1);
    else if (event.key === 'ArrowUp') move(activeIndex - 1);
    else if (event.key === 'PageDown') setActive(Math.min(activeIndex + PAGE, rows.length - 1));
    else if (event.key === 'PageUp') setActive(Math.max(activeIndex - PAGE, 0));
    else if (event.key === 'Enter' && current) onRun(current.item);
    else return;
    event.preventDefault();
  };

  let index = -1;
  return (
    <div className={cn('flex min-h-0 flex-col', className)}>
      <div className="flex h-[52px] shrink-0 items-center gap-3 border-b border-white/[0.07] px-4">
        <Search aria-hidden="true" className="size-[18px] shrink-0 text-subtle" strokeWidth={2} />
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          aria-label={t('palette.search')}
          aria-autocomplete="list"
          aria-expanded={rows.length > 0}
          aria-controls={listId}
          aria-activedescendant={activeIndex >= 0 ? optionId(activeIndex) : undefined}
          aria-describedby={statusId}
          value={query}
          onChange={(event) => onQueryChange(event.target.value)}
          onKeyDown={onKeyDown}
          placeholder={placeholder}
          spellCheck={false}
          autoComplete="off"
          autoCorrect="off"
          autoCapitalize="off"
          className="h-full min-w-0 flex-1 bg-transparent text-[15px] text-fg outline-none"
        />
        <Kbd className="shrink-0">esc</Kbd>
      </div>

      {rows.length > 0 ? (
        <div
          ref={list}
          id={listId}
          role="listbox"
          aria-label={t('palette.results')}
          className="flex min-h-0 flex-1 flex-col overflow-y-auto p-1.5"
        >
          {sections.map((section) => {
            const headingId = `${listId}-${section.id}`;
            const options = section.items.map((ranked) => {
              index += 1;
              const at = index;
              return (
                <Row
                  key={ranked.item.id}
                  id={optionId(at)}
                  item={ranked.item}
                  positions={ranked.positions}
                  active={at === activeIndex}
                  busy={busy === ranked.item.id}
                  onHover={() => setActive(at)}
                  onRun={() => onRun(ranked.item)}
                />
              );
            });
            return section.label ? (
              // A fieldset is a group, which a listbox may hold around its options.
              <fieldset
                key={section.id}
                aria-labelledby={headingId}
                className="m-0 flex min-w-0 flex-col border-0 p-0 pb-1"
              >
                <div
                  id={headingId}
                  role="presentation"
                  className="px-2.5 pt-2 pb-1 text-[11.5px] font-semibold text-subtle"
                >
                  {section.label}
                </div>
                {options}
              </fieldset>
            ) : (
              <div key={section.id} role="presentation" className="flex flex-col">
                {options}
              </div>
            );
          })}
        </div>
      ) : (
        <div className="flex flex-1 items-center justify-center px-6 py-8 text-center text-[12.5px] text-muted">
          {empty}
        </div>
      )}

      {notice ? (
        <p role="alert" className="shrink-0 px-4 pb-2 text-[12.5px] text-critical">
          {notice}
        </p>
      ) : null}

      <p id={statusId} role="status" className="sr-only">
        {t('palette.count', { count: rows.length })}
      </p>

      <footer className="flex h-9 shrink-0 items-center gap-3.5 border-t border-white/[0.07] px-4 text-[11.5px] text-subtle">
        <span className="flex items-center gap-1.5">
          <Kbd>↑</Kbd>
          <Kbd>↓</Kbd>
          {t('palette.hints.move')}
        </span>
        <span className="flex items-center gap-1.5">
          <Kbd>↵</Kbd>
          {t('palette.hints.run')}
        </span>
        <span className="ml-auto flex items-center gap-3">
          {prefixes.map((prefix) => (
            <span key={prefix} className="flex items-center gap-1.5">
              <Kbd>{prefix}</Kbd>
              {t(PREFIX_LABEL[prefix])}
            </span>
          ))}
        </span>
      </footer>
    </div>
  );
}

interface RowProps {
  id: string;
  item: PaletteItem;
  positions: readonly number[];
  active: boolean;
  busy: boolean;
  onHover: () => void;
  onRun: () => void;
}

function Row({ id, item, positions, active, busy, onHover, onRun }: RowProps) {
  const Icon = item.icon;
  return (
    // biome-ignore lint/a11y/useKeyWithClickEvents: the search field takes the keys (aria-activedescendant)
    <div
      id={id}
      role="option"
      aria-selected={active}
      aria-busy={busy || undefined}
      // Its parts, read apart: their text alone would run together.
      aria-label={[item.title, item.detail, item.action, item.shortcut].filter(Boolean).join(', ')}
      tabIndex={-1}
      // Not on enter: rows scrolled under a still pointer would take the highlight.
      onMouseMove={active ? undefined : onHover}
      onClick={onRun}
      className={cn(
        'flex h-10 min-w-0 shrink-0 items-center gap-2.5 rounded-[10px] px-2.5',
        active ? 'selected-row' : 'hover:bg-white/[0.04]',
      )}
    >
      <Tile tone={item.tone} size={26}>
        <Icon className="size-[14px]" strokeWidth={2} />
      </Tile>
      <span className="flex min-w-0 flex-1 items-baseline gap-2">
        <span className="truncate text-fg">
          <Highlighted text={item.title} positions={positions} />
        </span>
        {item.detail ? (
          <span className="min-w-0 truncate text-[12px] text-subtle">{item.detail}</span>
        ) : null}
      </span>
      <span className="flex shrink-0 items-center gap-2 text-[12px] text-muted">
        {busy ? <Spinner className="size-3.5" /> : null}
        {item.action}
        {item.shortcut ? <Kbd>{item.shortcut}</Kbd> : null}
      </span>
    </div>
  );
}

/** The matched characters in the accent colour. */
function Highlighted({ text, positions }: { text: string; positions: readonly number[] }) {
  if (positions.length === 0) return text;
  const marked = new Set(positions);
  const parts: { text: string; mark: boolean }[] = [];
  for (let at = 0; at < text.length; at += 1) {
    const mark = marked.has(at);
    const last = parts.at(-1);
    if (last && last.mark === mark) last.text += text[at];
    else parts.push({ text: text[at] ?? '', mark });
  }
  return parts.map((part, at) =>
    part.mark ? (
      // biome-ignore lint/suspicious/noArrayIndexKey: the parts of one fixed text
      <span key={at} className="font-semibold text-[var(--accent-text)]">
        {part.text}
      </span>
    ) : (
      // biome-ignore lint/suspicious/noArrayIndexKey: the parts of one fixed text
      <span key={at}>{part.text}</span>
    ),
  );
}
