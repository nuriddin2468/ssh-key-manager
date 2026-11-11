import { type KeyboardEvent, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/cn';

export type EnvsView = 'envs' | 'files';

const VIEWS: EnvsView[] = ['envs', 'files'];

/** The id of a view's panel, for `aria-controls`. */
export const viewPanelId = (view: EnvsView) => `envs-view-${view}`;

interface ViewTabsProps {
  view: EnvsView;
  onChange: (view: EnvsView) => void;
  /** Files that need the user, shown on the Files tab. */
  attention?: number;
}

/**
 * The Environments page's two views, as tabs: the environments and their
 * variables, and the files they are written to. Arrow keys move between
 * them, as in any tab list.
 */
export function ViewTabs({ view, onChange, attention = 0 }: ViewTabsProps) {
  const { t } = useTranslation();
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = VIEWS.indexOf(view);
    const next =
      event.key === 'ArrowRight'
        ? (index + 1) % VIEWS.length
        : event.key === 'ArrowLeft'
          ? (index - 1 + VIEWS.length) % VIEWS.length
          : event.key === 'Home'
            ? 0
            : event.key === 'End'
              ? VIEWS.length - 1
              : null;
    if (next === null) return;
    event.preventDefault();
    const target = VIEWS[next];
    if (!target) return;
    onChange(target);
    tabs.current[next]?.focus();
  };
  return (
    <div
      role="tablist"
      aria-label={t('envs.views.label')}
      onKeyDown={onKeyDown}
      className="flex h-[30px] items-center rounded-[10px] border border-white/[0.08] bg-white/[0.04] p-[3px]"
    >
      {VIEWS.map((item, index) => {
        const selected = item === view;
        return (
          <button
            key={item}
            ref={(node) => {
              tabs.current[index] = node;
            }}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={selected ? viewPanelId(item) : undefined}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(item)}
            className={cn(
              'pressable inline-flex h-6 items-center gap-1.5 rounded-[7px] px-2.5 text-[12.5px] font-medium',
              selected ? 'bg-white/[0.11] text-fg shadow-sm' : 'text-muted hover:text-fg-2',
            )}
          >
            {t(`envs.views.${item}`)}
            {item === 'files' && attention > 0 ? (
              <>
                <span
                  aria-hidden="true"
                  className="grid h-4 min-w-4 place-items-center rounded-full bg-warning-solid/20 px-1 text-[10.5px] font-semibold text-warning tabular-nums"
                >
                  {attention}
                </span>
                <span className="sr-only">{t('envs.views.attention', { count: attention })}</span>
              </>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}
