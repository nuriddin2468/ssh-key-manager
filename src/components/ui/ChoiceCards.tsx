import { RadioGroup } from 'radix-ui';
import {
  type ComponentType,
  type CSSProperties,
  type KeyboardEvent,
  type ReactNode,
  useId,
} from 'react';
import { cn } from '@/lib/cn';
import { Tile, type Tone } from './Tile';

/** Icons drawn inside a card's tile; lucide icons fit. */
export type ChoiceIcon = ComponentType<{ className?: string; strokeWidth?: number }>;

export interface ChoiceOption<T extends string> {
  value: T;
  title: ReactNode;
  /** One line under the title; wraps, never truncates. */
  hint?: ReactNode;
  /** The tile's gradient; without `tone` and `icon` the card shows a radio dot. */
  tone?: Tone;
  icon?: ChoiceIcon;
  disabled?: boolean;
}

interface ChoiceCardsProps<T extends string> {
  /** Names the group (a `legend`); `legendHidden` keeps it for screen readers only. */
  legend: ReactNode;
  legendHidden?: boolean;
  value: T;
  onValueChange: (value: T) => void;
  options: readonly ChoiceOption<T>[];
  /** Cards per row; all in one row by default. */
  columns?: number;
  /**
   * `row`: tile beside the text (compact, the default).
   * `stack`: a larger tile above the text, for two or three big choices.
   */
  layout?: 'row' | 'stack';
  /** A soft accent glow under the selected card. */
  glow?: boolean;
  className?: string;
}

const LAYOUT = {
  row: {
    card: 'items-start gap-2.5 p-2.5',
    tile: 30,
    icon: 'size-[15px]',
    text: '',
    hint: 'text-[11.5px] leading-4',
  },
  stack: {
    card: 'flex-col items-start gap-2.5 p-[13px]',
    tile: 36,
    icon: 'size-[18px]',
    text: 'gap-0.5',
    hint: 'text-[12px] leading-[17px]',
  },
} as const;

/**
 * One choice out of a few, as cards: a Radix radio group inside a
 * `fieldset`, so arrow keys move between the cards (and select), Space and
 * Enter select, and screen readers hear a labelled radio group.
 */
export function ChoiceCards<T extends string>({
  legend,
  legendHidden = false,
  value,
  onValueChange,
  options,
  columns = options.length,
  layout = 'row',
  glow = false,
  className,
}: ChoiceCardsProps<T>) {
  const id = useId();
  const sizes = LAYOUT[layout];
  return (
    <RadioGroup.Root
      asChild
      value={value}
      onValueChange={(next) => onValueChange(next as T)}
      aria-labelledby={`${id}-legend`}
    >
      <fieldset className={cn('m-0 flex min-w-0 flex-col border-0 p-0', className)}>
        <legend
          id={`${id}-legend`}
          className={cn(
            'p-0',
            legendHidden
              ? 'sr-only'
              : 'mb-2.5 text-[12px] font-semibold tracking-[0.02em] text-subtle',
          )}
        >
          {legend}
        </legend>
        {/* Narrower than 26rem, the cards stack, so words never break inside. */}
        <div className="@container">
          <div
            className="grid grid-cols-1 gap-2.5 @[26rem]:grid-cols-[repeat(var(--choice-columns),minmax(0,1fr))]"
            style={{ '--choice-columns': Math.max(1, columns) } as CSSProperties}
          >
            {options.map((option) => {
              const selected = option.value === value;
              const Icon = option.icon;
              const itemId = `${id}-${option.value}`;
              return (
                <RadioGroup.Item
                  key={option.value}
                  value={option.value}
                  disabled={option.disabled}
                  aria-labelledby={`${itemId}-title`}
                  aria-describedby={option.hint ? `${itemId}-hint` : undefined}
                  // Radix leaves Enter alone (it would submit the form); here it selects.
                  onKeyDown={(event: KeyboardEvent) => {
                    if (event.key === 'Enter' && !option.disabled) onValueChange(option.value);
                  }}
                  className={cn(
                    'pressable-soft flex min-w-0 rounded-[14px] border text-left disabled:opacity-50',
                    sizes.card,
                    selected
                      ? cn(
                          'border-[rgb(var(--accent-rgb)/0.6)] bg-[rgb(var(--accent-rgb)/0.08)]',
                          glow
                            ? 'shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.14),0_14px_30px_-18px_rgb(var(--accent-rgb)/0.8)]'
                            : 'shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.14)]',
                        )
                      : 'border-ink/[0.09] bg-card-subtle hover:bg-ink/[0.05]',
                  )}
                >
                  {option.tone && Icon ? (
                    <Tile tone={option.tone} size={sizes.tile}>
                      <Icon className={sizes.icon} strokeWidth={2} />
                    </Tile>
                  ) : (
                    <span
                      aria-hidden="true"
                      className="mt-0.5 grid size-4 shrink-0 place-items-center rounded-full border border-ink/25"
                    >
                      <RadioGroup.Indicator className="size-2 rounded-full bg-[var(--accent-text)]" />
                    </span>
                  )}
                  <span className={cn('flex min-w-0 flex-col', sizes.text)}>
                    <span id={`${itemId}-title`} className="font-semibold break-words">
                      {option.title}
                    </span>
                    {option.hint ? (
                      <span id={`${itemId}-hint`} className={cn('text-muted', sizes.hint)}>
                        {option.hint}
                      </span>
                    ) : null}
                  </span>
                </RadioGroup.Item>
              );
            })}
          </div>
        </div>
      </fieldset>
    </RadioGroup.Root>
  );
}
