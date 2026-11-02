import { Check, ChevronDown, ChevronUp } from 'lucide-react';
import { Select as RSelect } from 'radix-ui';
import { type ReactNode, useId } from 'react';
import { cn } from '@/lib/cn';

export interface SelectOption {
  value: string;
  label: ReactNode;
  /** Shown after the label in the list only, e.g. a key type. */
  hint?: ReactNode;
  icon?: ReactNode;
  disabled?: boolean;
}

interface SelectProps {
  value: string;
  onValueChange: (value: string) => void;
  options: readonly SelectOption[];
  label?: ReactNode;
  hint?: ReactNode;
  /** Leading icon in the field when the selected option has none. */
  icon?: ReactNode;
  mono?: boolean;
  size?: 'sm' | 'md';
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  'aria-label'?: string;
}

/**
 * A select with the app's own field and dropdown. Built on Radix, so it keeps
 * native keyboard behaviour (arrows, type-ahead, Escape) and screen-reader
 * semantics.
 */
export function Select({
  value,
  onValueChange,
  options,
  label,
  hint,
  icon,
  mono = false,
  size = 'md',
  placeholder,
  disabled,
  className,
  'aria-label': ariaLabel,
}: SelectProps) {
  const id = useId();
  const selected = options.find((option) => option.value === value);
  const leading = selected?.icon ?? icon;

  const field = (
    <RSelect.Root value={value} onValueChange={onValueChange} disabled={disabled}>
      <RSelect.Trigger
        id={id}
        aria-label={ariaLabel}
        aria-describedby={hint ? `${id}-hint` : undefined}
        className={cn(
          'field pressable-soft group flex w-full min-w-0 items-center gap-2 text-left text-fg outline-none',
          'hover:bg-white/[0.07] focus-visible:border-[rgb(var(--accent-rgb)/0.55)] focus-visible:shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.15)]',
          'data-[state=open]:border-[rgb(var(--accent-rgb)/0.55)] data-[state=open]:bg-white/[0.07] disabled:opacity-50',
          size === 'md' ? 'h-9 rounded-[10px] px-[11px]' : 'h-8 rounded-[9px] px-2.5 text-[12.5px]',
          mono && 'font-mono text-[12.5px]',
          !label && className,
        )}
      >
        {leading ? <span className="flex shrink-0 items-center">{leading}</span> : null}
        <span className="min-w-0 flex-1 truncate">
          <RSelect.Value placeholder={placeholder} />
        </span>
        <RSelect.Icon asChild>
          <ChevronDown
            aria-hidden="true"
            className="size-[15px] shrink-0 text-subtle transition-transform duration-200 group-data-[state=open]:rotate-180"
            strokeWidth={1.8}
          />
        </RSelect.Icon>
      </RSelect.Trigger>

      <RSelect.Portal>
        <RSelect.Content
          position="popper"
          sideOffset={6}
          collisionPadding={12}
          className={cn(
            'z-50 max-h-[min(320px,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-xl border border-white/10',
            'bg-[rgb(22_27_39/0.96)] text-[13px] text-fg shadow-[0_24px_48px_-16px_rgb(0_0_0/0.75),inset_0_1px_0_rgb(255_255_255/0.06)]',
            'origin-[var(--radix-select-content-transform-origin)] data-[state=closed]:pointer-events-none data-[state=closed]:animate-popover-out data-[state=open]:animate-popover-in',
          )}
        >
          <RSelect.ScrollUpButton className="flex h-6 items-center justify-center text-subtle">
            <ChevronUp aria-hidden="true" className="size-4" />
          </RSelect.ScrollUpButton>
          <RSelect.Viewport className="p-1">
            {options.map((option) => (
              <RSelect.Item
                key={option.value}
                value={option.value}
                disabled={option.disabled}
                className={cn(
                  'relative flex h-8 cursor-default items-center gap-2.5 rounded-lg pr-8 pl-2.5 outline-none select-none',
                  'transition-colors duration-100 data-[highlighted]:bg-white/[0.08] active:bg-white/[0.12]',
                  'data-[state=checked]:text-[var(--accent-text)] data-[disabled]:opacity-40',
                  mono && 'font-mono text-[12.5px]',
                )}
              >
                {option.icon ? (
                  <span className="flex shrink-0 items-center">{option.icon}</span>
                ) : null}
                <RSelect.ItemText>{option.label}</RSelect.ItemText>
                {option.hint ? (
                  <span className="ml-auto pl-4 font-sans text-[11.5px] text-subtle">
                    {option.hint}
                  </span>
                ) : null}
                <RSelect.ItemIndicator className="absolute right-2.5 flex items-center">
                  <Check aria-hidden="true" className="size-3.5" strokeWidth={2.5} />
                </RSelect.ItemIndicator>
              </RSelect.Item>
            ))}
          </RSelect.Viewport>
          <RSelect.ScrollDownButton className="flex h-6 items-center justify-center text-subtle">
            <ChevronDown aria-hidden="true" className="size-4" />
          </RSelect.ScrollDownButton>
        </RSelect.Content>
      </RSelect.Portal>
    </RSelect.Root>
  );

  if (!label) return field;
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label htmlFor={id} className="text-[12px] font-semibold text-fg-2">
        {label}
      </label>
      {field}
      {hint ? (
        <p id={`${id}-hint`} className="text-[12px] text-subtle">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
