import { Check, Minus } from 'lucide-react';
import { Checkbox as RCheckbox } from 'radix-ui';
import { type ComponentProps, type ReactNode, useId } from 'react';
import { cn } from '@/lib/cn';

/**
 * The bare box, in the section's accent like the switch, for tables and other
 * places that label it with `aria-label`. `checked` may be `'indeterminate'`
 * for a "select all" box. The hit area reaches 24 px.
 */
export function CheckboxControl({
  className,
  checked,
  ...props
}: ComponentProps<typeof RCheckbox.Root>) {
  return (
    <RCheckbox.Root
      checked={checked}
      className={cn(
        'pressable relative grid size-[18px] shrink-0 place-items-center rounded-[5px] border border-line-control bg-ink/[0.05] text-[var(--accent-ink)] after:absolute after:-inset-[3px] disabled:opacity-50',
        'data-[state=checked]:border-transparent data-[state=checked]:bg-[linear-gradient(135deg,var(--accent-1),var(--accent-2))]',
        'data-[state=indeterminate]:border-transparent data-[state=indeterminate]:bg-[linear-gradient(135deg,var(--accent-1),var(--accent-2))]',
        className,
      )}
      {...props}
    >
      <RCheckbox.Indicator>
        {checked === 'indeterminate' ? (
          <Minus aria-hidden="true" className="size-3" strokeWidth={3} />
        ) : (
          <Check aria-hidden="true" className="size-3.5" strokeWidth={3} />
        )}
      </RCheckbox.Indicator>
    </RCheckbox.Root>
  );
}

interface CheckboxProps {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  label: ReactNode;
  /** Replaces the visible label as the accessible name, e.g. for `a–z`. */
  'aria-label'?: string;
  disabled?: boolean;
  className?: string;
}

/** A checkbox with its label; the whole row toggles it. */
export function Checkbox({
  checked,
  onCheckedChange,
  label,
  'aria-label': ariaLabel,
  disabled,
  className,
}: CheckboxProps) {
  const id = useId();
  return (
    <div className={cn('flex items-start gap-2.5', disabled && 'opacity-50', className)}>
      <CheckboxControl
        id={id}
        checked={checked}
        onCheckedChange={(next) => onCheckedChange(next === true)}
        disabled={disabled}
        aria-label={ariaLabel}
        className="mt-0.5"
      />
      <label htmlFor={id} className="min-w-0 flex-1 leading-[22px] font-medium text-fg">
        {label}
      </label>
    </div>
  );
}
