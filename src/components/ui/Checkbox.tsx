import { Check } from 'lucide-react';
import { Checkbox as RCheckbox } from 'radix-ui';
import { type ReactNode, useId } from 'react';
import { cn } from '@/lib/cn';

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
      <RCheckbox.Root
        id={id}
        checked={checked}
        onCheckedChange={(next) => onCheckedChange(next === true)}
        disabled={disabled}
        aria-label={ariaLabel}
        className={cn(
          'pressable mt-0.5 grid size-[18px] shrink-0 place-items-center rounded-[5px] border',
          'border-white/25 bg-white/[0.06] data-[state=checked]:border-transparent',
          'data-[state=checked]:bg-[linear-gradient(135deg,var(--accent-1),var(--accent-2))] data-[state=checked]:text-[var(--accent-ink)]',
        )}
      >
        <RCheckbox.Indicator>
          <Check aria-hidden="true" className="size-3.5" strokeWidth={3} />
        </RCheckbox.Indicator>
      </RCheckbox.Root>
      <label htmlFor={id} className="min-w-0 flex-1 leading-[22px] font-medium text-fg">
        {label}
      </label>
    </div>
  );
}
