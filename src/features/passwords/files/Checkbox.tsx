import { Check, Minus } from 'lucide-react';
import { Checkbox as RCheckbox } from 'radix-ui';
import type { ComponentProps } from 'react';
import { cn } from '@/lib/cn';

/**
 * A checkbox in the section's accent, like the switch. `checked` may be
 * `'indeterminate'` for a "select all" box. The hit area reaches 24 px.
 */
export function Checkbox({ className, checked, ...props }: ComponentProps<typeof RCheckbox.Root>) {
  return (
    <RCheckbox.Root
      checked={checked}
      className={cn(
        'pressable relative grid size-[18px] shrink-0 place-items-center rounded-[5px] border border-white/40 bg-white/[0.05] text-[var(--accent-ink)] after:absolute after:-inset-[3px] disabled:opacity-50',
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
          <Check aria-hidden="true" className="size-3" strokeWidth={3} />
        )}
      </RCheckbox.Indicator>
    </RCheckbox.Root>
  );
}
