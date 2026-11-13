import { Checkbox as RCheckbox, Switch as RSwitch } from 'radix-ui';
import { type ComponentProps, type ReactNode, useId } from 'react';
import { cn } from '@/lib/cn';

interface SwitchRowProps {
  label: ReactNode;
  hint?: ReactNode;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  disabled?: boolean;
}

/** A label + hint on the left and a switch on the right, like a settings row. */
export function SwitchRow({ label, hint, checked, onCheckedChange, disabled }: SwitchRowProps) {
  const id = useId();
  return (
    <div className="flex items-center gap-3 rounded-[10px] px-2.5 py-[9px]">
      <div className="flex min-w-0 flex-1 flex-col">
        <label htmlFor={id} className="font-medium text-fg">
          {label}
        </label>
        {hint ? (
          <span id={`${id}-hint`} className="text-[12px] text-subtle">
            {hint}
          </span>
        ) : null}
      </div>
      <Switch
        id={id}
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        aria-describedby={hint ? `${id}-hint` : undefined}
      />
    </div>
  );
}

/** The bare switch, for rows that lay out their own label. */
export function Switch({ className, ...props }: ComponentProps<typeof RSwitch.Root>) {
  return (
    <RSwitch.Root
      className={cn(
        'group relative h-[22px] w-[38px] shrink-0 rounded-full shadow-[inset_0_0_0_1px_var(--color-line-strong)] transition-colors duration-150 disabled:opacity-50',
        // Off: an outlined track and a grey knob in the light theme, 3:1 (WCAG 1.4.11).
        'bg-switch-off data-[state=unchecked]:shadow-[inset_0_0_0_1px_var(--color-switch-line)]',
        'data-[state=checked]:bg-[linear-gradient(135deg,var(--accent-1),var(--accent-2))]',
        className,
      )}
      {...props}
    >
      {/* While pressed the knob stretches toward the other side, like macOS. */}
      <RSwitch.Thumb className="block h-4 w-4 translate-x-[3px] rounded-full bg-knob-off shadow-thumb transition-[translate,width] duration-200 ease-[cubic-bezier(0.2,0.8,0.2,1)] group-active:w-5 data-[state=checked]:translate-x-[19px] data-[state=checked]:bg-knob group-active:data-[state=checked]:translate-x-[15px]" />
    </RSwitch.Root>
  );
}

/**
 * A switch for a set of things that may be partly on: `'mixed'` puts the knob
 * in the middle. It is a tri-state checkbox to screen readers ("partly
 * checked"), which a switch can't be.
 */
export function MixedSwitch({
  checked,
  className,
  ...props
}: Omit<ComponentProps<typeof RCheckbox.Root>, 'checked'> & { checked: boolean | 'mixed' }) {
  return (
    <RCheckbox.Root
      checked={checked === 'mixed' ? 'indeterminate' : checked}
      className={cn(
        'group relative h-[22px] w-[38px] shrink-0 rounded-full shadow-[inset_0_0_0_1px_var(--color-line-strong)] transition-colors duration-150 disabled:opacity-50',
        'bg-switch-off data-[state=unchecked]:shadow-[inset_0_0_0_1px_var(--color-switch-line)]',
        'data-[state=checked]:bg-[linear-gradient(135deg,var(--accent-1),var(--accent-2))]',
        'data-[state=indeterminate]:bg-[linear-gradient(90deg,rgb(var(--accent-rgb)/0.55),var(--color-line-strong))]',
        className,
      )}
      {...props}
    >
      <span
        aria-hidden="true"
        className="block h-4 w-4 translate-x-[3px] rounded-full bg-knob-off shadow-thumb transition-[translate,width] duration-200 ease-[cubic-bezier(0.2,0.8,0.2,1)] group-active:w-5 group-data-[state=checked]:bg-knob group-data-[state=indeterminate]:bg-knob group-data-[state=checked]:translate-x-[19px] group-data-[state=indeterminate]:translate-x-[11px] group-active:group-data-[state=checked]:translate-x-[15px]"
      />
    </RCheckbox.Root>
  );
}

export function SwitchGroup({ children }: { children: ReactNode }) {
  return <div className="glass flex flex-col gap-1 rounded-[14px] p-1.5">{children}</div>;
}
