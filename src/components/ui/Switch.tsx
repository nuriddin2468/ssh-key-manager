import { Switch as RSwitch } from 'radix-ui';
import { type ReactNode, useId } from 'react';
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
      <RSwitch.Root
        id={id}
        checked={checked}
        onCheckedChange={onCheckedChange}
        disabled={disabled}
        aria-describedby={hint ? `${id}-hint` : undefined}
        className={cn(
          'group relative h-[22px] w-[38px] shrink-0 rounded-full shadow-[inset_0_0_0_1px_rgb(255_255_255/0.1)] transition-colors duration-150 disabled:opacity-50',
          'bg-white/10 data-[state=checked]:bg-[linear-gradient(135deg,var(--accent-1),var(--accent-2))]',
        )}
      >
        {/* While pressed the knob stretches toward the other side, like macOS. */}
        <RSwitch.Thumb className="block h-4 w-4 translate-x-[3px] rounded-full bg-white shadow-[0_2px_4px_rgb(0_0_0/0.35)] transition-[translate,width] duration-200 ease-[cubic-bezier(0.2,0.8,0.2,1)] group-active:w-5 data-[state=checked]:translate-x-[19px] group-active:data-[state=checked]:translate-x-[15px]" />
      </RSwitch.Root>
    </div>
  );
}

export function SwitchGroup({ children }: { children: ReactNode }) {
  return <div className="glass flex flex-col gap-1 rounded-[14px] p-1.5">{children}</div>;
}
