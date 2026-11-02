import { cn } from '@/lib/cn';

interface ChipProps {
  label: string;
  count?: number;
  pressed: boolean;
  onClick: () => void;
}

/** A toggle pill used for quick filters above lists. */
export function Chip({ label, count, pressed, onClick }: ChipProps) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      onClick={onClick}
      className={cn(
        'pressable inline-flex h-[30px] items-center gap-1.5 rounded-full border px-3 text-[12.5px] font-medium',
        pressed
          ? 'border-[rgb(var(--accent-rgb)/0.45)] bg-[rgb(var(--accent-rgb)/0.14)] text-[var(--accent-text)]'
          : 'border-white/[0.09] bg-white/[0.04] text-fg-2 hover:bg-white/[0.07]',
      )}
    >
      {label}
      {count !== undefined ? (
        <span className={cn('tabular-nums', pressed ? 'text-[var(--accent-1)]' : 'text-subtle')}>
          {count}
        </span>
      ) : null}
    </button>
  );
}
