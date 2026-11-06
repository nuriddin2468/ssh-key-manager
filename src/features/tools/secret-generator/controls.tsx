import { RadioGroup } from 'radix-ui';
import { type ReactNode, useEffect, useId, useState } from 'react';
import { cn } from '@/lib/cn';

/** Two or three choices side by side, as a radio group. */
export function Segmented<T extends string>({
  label,
  value,
  onValueChange,
  options,
}: {
  label: string;
  value: T;
  onValueChange: (value: T) => void;
  options: readonly { value: T; label: ReactNode }[];
}) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1.5">
      <span id={id} className="text-[12px] font-semibold text-fg-2">
        {label}
      </span>
      <RadioGroup.Root
        aria-labelledby={id}
        value={value}
        onValueChange={(next) => onValueChange(next as T)}
        className="grid auto-cols-fr grid-flow-col gap-1 rounded-[10px] border border-white/[0.08] bg-black/25 p-[3px]"
      >
        {options.map((option) => (
          <RadioGroup.Item
            key={option.value}
            value={option.value}
            className={cn(
              'pressable h-7 rounded-[7px] px-2.5 text-[12.5px] font-medium whitespace-nowrap',
              value === option.value
                ? 'bg-white/[0.12] text-fg shadow-[0_1px_2px_rgb(0_0_0/0.4)]'
                : 'text-muted hover:text-fg',
            )}
          >
            {option.label}
          </RadioGroup.Item>
        ))}
      </RadioGroup.Root>
    </div>
  );
}

/** A number picked with a slider, or typed. */
export function RangeField({
  label,
  value,
  min,
  max,
  onChange,
}: {
  label: string;
  value: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
}) {
  const id = useId();
  const [text, setText] = useState(String(value));
  useEffect(() => setText(String(value)), [value]);
  const clamp = (n: number) => Math.min(max, Math.max(min, Number.isFinite(n) ? n : min));

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between gap-3">
        <label
          id={`${id}-label`}
          htmlFor={`${id}-range`}
          className="text-[12px] font-semibold text-fg-2"
        >
          {label}
        </label>
        <input
          aria-labelledby={`${id}-label`}
          type="number"
          inputMode="numeric"
          min={min}
          max={max}
          value={text}
          onChange={(event) => {
            setText(event.target.value);
            const next = Number(event.target.value);
            if (event.target.value !== '' && next >= min && next <= max) onChange(Math.round(next));
          }}
          onBlur={() => onChange(clamp(Math.round(Number(text))))}
          className="field h-7 w-14 rounded-md px-2 text-right font-mono text-[12.5px] tabular-nums outline-none focus:border-[rgb(var(--accent-rgb)/0.55)]"
        />
      </div>
      <input
        id={`${id}-range`}
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
        className="h-4 w-full accent-[var(--accent-2)]"
      />
    </div>
  );
}
