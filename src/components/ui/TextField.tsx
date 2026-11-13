import { type InputHTMLAttributes, type ReactNode, type Ref, useId } from 'react';
import { cn } from '@/lib/cn';

interface TextFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'prefix'> {
  label: ReactNode;
  hint?: ReactNode;
  error?: ReactNode;
  /** Fixed text shown inside the field before the value, e.g. `~/.ssh/`. */
  prefix?: string;
  /** Controls inside the field after the value, e.g. show/hide buttons. */
  suffix?: ReactNode;
  mono?: boolean;
  /** Classes for the input itself, e.g. a larger code font. */
  inputClassName?: string;
  ref?: Ref<HTMLInputElement>;
}

export function TextField({
  label,
  hint,
  error,
  prefix,
  suffix,
  mono = false,
  inputClassName,
  className,
  id,
  ref,
  ...props
}: TextFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const describedBy = error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined;

  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', className)}>
      <label htmlFor={inputId} className="text-[12px] font-semibold text-fg-2">
        {label}
      </label>
      <div
        className={cn(
          'field flex h-9 items-center overflow-hidden rounded-[10px] transition-colors focus-within:border-[rgb(var(--accent-rgb)/var(--edge-alpha))] focus-within:shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.15)]',
          error && 'border-critical-solid/60',
        )}
      >
        {prefix ? (
          <span className="flex h-full items-center border-r border-line bg-ink/[0.04] pr-2 pl-[11px] font-mono text-[12px] text-subtle">
            {prefix}
          </span>
        ) : null}
        <input
          ref={ref}
          id={inputId}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          spellCheck={false}
          autoComplete="off"
          className={cn(
            'h-full min-w-0 flex-1 bg-transparent px-[11px] text-fg outline-none',
            mono && 'font-mono text-[12.5px]',
            inputClassName,
          )}
          {...props}
        />
        {suffix ? <span className="flex shrink-0 items-center gap-0.5 pr-1">{suffix}</span> : null}
      </div>
      {error ? (
        <p id={`${inputId}-error`} className="text-[12px] text-critical">
          {error}
        </p>
      ) : hint ? (
        <p id={`${inputId}-hint`} className="text-[12px] text-subtle">
          {hint}
        </p>
      ) : null}
    </div>
  );
}
