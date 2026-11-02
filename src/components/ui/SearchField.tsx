import { Search } from 'lucide-react';
import type { Ref } from 'react';
import { cn } from '@/lib/cn';

interface SearchFieldProps {
  value: string;
  onChange: (value: string) => void;
  label: string;
  placeholder?: string;
  className?: string;
  ref?: Ref<HTMLInputElement>;
}

export function SearchField({
  value,
  onChange,
  label,
  placeholder,
  className,
  ref,
}: SearchFieldProps) {
  return (
    <label
      className={cn(
        'flex h-[30px] min-w-[150px] items-center gap-[7px] rounded-lg border border-white/[0.08] bg-white/[0.06] px-2.5 text-subtle focus-within:border-[rgb(var(--accent-rgb)/0.5)]',
        className,
      )}
    >
      <Search aria-hidden="true" className="size-3.5 shrink-0" strokeWidth={2} />
      <span className="sr-only">{label}</span>
      <input
        ref={ref}
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === 'Escape' && value) {
            event.stopPropagation();
            onChange('');
          }
        }}
        placeholder={placeholder}
        spellCheck={false}
        autoComplete="off"
        className="min-w-0 flex-1 bg-transparent text-[12.5px] text-fg outline-none [&::-webkit-search-cancel-button]:hidden"
      />
    </label>
  );
}
