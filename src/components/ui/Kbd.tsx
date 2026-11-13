import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

export function Kbd({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        'rounded-[5px] border border-kbd-line px-1.5 font-mono text-[11px] leading-[18px] text-subtle',
        className,
      )}
    >
      {children}
    </kbd>
  );
}
