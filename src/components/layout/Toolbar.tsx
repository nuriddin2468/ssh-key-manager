import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

interface ToolbarProps {
  title?: ReactNode;
  meta?: ReactNode;
  children?: ReactNode;
  className?: string;
}

/**
 * The 52 px unified toolbar at the top of every page. It doubles as the
 * window's drag area, like a native title bar.
 */
export function Toolbar({ title, meta, children, className }: ToolbarProps) {
  return (
    <header
      data-tauri-drag-region
      className={cn(
        'flex min-h-[52px] shrink-0 flex-wrap items-center gap-2.5 border-b border-white/[0.06] bg-[rgb(11_15_23/0.55)] pr-5 pl-6 backdrop-blur-xl',
        className,
      )}
    >
      {title ? (
        <h1
          data-tauri-drag-region
          className="text-[15px] leading-5 font-semibold tracking-[-0.01em]"
        >
          {title}
        </h1>
      ) : null}
      {meta ? (
        <span data-tauri-drag-region className="text-[12.5px] text-subtle">
          {meta}
        </span>
      ) : null}
      <span data-tauri-drag-region className="flex-1" />
      {children}
    </header>
  );
}

/** Scrollable page content under the toolbar. */
export function PageBody({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div
      className={cn('flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-6 pt-4 pb-6', className)}
    >
      {children}
    </div>
  );
}
