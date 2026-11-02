import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

const tones = {
  neutral: 'border-white/10 bg-white/[0.05] text-fg-2',
  accent:
    'border-[rgb(var(--accent-rgb)/0.35)] bg-[rgb(var(--accent-rgb)/0.14)] text-[var(--accent-text)]',
  warning: 'border-warning-solid/35 bg-warning-solid/10 text-warning',
  critical: 'border-critical-solid/35 bg-critical-solid/10 text-critical',
  info: 'border-info-solid/30 bg-info-solid/12 text-info',
  violet: 'border-violet-400/30 bg-violet-400/12 text-violet-200',
} as const;

export type BadgeTone = keyof typeof tones;

interface BadgeProps {
  tone?: BadgeTone;
  mono?: boolean;
  pill?: boolean;
  className?: string;
  children: ReactNode;
}

export function Badge({
  tone = 'neutral',
  mono = false,
  pill = false,
  className,
  children,
}: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex h-[22px] shrink-0 items-center whitespace-nowrap border px-2 text-[11px] font-medium',
        pill ? 'h-[18px] rounded-full px-[7px] text-[10.5px] font-semibold' : 'rounded-md',
        mono && 'font-mono',
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}
