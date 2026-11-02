import type { CSSProperties, ReactNode } from 'react';
import { cn } from '@/lib/cn';

/** Gradient pairs for icon tiles; each section and key family has one. */
export const TONES = {
  teal: ['#5EEAD4', '#0D9488'],
  blue: ['#7DD3FC', '#2563EB'],
  violet: ['#C4B5FD', '#7C3AED'],
  amber: ['#FCD34D', '#D97706'],
  rose: ['#FDA4AF', '#E11D48'],
  slate: ['#CBD5E1', '#475569'],
  indigo: ['#A5B4FC', '#4F46E5'],
  pink: ['#F9A8D4', '#DB2777'],
  orange: ['#FDBA74', '#EA580C'],
  aurora: ['#2DD4BF', '#6366F1'],
} as const;

export type Tone = keyof typeof TONES;

export function toneGradient(tone: Tone): string {
  const [from, to] = TONES[tone];
  return `linear-gradient(140deg, ${from}, ${to})`;
}

interface TileProps {
  tone: Tone;
  /** Edge length in px. */
  size?: number;
  glow?: boolean;
  className?: string;
  children: ReactNode;
}

export function Tile({ tone, size = 34, glow = false, className, children }: TileProps) {
  const [, to] = TONES[tone];
  const style: CSSProperties = {
    width: size,
    height: size,
    borderRadius: Math.round(size * 0.29),
    background: toneGradient(tone),
    boxShadow: [
      'inset 0 1px 0 rgb(255 255 255 / 0.32)',
      glow ? `0 12px 26px -10px ${to}` : undefined,
    ]
      .filter(Boolean)
      .join(', '),
  };
  return (
    <span
      aria-hidden="true"
      className={cn('grid shrink-0 place-items-center text-white', className)}
      style={style}
    >
      {children}
    </span>
  );
}
