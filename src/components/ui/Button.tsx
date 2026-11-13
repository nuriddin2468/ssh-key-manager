import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { cn } from '@/lib/cn';
import { Spinner } from './Spinner';

const variants = {
  primary: 'accent-fill font-semibold hover:brightness-110 active:brightness-95',
  secondary: 'field text-fg-2 font-medium hover:bg-fill-hover hover:text-fg',
  ghost: 'text-fg-2 font-medium hover:bg-fill hover:text-fg',
  soft: 'accent-soft font-medium hover:brightness-110',
  danger: 'text-critical font-medium hover:bg-critical-solid/10',
} as const;

const sizes = {
  sm: 'h-[30px] gap-1.5 rounded-lg px-3 text-[12.5px]',
  md: 'h-[34px] gap-2 rounded-[9px] px-3.5',
  lg: 'h-10 gap-2 rounded-[11px] px-4 text-[13.5px]',
  hero: 'h-12 gap-2.5 rounded-full px-6 text-[15px] tracking-[-0.01em]',
} as const;

export type ButtonVariant = keyof typeof variants;

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: keyof typeof sizes;
  icon?: ReactNode;
  loading?: boolean;
}

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  loading = false,
  disabled,
  className,
  children,
  type = 'button',
  ...props
}: ButtonProps) {
  return (
    <button
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={cn(
        'pressable inline-flex shrink-0 items-center justify-center whitespace-nowrap disabled:pointer-events-none disabled:opacity-50',
        variants[variant],
        sizes[size],
        className,
      )}
      {...props}
    >
      {loading ? <Spinner className="size-4" /> : icon}
      {children}
    </button>
  );
}
