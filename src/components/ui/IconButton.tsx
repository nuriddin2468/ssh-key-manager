import type { ButtonHTMLAttributes, ReactNode } from 'react';
import { cn } from '@/lib/cn';
import { Tooltip } from './Tooltip';

const variants = {
  secondary: 'field text-fg-2 hover:bg-white/[0.09] hover:text-fg',
  ghost: 'text-muted hover:bg-white/[0.07] hover:text-fg',
  danger: 'field text-critical hover:bg-critical-solid/10',
} as const;

const sizes = {
  sm: 'size-[30px] rounded-lg',
  md: 'size-8 rounded-[9px]',
} as const;

interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'children'> {
  /** Accessible name, also shown as the tooltip. */
  label: string;
  icon: ReactNode;
  shortcut?: string;
  variant?: keyof typeof variants;
  size?: keyof typeof sizes;
}

export function IconButton({
  label,
  icon,
  shortcut,
  variant = 'ghost',
  size = 'sm',
  className,
  type = 'button',
  ...props
}: IconButtonProps) {
  return (
    <Tooltip content={label} shortcut={shortcut}>
      <button
        type={type}
        aria-label={label}
        className={cn(
          'pressable grid shrink-0 place-items-center disabled:pointer-events-none disabled:opacity-40',
          variants[variant],
          sizes[size],
          className,
        )}
        {...props}
      >
        {icon}
      </button>
    </Tooltip>
  );
}
