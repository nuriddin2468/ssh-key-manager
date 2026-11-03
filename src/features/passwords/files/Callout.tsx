import type { LucideIcon } from 'lucide-react';
import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

const TONES = {
  info: { box: 'border-info-solid/30 bg-info-solid/[0.09]', icon: 'text-info' },
  warning: { box: 'border-warning-solid/30 bg-warning-solid/[0.09]', icon: 'text-warning' },
  critical: { box: 'border-critical-solid/30 bg-critical-solid/10', icon: 'text-critical' },
} as const;

interface CalloutProps {
  tone: keyof typeof TONES;
  icon: LucideIcon;
  title?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
}

/** A tinted box with an icon, like the host key check result. */
export function Callout({ tone, icon: Icon, title, children, className, id }: CalloutProps) {
  const style = TONES[tone];
  return (
    <div id={id} className={cn('flex gap-2.5 rounded-xl border px-3.5 py-3', style.box, className)}>
      <Icon
        aria-hidden="true"
        className={cn('mt-0.5 size-4 shrink-0', style.icon)}
        strokeWidth={2}
      />
      <div className="flex min-w-0 flex-col gap-0.5">
        {title ? <p className="font-semibold text-fg">{title}</p> : null}
        <div className="text-[12.5px] leading-[19px] text-fg-2">{children}</div>
      </div>
    </div>
  );
}
