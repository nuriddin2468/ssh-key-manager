import { Tooltip as RTooltip } from 'radix-ui';
import type { ReactNode } from 'react';
import { Kbd } from './Kbd';

export const TooltipProvider = RTooltip.Provider;

interface TooltipProps {
  content: ReactNode;
  shortcut?: string;
  side?: 'top' | 'right' | 'bottom' | 'left';
  children: ReactNode;
}

export function Tooltip({ content, shortcut, side = 'bottom', children }: TooltipProps) {
  return (
    <RTooltip.Root>
      <RTooltip.Trigger asChild>{children}</RTooltip.Trigger>
      <RTooltip.Portal>
        <RTooltip.Content
          side={side}
          sideOffset={6}
          className="z-50 flex items-center gap-2 rounded-md border border-line-strong bg-popover px-2 py-1 text-[12px] text-fg shadow-xl shadow-shade/40 data-[state=delayed-open]:animate-fade-in"
        >
          {content}
          {shortcut ? <Kbd>{shortcut}</Kbd> : null}
        </RTooltip.Content>
      </RTooltip.Portal>
    </RTooltip.Root>
  );
}
