import { DropdownMenu } from 'radix-ui';
import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

export const Menu = DropdownMenu.Root;
export const MenuTrigger = DropdownMenu.Trigger;

export function MenuContent({
  children,
  align = 'end',
}: {
  children: ReactNode;
  align?: 'start' | 'end';
}) {
  return (
    <DropdownMenu.Portal>
      <DropdownMenu.Content
        align={align}
        sideOffset={6}
        className="z-50 min-w-[200px] rounded-xl border border-white/10 bg-popover p-1 text-[13px] text-fg shadow-[0_20px_40px_-12px_rgb(0_0_0/0.7)] origin-[var(--radix-dropdown-menu-content-transform-origin)] data-[state=closed]:pointer-events-none data-[state=closed]:animate-popover-out data-[state=open]:animate-popover-in"
      >
        {children}
      </DropdownMenu.Content>
    </DropdownMenu.Portal>
  );
}

interface MenuItemProps {
  icon?: ReactNode;
  destructive?: boolean;
  disabled?: boolean;
  onSelect: () => void;
  children: ReactNode;
}

export function MenuItem({ icon, destructive, disabled, onSelect, children }: MenuItemProps) {
  return (
    <DropdownMenu.Item
      disabled={disabled}
      onSelect={onSelect}
      className={cn(
        'flex h-8 items-center gap-2.5 rounded-lg px-2.5 outline-none select-none transition-colors duration-100 active:bg-white/[0.12] data-[disabled]:opacity-40 data-[highlighted]:bg-white/[0.08]',
        destructive && 'text-critical',
      )}
    >
      {icon ? <span className="flex size-4 items-center justify-center">{icon}</span> : null}
      {children}
    </DropdownMenu.Item>
  );
}

export function MenuSeparator() {
  return <DropdownMenu.Separator className="my-1 h-px bg-white/[0.07]" />;
}
