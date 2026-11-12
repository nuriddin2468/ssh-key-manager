import { ChevronRight } from 'lucide-react';
import { DropdownMenu } from 'radix-ui';
import type { ReactNode } from 'react';
import { cn } from '@/lib/cn';

export const Menu = DropdownMenu.Root;
export const MenuTrigger = DropdownMenu.Trigger;

const CONTENT =
  'z-50 min-w-[200px] rounded-xl border border-white/10 bg-popover p-1 text-[13px] text-fg shadow-[0_20px_40px_-12px_rgb(0_0_0/0.7)] data-[state=closed]:pointer-events-none data-[state=closed]:animate-popover-out data-[state=open]:animate-popover-in';
const ITEM =
  'flex h-8 items-center gap-2.5 rounded-lg px-2.5 outline-none select-none transition-colors duration-100 active:bg-white/[0.12] data-[disabled]:opacity-40 data-[highlighted]:bg-white/[0.08]';

export function MenuContent({
  children,
  align = 'end',
  onCloseAutoFocus,
}: {
  children: ReactNode;
  align?: 'start' | 'end';
  /** `preventDefault()` keeps focus where an item moved it, e.g. in a dialog it opened. */
  onCloseAutoFocus?: (event: Event) => void;
}) {
  return (
    <DropdownMenu.Portal>
      <DropdownMenu.Content
        align={align}
        sideOffset={6}
        onCloseAutoFocus={onCloseAutoFocus}
        className={cn(CONTENT, 'origin-[var(--radix-dropdown-menu-content-transform-origin)]')}
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
      className={cn(ITEM, destructive && 'text-critical')}
    >
      {icon ? <span className="flex size-4 items-center justify-center">{icon}</span> : null}
      {children}
    </DropdownMenu.Item>
  );
}

/** A heading over some of a menu's items, e.g. what a choice is about. */
export function MenuLabel({ children }: { children: ReactNode }) {
  return (
    <DropdownMenu.Label className="px-2.5 pt-1 pb-1.5 text-[11px] font-semibold text-subtle">
      {children}
    </DropdownMenu.Label>
  );
}

export function MenuSeparator() {
  return <DropdownMenu.Separator className="my-1 h-px bg-white/[0.07]" />;
}

/** A menu item that opens a nested menu, e.g. a list of destinations. */
export function MenuSub({
  icon,
  label,
  disabled,
  children,
}: {
  icon?: ReactNode;
  label: ReactNode;
  disabled?: boolean;
  children: ReactNode;
}) {
  return (
    <DropdownMenu.Sub>
      <DropdownMenu.SubTrigger
        disabled={disabled}
        className={cn(ITEM, 'data-[state=open]:bg-white/[0.08]')}
      >
        {icon ? <span className="flex size-4 items-center justify-center">{icon}</span> : null}
        <span className="flex-1">{label}</span>
        <ChevronRight aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />
      </DropdownMenu.SubTrigger>
      <DropdownMenu.Portal>
        <DropdownMenu.SubContent
          sideOffset={6}
          alignOffset={-5}
          className={cn(
            CONTENT,
            'max-h-[min(360px,var(--radix-dropdown-menu-content-available-height))] overflow-y-auto origin-[var(--radix-dropdown-menu-content-transform-origin)]',
          )}
        >
          {children}
        </DropdownMenu.SubContent>
      </DropdownMenu.Portal>
    </DropdownMenu.Sub>
  );
}
