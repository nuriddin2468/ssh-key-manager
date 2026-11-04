import { Popover as RPopover } from 'radix-ui';
import { type ReactNode, useId } from 'react';

export const Popover = RPopover.Root;
export const PopoverTrigger = RPopover.Trigger;
export const PopoverClose = RPopover.Close;

interface PreviewPopoverProps {
  /** The tile, title and subtitle at the top. */
  icon: ReactNode;
  title: ReactNode;
  subtitle?: ReactNode;
  /** The rows; an empty value leaves its row out. */
  facts: { label: string; value: ReactNode }[];
  /** The one action under the facts, e.g. "Open in Hosts". */
  action?: ReactNode;
  children?: ReactNode;
}

/**
 * A short look at a linked item (a host, a key) from the chip that names it,
 * so seeing it doesn't mean leaving the page. Same surface and motion as a
 * menu; a dialog for screen readers, named by its title, closed with Escape.
 */
export function PreviewPopover({
  icon,
  title,
  subtitle,
  facts,
  action,
  children,
}: PreviewPopoverProps) {
  const titleId = useId();
  return (
    <RPopover.Portal>
      <RPopover.Content
        align="start"
        sideOffset={6}
        collisionPadding={12}
        aria-labelledby={titleId}
        className="z-50 flex w-[300px] origin-[var(--radix-popover-content-transform-origin)] flex-col gap-3 rounded-xl border border-white/10 bg-popover p-3.5 text-[12.5px] text-fg shadow-[0_20px_40px_-12px_rgb(0_0_0/0.7)] outline-none data-[state=closed]:pointer-events-none data-[state=closed]:animate-popover-out data-[state=open]:animate-popover-in"
      >
        <div className="flex items-center gap-2.5">
          {icon}
          <div className="min-w-0 flex-1">
            <p id={titleId} className="truncate font-mono text-[13.5px] font-medium">
              {title}
            </p>
            {subtitle ? <p className="truncate text-[12px] text-subtle">{subtitle}</p> : null}
          </div>
        </div>
        <dl className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-3 gap-y-1.5">
          {facts.map(({ label, value }) =>
            value === null || value === undefined || value === '' ? null : (
              <Fact key={label} label={label} value={value} />
            ),
          )}
        </dl>
        {children}
        {action ? <div className="flex justify-end gap-2">{action}</div> : null}
      </RPopover.Content>
    </RPopover.Portal>
  );
}

function Fact({ label, value }: { label: string; value: ReactNode }) {
  return (
    <>
      <dt className="text-subtle">{label}</dt>
      <dd className="selectable min-w-0 [overflow-wrap:anywhere]">{value}</dd>
    </>
  );
}
