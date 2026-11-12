import { X } from 'lucide-react';
import { Dialog as RDialog } from 'radix-ui';
import { type ReactNode, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/cn';
import { IconButton } from './IconButton';

export const Dialog = RDialog.Root;
export const DialogClose = RDialog.Close;

interface DialogContentProps {
  /** Page section whose accent the dialog uses. */
  section: string;
  className?: string;
  /** `false` ignores Escape and clicks outside, for a step that must be finished. */
  dismissible?: boolean;
  /**
   * Escape goes back a step instead of closing, while this is set (a
   * dialog's second step).
   */
  onBack?: () => void;
  children: ReactNode;
}

export function DialogContent({
  section,
  className,
  dismissible = true,
  onBack,
  children,
}: DialogContentProps) {
  const block = dismissible ? undefined : (event: Event) => event.preventDefault();
  const onEscape = onBack
    ? (event: Event) => {
        event.preventDefault();
        if (dismissible) onBack();
      }
    : block;
  const returnFocus = useReturnFocus();
  return (
    <RDialog.Portal>
      <RDialog.Overlay className="fixed inset-0 z-40 bg-[rgb(4_6_11/0.62)] backdrop-blur-[6px] data-[state=open]:animate-fade-in" />
      <div className="pointer-events-none fixed inset-0 z-50 grid place-items-center overflow-y-auto p-4">
        <RDialog.Content
          data-section={section}
          onEscapeKeyDown={onEscape}
          onInteractOutside={block}
          // Start in the first field rather than on the close button. Radix
          // radios and checkboxes add hidden inputs (tabindex -1) to forms;
          // skip those.
          onOpenAutoFocus={(event) => {
            returnFocus.remember();
            const field = (event.currentTarget as HTMLElement).querySelector<HTMLElement>(
              'input:not([type=hidden]):not([disabled]):not([tabindex="-1"]), textarea, select',
            );
            if (field) {
              event.preventDefault();
              field.focus();
            }
          }}
          onCloseAutoFocus={returnFocus.restore}
          // `overflow-clip`, not `overflow-hidden`: the glow is wider than the
          // dialog, and a scroll container could be scrolled sideways by a click.
          className={cn(
            'pointer-events-auto relative flex max-h-[calc(100vh-32px)] w-full max-w-[620px] flex-col overflow-clip rounded-[22px] border border-white/10 bg-[linear-gradient(180deg,rgb(26_31_46/0.97),rgb(15_18_28/0.97))] text-fg shadow-[0_40px_80px_-24px_rgb(0_0_0/0.8),inset_0_1px_0_rgb(255_255_255/0.06)] outline-none data-[state=open]:animate-dialog-in',
            className,
          )}
        >
          <div
            aria-hidden="true"
            className="soft-glow absolute -top-[225px] left-1/2 h-[450px] w-[630px] -translate-x-1/2 [--glow-color:color-mix(in_srgb,var(--accent-2)_27%,transparent)]"
          />
          {children}
        </RDialog.Content>
      </div>
    </RDialog.Portal>
  );
}

/**
 * Radix returns focus to a `Dialog.Trigger`; dialogs here open from plain
 * buttons, menus and shortcuts, so remember what had focus when one opened
 * (Radix calls `onOpenAutoFocus` before moving focus) and go back to it.
 */
export function useReturnFocus() {
  const element = useRef<HTMLElement | null>(null);
  return {
    remember: () => {
      const active = document.activeElement;
      element.current = active instanceof HTMLElement && active !== document.body ? active : null;
    },
    restore: (event: Event) => {
      const target = element.current;
      if (!target?.isConnected) return;
      event.preventDefault();
      target.focus();
    },
  };
}

interface DialogHeaderProps {
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
  /** `false` hides the close button, for a step that must be finished. */
  closable?: boolean;
}

export function DialogHeader({ icon, title, description, closable = true }: DialogHeaderProps) {
  const { t } = useTranslation();
  return (
    <header className="relative flex items-start gap-3.5 px-6 pt-[22px] pb-4">
      {icon}
      <div className="min-w-0 flex-1">
        <RDialog.Title className="text-[19px] leading-[26px] font-semibold tracking-[-0.02em]">
          {title}
        </RDialog.Title>
        {description ? (
          <RDialog.Description className="mt-0.5 text-[12.5px] text-muted">
            {description}
          </RDialog.Description>
        ) : (
          <RDialog.Description className="sr-only">{title}</RDialog.Description>
        )}
      </div>
      {closable ? (
        <RDialog.Close asChild>
          <IconButton
            label={t('common.close')}
            icon={<X className="size-4" />}
            variant="secondary"
          />
        </RDialog.Close>
      ) : null}
    </header>
  );
}

export function DialogBody({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div
      className={cn(
        'relative flex min-h-0 flex-col gap-[18px] overflow-y-auto px-6 pt-1 pb-5',
        className,
      )}
    >
      {children}
    </div>
  );
}

export function DialogFooter({ children }: { children: ReactNode }) {
  return (
    <footer className="relative flex flex-wrap items-center justify-end gap-2.5 border-t border-white/[0.07] px-6 pt-3.5 pb-[18px]">
      {children}
    </footer>
  );
}
