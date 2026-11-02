import { X } from 'lucide-react';
import { Dialog as RDialog } from 'radix-ui';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { cn } from '@/lib/cn';
import { IconButton } from './IconButton';

export const Dialog = RDialog.Root;
export const DialogClose = RDialog.Close;

interface DialogContentProps {
  /** Page section whose accent the dialog uses. */
  section: string;
  className?: string;
  children: ReactNode;
}

export function DialogContent({ section, className, children }: DialogContentProps) {
  return (
    <RDialog.Portal>
      <RDialog.Overlay className="fixed inset-0 z-40 bg-[rgb(4_6_11/0.62)] backdrop-blur-[6px] data-[state=open]:animate-fade-in" />
      <div className="pointer-events-none fixed inset-0 z-50 grid place-items-center overflow-y-auto p-4">
        <RDialog.Content
          data-section={section}
          // Start in the first field rather than on the close button.
          onOpenAutoFocus={(event) => {
            const field = (event.currentTarget as HTMLElement).querySelector<HTMLElement>(
              'input:not([type=hidden]):not([disabled]), textarea, select',
            );
            if (field) {
              event.preventDefault();
              field.focus();
            }
          }}
          className={cn(
            'pointer-events-auto relative flex max-h-[calc(100vh-32px)] w-full max-w-[620px] flex-col overflow-hidden rounded-[22px] border border-white/10 bg-[linear-gradient(180deg,rgb(26_31_46/0.97),rgb(15_18_28/0.97))] text-fg shadow-[0_40px_80px_-24px_rgb(0_0_0/0.8),inset_0_1px_0_rgb(255_255_255/0.06)] outline-none data-[state=open]:animate-dialog-in',
            className,
          )}
        >
          <div
            aria-hidden="true"
            className="pointer-events-none absolute -top-[120px] left-1/2 h-[240px] w-[420px] -translate-x-1/2 rounded-full bg-[var(--accent-2)] opacity-30 blur-[70px]"
          />
          {children}
        </RDialog.Content>
      </div>
    </RDialog.Portal>
  );
}

interface DialogHeaderProps {
  icon?: ReactNode;
  title: ReactNode;
  description?: ReactNode;
}

export function DialogHeader({ icon, title, description }: DialogHeaderProps) {
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
      <RDialog.Close asChild>
        <IconButton label={t('common.close')} icon={<X className="size-4" />} variant="secondary" />
      </RDialog.Close>
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
