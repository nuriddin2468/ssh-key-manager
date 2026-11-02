import { AlertDialog } from 'radix-ui';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from './Button';
import { useReturnFocus } from './Dialog';

interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  busy?: boolean;
  onConfirm: () => void;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive = false,
  busy = false,
  onConfirm,
}: ConfirmDialogProps) {
  const { t } = useTranslation();
  const returnFocus = useReturnFocus();
  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 z-40 bg-[rgb(4_6_11/0.62)] backdrop-blur-[6px] data-[state=open]:animate-fade-in" />
        <AlertDialog.Content
          onOpenAutoFocus={returnFocus.remember}
          onCloseAutoFocus={returnFocus.restore}
          className="fixed top-1/2 left-1/2 z-50 flex w-[calc(100%-32px)] max-w-[420px] -translate-x-1/2 -translate-y-1/2 flex-col gap-4 rounded-[18px] border border-white/10 bg-popover p-5 text-fg shadow-[0_40px_80px_-24px_rgb(0_0_0/0.8)] outline-none data-[state=open]:animate-fade-in"
        >
          <div className="flex flex-col gap-1.5">
            <AlertDialog.Title className="text-[16px] font-semibold">{title}</AlertDialog.Title>
            <AlertDialog.Description className="text-[13px] leading-5 text-muted">
              {description}
            </AlertDialog.Description>
          </div>
          <div className="flex justify-end gap-2">
            <AlertDialog.Cancel asChild>
              <Button>{t('common.cancel')}</Button>
            </AlertDialog.Cancel>
            <Button
              variant={destructive ? 'danger' : 'primary'}
              className={destructive ? 'field border-critical-solid/40' : undefined}
              loading={busy}
              onClick={onConfirm}
            >
              {confirmLabel}
            </Button>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
