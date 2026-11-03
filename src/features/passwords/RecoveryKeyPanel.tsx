import { AlertTriangle, Copy } from 'lucide-react';
import { Fragment } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { toastError } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { copyText } from '@/lib/clipboard';
import { recoveryKeyGroups } from './model';

interface RecoveryKeyPanelProps {
  recoveryKey: string;
  saved: boolean;
  onSavedChange: (saved: boolean) => void;
}

/**
 * A recovery key shown once: large, in groups, with Copy, a warning and the
 * "I've saved it" checkbox the caller requires before moving on.
 */
export function RecoveryKeyPanel({ recoveryKey, saved, onSavedChange }: RecoveryKeyPanelProps) {
  const { t } = useTranslation();
  const groups = recoveryKeyGroups(recoveryKey);

  const copy = async () => {
    try {
      await copyText(recoveryKey);
      toast.success(t('passwords.keyCopied'), { description: t('passwords.keyCopiedHint') });
    } catch (error) {
      toastError(t, error);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <figure className="flex flex-col items-center gap-3 rounded-2xl border border-white/10 bg-black/35 px-5 pt-4 pb-3.5 shadow-[inset_0_1px_0_rgb(255_255_255/0.04)]">
        <figcaption className="self-start text-[11.5px] font-semibold tracking-[0.02em] text-subtle">
          {t('passwords.recoveryKey')}
        </figcaption>
        {/* Dashes stay in the text, so selecting and copying by hand keeps them. */}
        <p
          data-testid="recovery-key"
          className="selectable max-w-[340px] text-center font-mono text-[19px] leading-[34px] font-medium tracking-[0.06em] text-fg"
        >
          {groups.map((group, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: groups are fixed positions in one key
            <Fragment key={index}>
              {index > 0 ? (
                <>
                  <span className="text-faint">-</span>
                  <wbr />
                </>
              ) : null}
              <span>{group}</span>
            </Fragment>
          ))}
        </p>
        <Button
          size="sm"
          variant="secondary"
          icon={<Copy className="size-3.5" strokeWidth={2} />}
          onClick={() => void copy()}
        >
          {t('passwords.copyKey')}
        </Button>
      </figure>

      <p className="flex gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5 text-[12.5px] leading-[18px] text-fg-2">
        <AlertTriangle
          aria-hidden="true"
          className="mt-px size-4 shrink-0 text-warning"
          strokeWidth={2}
        />
        <span>{t('passwords.recoveryWarning')}</span>
      </p>

      <Checkbox checked={saved} onCheckedChange={onSavedChange} label={t('passwords.savedIt')} />
    </div>
  );
}
