import { Check } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { TextField } from '@/components/ui/TextField';
import { StrengthMeter, useStrength } from './StrengthMeter';

interface MasterPasswordFieldsProps {
  value: string;
  repeat: string;
  onChange: (value: string) => void;
  onRepeatChange: (value: string) => void;
  /** Labels for setting a new password over an old one. */
  replacing?: boolean;
  autoFocus?: boolean;
}

/** A new master password twice, with a live strength meter and match check. */
export function MasterPasswordFields({
  value,
  repeat,
  onChange,
  onRepeatChange,
  replacing = false,
  autoFocus,
}: MasterPasswordFieldsProps) {
  const { t } = useTranslation();
  const strength = useStrength(value);
  const mismatch = repeat.length > 0 && repeat !== value;
  const matches = repeat.length > 0 && repeat === value;
  const weak = strength !== null && strength.score <= 1;

  return (
    <>
      <div className="flex flex-col gap-1.5">
        <TextField
          label={replacing ? t('passwords.newMaster') : t('passwords.masterPassword')}
          type="password"
          autoComplete="new-password"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          hint={value ? undefined : t('passwords.masterHint')}
          autoFocus={autoFocus}
        />
        {value ? <StrengthMeter strength={strength} /> : null}
        {weak ? <p className="text-[12px] text-warning">{t('passwords.weakMaster')}</p> : null}
      </div>
      <div className="flex flex-col gap-1.5">
        <TextField
          label={replacing ? t('passwords.repeatNewMaster') : t('passwords.repeatMaster')}
          type="password"
          autoComplete="new-password"
          value={repeat}
          onChange={(event) => onRepeatChange(event.target.value)}
          error={mismatch ? t('passwords.mismatch') : undefined}
        />
        {matches ? (
          <span className="flex items-center gap-1.5 text-[12px] text-ok">
            <Check aria-hidden="true" className="size-3.5" strokeWidth={2.25} />
            {t('passwords.match')}
          </span>
        ) : null}
      </div>
    </>
  );
}

/** Whether a new master password can be submitted. */
export const masterReady = (value: string, repeat: string) => value.length > 0 && value === repeat;
