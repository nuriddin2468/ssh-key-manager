import { Check } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { passphraseStrength } from '@/features/keys/model';
import { cn } from '@/lib/cn';
import { TextField } from './TextField';

interface PassphraseFieldsProps {
  value: string;
  repeat: string;
  onChange: (value: string) => void;
  onRepeatChange: (value: string) => void;
  autoFocus?: boolean;
  /** Show the text, e.g. after a passphrase was generated. */
  visible?: boolean;
  /** The first field's label; "Passphrase" by default. */
  label?: string;
}

const SEGMENT_COLORS = [
  '',
  'var(--color-strength-1)',
  'var(--color-strength-2)',
  'var(--color-strength-3)',
  'var(--color-strength-4)',
];

/** New passphrase + repeat, with a strength meter and match check. */
export function PassphraseFields({
  value,
  repeat,
  onChange,
  onRepeatChange,
  autoFocus,
  visible = false,
  label,
}: PassphraseFieldsProps) {
  const { t } = useTranslation();
  const strength = passphraseStrength(value);
  const mismatch = repeat.length > 0 && repeat !== value;
  const matches = repeat.length > 0 && repeat === value;
  const type = visible ? 'text' : 'password';

  return (
    <>
      <div className="flex min-w-0 flex-col gap-1.5">
        <TextField
          label={label ?? t('generate.passphrase')}
          type={type}
          autoComplete="new-password"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          autoFocus={autoFocus}
        />
        {value ? (
          <div className="flex items-center gap-2">
            <div aria-hidden="true" className="grid flex-1 grid-cols-4 gap-1">
              {[1, 2, 3, 4].map((segment) => (
                <span
                  key={segment}
                  className="h-1 rounded-sm bg-ink/10"
                  style={segment <= strength ? { background: SEGMENT_COLORS[strength] } : undefined}
                />
              ))}
            </div>
            <span
              className="text-[12px] font-medium"
              style={{ color: SEGMENT_COLORS[strength] || 'var(--color-critical)' }}
            >
              {t(`generate.strength${strength}`)}
            </span>
          </div>
        ) : null}
      </div>
      <div className="flex min-w-0 flex-col gap-1.5">
        <TextField
          label={t('generate.repeat')}
          type={type}
          autoComplete="new-password"
          value={repeat}
          onChange={(event) => onRepeatChange(event.target.value)}
          error={mismatch ? t('generate.mismatch') : undefined}
        />
        {matches ? (
          <span className={cn('flex items-center gap-1.5 text-[12px] text-ok')}>
            <Check aria-hidden="true" className="size-3.5" strokeWidth={2.25} />
            {t('generate.match')}
          </span>
        ) : null}
      </div>
    </>
  );
}
