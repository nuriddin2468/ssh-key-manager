import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import type { Strength } from '@/bindings/Strength';
import { cn } from '@/lib/cn';
import { type StrengthScore, strengthLabelKey, strengthScore } from './model';

const DEBOUNCE_MS = 250;

/**
 * zxcvbn's estimate for `password`, asked of the backend after typing pauses.
 * The password goes only to `vault_strength` and is never cached.
 */
export function useStrength(password: string, context: readonly string[] = []): Strength | null {
  const [strength, setStrength] = useState<Strength | null>(null);
  const contextKey = context.join('\u0000');

  useEffect(() => {
    if (!password) {
      setStrength(null);
      return;
    }
    let current = true;
    const timer = window.setTimeout(() => {
      api
        .vaultStrength(password, contextKey ? contextKey.split('\u0000') : [])
        .then((result) => {
          if (current) setStrength(result);
        })
        .catch(() => {
          if (current) setStrength(null);
        });
    }, DEBOUNCE_MS);
    return () => {
      current = false;
      window.clearTimeout(timer);
    };
  }, [password, contextKey]);

  return password ? strength : null;
}

const SEGMENT = ['', 'bg-critical-solid', 'bg-warning-solid', 'bg-ok', 'bg-ok-solid'] as const;
const LABEL = ['text-critical', 'text-critical', 'text-warning', 'text-ok', 'text-ok'] as const;

/** Four segments and a label, like the passphrase meter on the Keys page. */
export function StrengthMeter({
  strength,
  className,
}: {
  strength: Strength | null;
  className?: string;
}) {
  const { t } = useTranslation();
  const score: StrengthScore = strengthScore(strength?.score);
  const label = strength ? t(strengthLabelKey(score)) : '';
  return (
    <div className={cn('flex h-4 items-center gap-2', className)}>
      <meter
        className="sr-only"
        aria-label={t('passwords.strength')}
        aria-valuetext={label || undefined}
        min={0}
        max={4}
        value={score}
      />
      <div aria-hidden="true" className="grid flex-1 grid-cols-4 gap-1">
        {[1, 2, 3, 4].map((segment) => (
          <span
            key={segment}
            className={cn(
              'h-1 rounded-sm bg-ink/10 transition-colors duration-200',
              strength && segment <= score && SEGMENT[score],
            )}
          />
        ))}
      </div>
      <span
        aria-live="polite"
        className={cn('min-w-[64px] text-right text-[12px] font-medium', LABEL[score])}
      >
        {label}
      </span>
    </div>
  );
}
