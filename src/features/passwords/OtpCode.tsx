import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { Spinner } from '@/components/ui/Spinner';
import { cn } from '@/lib/cn';
import { formatOtp, otpFraction, otpPeriod, otpRemaining } from './model';
import { isVaultLocked, markLocked } from './vault';

interface Code {
  code: string;
  validFor: number;
  fetchedAt: number;
}

/** Slack after expiry before asking again, so the next code is really new. */
const REFRESH_SLACK_MS = 600;
const RING_RADIUS = 8;
const RING_LENGTH = 2 * Math.PI * RING_RADIUS;

/**
 * The entry's current 2FA code with a countdown ring. The code lives only in
 * this component's state and is fetched again when it expires.
 */
export function OtpCode({ entryId }: { entryId: string }) {
  const { t } = useTranslation();
  const [otp, setOtp] = useState<Code | null>(null);
  const [failed, setFailed] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  const load = useCallback(async () => {
    try {
      const result = await api.vaultOtp(entryId);
      setOtp({ ...result, fetchedAt: Date.now() });
      setFailed(false);
    } catch (error) {
      if (isVaultLocked(error)) markLocked();
      setFailed(true);
    }
  }, [entryId]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!otp) return;
    const timer = window.setTimeout(
      () => void load(),
      Math.max(0, otp.validFor) * 1000 + REFRESH_SLACK_MS,
    );
    return () => window.clearTimeout(timer);
  }, [otp, load]);

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  if (!otp) {
    return failed ? (
      <span className="text-subtle">—</span>
    ) : (
      <Spinner className="size-4 text-subtle" />
    );
  }

  const remaining = otpRemaining(otp.validFor, otp.fetchedAt, now);
  const fraction = otpFraction(remaining, otpPeriod(otp.validFor));
  const ending = remaining <= 5;

  return (
    <span className="flex items-center gap-2.5">
      <span className="selectable font-mono text-[18px] leading-6 font-semibold tracking-[0.08em] tabular-nums">
        {formatOtp(otp.code)}
      </span>
      <span
        role="img"
        aria-label={t('passwords.otpChangesIn', { seconds: remaining })}
        className={cn(
          'relative grid size-6 place-items-center',
          ending ? 'text-warning' : 'text-[var(--accent-text)]',
        )}
      >
        <svg aria-hidden="true" viewBox="0 0 20 20" className="absolute inset-0 -rotate-90">
          <circle
            cx="10"
            cy="10"
            r={RING_RADIUS}
            fill="none"
            stroke="rgb(255 255 255 / 0.1)"
            strokeWidth="2"
          />
          <circle
            cx="10"
            cy="10"
            r={RING_RADIUS}
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeDasharray={RING_LENGTH}
            strokeDashoffset={RING_LENGTH * (1 - fraction)}
            className="transition-[stroke-dashoffset] duration-1000 ease-linear"
          />
        </svg>
        <span aria-hidden="true" className="text-[9.5px] font-semibold tabular-nums">
          {remaining}
        </span>
      </span>
    </span>
  );
}
