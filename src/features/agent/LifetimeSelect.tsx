import { Clock, Infinity as Forever } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Select } from '@/components/ui/Select';

interface LifetimeSelectProps {
  value: number | null;
  onChange: (value: number | null) => void;
  withLabel?: boolean;
  size?: 'sm' | 'md';
  ariaLabel?: string;
}

/** How long ssh-agent keeps a key: 1 hour, 8 hours or until logout. */
export function LifetimeSelect({
  value,
  onChange,
  withLabel = false,
  size = 'md',
  ariaLabel,
}: LifetimeSelectProps) {
  const { t } = useTranslation();
  const clock = <Clock aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />;
  return (
    <Select
      label={withLabel ? t('settings.defaultLifetime') : undefined}
      aria-label={withLabel ? undefined : (ariaLabel ?? t('settings.defaultLifetime'))}
      size={size}
      value={value === null ? 'forever' : String(value)}
      onValueChange={(next) => onChange(next === 'forever' ? null : Number(next))}
      options={[
        { value: '3600', label: t('agent.lifetime1h'), icon: clock },
        { value: '28800', label: t('agent.lifetime8h'), icon: clock },
        {
          value: 'forever',
          label: t('agent.lifetimeForever'),
          icon: <Forever aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />,
        },
      ]}
    />
  );
}
