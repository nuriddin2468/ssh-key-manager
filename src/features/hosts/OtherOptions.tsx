import { Plus, X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import { cn } from '@/lib/cn';
import { type OptionRow, optionProblem, optionRow, splitOption } from './model';

interface OtherOptionsProps {
  rows: OptionRow[];
  onChange: (rows: OptionRow[]) => void;
}

const INPUT =
  'field h-[34px] rounded-[10px] px-[11px] font-mono text-[12.5px] outline-none focus:border-[rgb(var(--accent-rgb)/0.55)]';

/** Any ssh_config option without its own control, as name/value rows. */
export function OtherOptions({ rows, onChange }: OtherOptionsProps) {
  const { t } = useTranslation();
  const update = (uid: number, patch: Partial<OptionRow>) =>
    onChange(rows.map((row) => (row.uid === uid ? { ...row, ...patch } : row)));
  const problems = rows.map(optionProblem);
  const message = problems.includes('missingName')
    ? t('hosts.optionNameRequired')
    : problems.includes('oneWord')
      ? t('hosts.optionNameOneWord')
      : null;

  return (
    <div className="flex flex-col gap-2">
      <h3 className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {t('hosts.otherOptions')}
      </h3>
      {rows.map((row, index) => (
        <div
          key={row.uid}
          className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_32px] items-center gap-2"
        >
          <input
            aria-label={t('hosts.optionName')}
            aria-invalid={problems[index] ? true : undefined}
            placeholder={t('hosts.optionNamePlaceholder')}
            value={row.key}
            onChange={(e) => update(row.uid, { key: e.target.value })}
            // A whole line typed into the name field becomes name + value.
            onBlur={() => update(row.uid, splitOption(row))}
            spellCheck={false}
            className={cn(INPUT, problems[index] && 'border-critical-solid/60')}
          />
          <input
            aria-label={t('hosts.optionValue')}
            placeholder={t('hosts.optionValuePlaceholder')}
            value={row.value}
            onChange={(e) => update(row.uid, { value: e.target.value })}
            spellCheck={false}
            className={INPUT}
          />
          <IconButton
            label={t('hosts.removeOption')}
            icon={<X className="size-[15px]" strokeWidth={1.75} />}
            onClick={() => onChange(rows.filter((other) => other.uid !== row.uid))}
          />
        </div>
      ))}
      {message ? (
        <p role="alert" className="text-[12px] text-critical">
          {message}
        </p>
      ) : null}
      <Button
        variant="ghost"
        size="sm"
        className="self-start text-[var(--accent-text)]"
        icon={<Plus className="size-[15px]" strokeWidth={2} />}
        onClick={() => onChange([...rows, optionRow()])}
      >
        {t('hosts.addOption')}
      </Button>
    </div>
  );
}
