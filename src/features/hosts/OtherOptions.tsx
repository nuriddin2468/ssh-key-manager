import { ChevronRight, Plus, X } from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { HostEntry } from '@/bindings/HostEntry';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import { SwitchGroup } from '@/components/ui/Switch';
import { cn } from '@/lib/cn';
import { ForwardAgentRow, JumpHostSelect } from './HostFields';
import {
  type HostForm,
  type OptionRow,
  optionProblem,
  optionRow,
  splitOption,
  suppressedOption,
} from './model';

interface MoreSectionProps {
  form: HostForm;
  set: <K extends keyof HostForm>(key: K, value: HostForm[K]) => void;
  hosts: readonly HostEntry[];
  hostId: number;
}

/**
 * Jump host, agent forwarding and every other option, folded away under a
 * one-line summary ("ProxyJump bastion · 1 more option"). It opens by
 * itself while an option row has a problem.
 */
export function MoreSection({ form, set, hosts, hostId }: MoreSectionProps) {
  const { t } = useTranslation();
  const panelId = useId();
  const [open, setOpen] = useState(false);
  // Rows the sign-in method sets aside stay in the form but aren't shown.
  const hidden = new Set(form.other.filter((row) => suppressedOption(form, row)).map((r) => r.uid));
  const rows = form.other.filter((row) => !hidden.has(row.uid));
  const expanded = open || rows.some((row) => optionProblem(row));

  const changeRows = (next: OptionRow[]) => {
    const byUid = new Map(next.map((row) => [row.uid, row]));
    const kept = form.other.flatMap((row) => {
      if (hidden.has(row.uid)) return [row];
      const updated = byUid.get(row.uid);
      return updated ? [updated] : [];
    });
    const added = next.filter((row) => !form.other.some((other) => other.uid === row.uid));
    set('other', [...kept, ...added]);
  };

  const count = (form.forwardAgent ? 1 : 0) + rows.filter((row) => splitOption(row).key).length;
  const jump = form.proxyJump.trim();
  const summary = jump
    ? [
        t('hosts.editor.moreJump', { jump }),
        count > 0 ? t('hosts.editor.moreCountAfter', { count }) : '',
      ]
        .filter(Boolean)
        .join(' · ')
    : count > 0
      ? t('hosts.editor.moreCount', { count })
      : t('hosts.editor.moreEmpty');

  return (
    <div className="flex flex-col gap-3">
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={expanded ? panelId : undefined}
        onClick={() => setOpen(!expanded)}
        className="pressable-soft flex min-w-0 items-center gap-2.5 rounded-[14px] border border-white/[0.08] bg-white/[0.03] px-3.5 py-3 text-left text-fg-2 hover:bg-white/[0.05]"
      >
        <ChevronRight
          aria-hidden="true"
          className={cn(
            'size-4 shrink-0 text-subtle transition-transform duration-150',
            expanded && 'rotate-90',
          )}
          strokeWidth={2}
        />
        <span className="font-semibold text-fg">{t('hosts.editor.more')}</span>
        <span className="min-w-0 truncate text-subtle">{summary}</span>
      </button>
      {expanded ? (
        <div id={panelId} className="flex flex-col gap-3.5">
          <div className="grid grid-cols-2 gap-3">
            <JumpHostSelect
              value={form.proxyJump}
              onChange={(value) => set('proxyJump', value)}
              hosts={hosts}
              hostId={hostId}
            />
          </div>
          <SwitchGroup>
            <ForwardAgentRow
              checked={form.forwardAgent}
              onChange={(value) => set('forwardAgent', value)}
            />
          </SwitchGroup>
          <OtherOptions rows={rows} onChange={changeRows} />
        </div>
      ) : null}
    </div>
  );
}

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
