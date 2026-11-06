import { useQuery } from '@tanstack/react-query';
import { ArrowLeftRight, Check, ChevronDown, Equal, Minus, Plus } from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { errorMessage } from '@/api/useAppMutation';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { envLabel, isProduction } from './model';

interface CompareDialogProps {
  env: EnvSummary;
  all: EnvSummary[];
  onDone: () => void;
}

/**
 * Which variables one environment lacks, adds or sets differently than
 * another. The backend compares the values; only names come here.
 */
export function CompareDialog({ env, all, onDone }: CompareDialogProps) {
  const { t } = useTranslation();
  const others = all.filter((other) => !other.inTrash && other.id !== env.id);
  // The same project's production first: what most comparisons are about.
  const [otherId, setOtherId] = useState(
    () =>
      (
        others.find((other) => other.project === env.project && isProduction(other.name)) ??
        others.find((other) => other.project === env.project) ??
        others[0]
      )?.id ?? '',
  );
  const other = others.find((item) => item.id === otherId);
  const comparison = useQuery({
    queryKey: ['vault', 'envs', 'compare', env.id, otherId, env.modified, other?.modified],
    queryFn: () => api.envsCompare(env.id, otherId),
    enabled: otherId !== '',
    gcTime: 0,
  });
  const result = comparison.data;
  const differences = result
    ? result.onlyLeft.length + result.onlyRight.length + result.changed.length
    : 0;

  return (
    <DialogContent section="envs" className="max-w-[600px]">
      <DialogHeader
        icon={
          <Tile tone="lime" size={44} glow>
            <ArrowLeftRight className="size-[22px]" strokeWidth={2} />
          </Tile>
        }
        title={t('envs.compareDialog.title')}
        description={t('envs.compareDialog.description')}
      />
      <DialogBody>
        <div className="grid grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)] items-end gap-3">
          <div className="flex min-w-0 flex-col gap-1.5">
            <span className="text-[12px] font-semibold text-fg-2">
              {t('envs.compareDialog.this')}
            </span>
            <span className="field flex h-9 min-w-0 items-center truncate rounded-[10px] px-[11px] text-fg-2">
              {envLabel(env)}
            </span>
          </div>
          <ArrowLeftRight aria-hidden="true" className="mb-2.5 size-4 text-subtle" />
          <Select
            label={t('envs.compareDialog.with')}
            value={otherId}
            onValueChange={setOtherId}
            options={others.map((item) => ({ value: item.id, label: envLabel(item) }))}
          />
        </div>

        {comparison.isPending && otherId ? (
          <div className="grid place-items-center py-8 text-subtle">
            <Spinner className="size-5" />
          </div>
        ) : comparison.isError ? (
          <p role="alert" className="text-[12.5px] text-critical">
            {errorMessage(t, comparison.error)}
          </p>
        ) : result && other ? (
          <div aria-live="polite" className="flex flex-col gap-3">
            {differences === 0 ? (
              <p className="flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3.5 py-3 text-fg-2">
                <Check aria-hidden="true" className="size-4 text-ok" strokeWidth={2.2} />
                {t('envs.compareDialog.identical', { count: result.same.length })}
              </p>
            ) : null}
            <Group
              icon={<Minus className="size-3.5" strokeWidth={2.4} />}
              tone="critical"
              title={t('envs.compareDialog.missing', { name: envLabel(other) })}
              names={result.onlyLeft}
            />
            <Group
              icon={<Plus className="size-3.5" strokeWidth={2.4} />}
              tone="info"
              title={t('envs.compareDialog.extra', { name: envLabel(other) })}
              names={result.onlyRight}
            />
            <Group
              icon={<ArrowLeftRight className="size-3.5" strokeWidth={2.2} />}
              tone="warning"
              title={t('envs.compareDialog.changed')}
              names={result.changed}
            />
            <Group
              icon={<Equal className="size-3.5" strokeWidth={2.2} />}
              tone="neutral"
              title={t('envs.compareDialog.same')}
              names={result.same}
              folded
            />
          </div>
        ) : null}
      </DialogBody>
      <DialogFooter>
        <Button size="lg" onClick={onDone}>
          {t('common.close')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

const TONES = {
  critical: 'text-critical bg-critical-solid/12',
  info: 'text-info bg-info-solid/12',
  warning: 'text-warning bg-warning-solid/12',
  neutral: 'text-muted bg-white/[0.06]',
} as const;

interface GroupProps {
  icon: ReactNode;
  tone: keyof typeof TONES;
  title: string;
  names: string[];
  /** Starts folded: the same values matter least. */
  folded?: boolean;
}

function Group({ icon, tone, title, names, folded = false }: GroupProps) {
  const { t } = useTranslation();
  const listId = useId();
  const [open, setOpen] = useState(!folded);
  if (names.length === 0) return null;
  return (
    <section className="glass flex flex-col rounded-[14px]">
      <h3>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={listId}
          onClick={() => setOpen((value) => !value)}
          className="pressable-soft flex w-full items-center gap-2.5 rounded-[14px] px-3.5 py-2.5 text-left"
        >
          <span
            aria-hidden="true"
            className={cn('grid size-6 shrink-0 place-items-center rounded-md', TONES[tone])}
          >
            {icon}
          </span>
          <span className="min-w-0 flex-1 font-semibold">{title}</span>
          <span className="text-subtle tabular-nums">
            {t('envs.compareDialog.count', { count: names.length })}
          </span>
          <ChevronDown
            aria-hidden="true"
            className={cn('size-4 text-subtle transition-transform', open && 'rotate-180')}
          />
        </button>
      </h3>
      {open ? (
        <ul id={listId} className="flex flex-wrap gap-1.5 px-3.5 pb-3">
          {names.map((name) => (
            <li
              key={name}
              className="selectable rounded-md border border-white/10 bg-white/[0.04] px-2 py-0.5 font-mono text-[12px] text-fg-2"
            >
              {name}
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
