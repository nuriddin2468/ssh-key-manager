import { ChevronDown, ScrollText } from 'lucide-react';
import type { FormEvent, ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useConfig } from '@/api/queries';
import { Badge, type BadgeTone } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/components/ui/Menu';
import { TextField } from '@/components/ui/TextField';
import { cn } from '@/lib/cn';
import { type ConfigTarget, configTargets } from './model';

/** The form above a network tool's result: its fields, then the button that runs it. */
export function ToolForm({
  onSubmit,
  children,
  action,
}: {
  onSubmit: () => void;
  children: ReactNode;
  action: ReactNode;
}) {
  const submit = (event: FormEvent) => {
    event.preventDefault();
    onSubmit();
  };
  return (
    <form
      onSubmit={submit}
      className="glass flex flex-wrap items-start gap-3 rounded-2xl p-4 [&>*]:min-w-0"
    >
      {children}
      {/* The labels above the fields are 18px plus a 6px gap. */}
      <div className="flex shrink-0 pt-6">{action}</div>
    </form>
  );
}

/** A host field, with a menu of the hosts in ~/.ssh/config when `onPick` is given. */
export function HostField({
  value,
  onChange,
  invalid,
  label,
  placeholder,
  onPick,
}: {
  value: string;
  onChange: (value: string) => void;
  invalid: boolean;
  label?: string;
  placeholder?: string;
  onPick?: (target: ConfigTarget) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="flex min-w-[240px] flex-[2_1_260px] items-start gap-2">
      <TextField
        label={label ?? t('toolNetwork.host')}
        mono
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder ?? t('toolNetwork.hostPlaceholder')}
        error={invalid ? t('toolNetwork.hostInvalid') : undefined}
        className="flex-1"
        autoFocus
      />
      {onPick ? <ConfigPicker onPick={onPick} /> : null}
    </div>
  );
}

function ConfigPicker({ onPick }: { onPick: (target: ConfigTarget) => void }) {
  const { t } = useTranslation();
  const config = useConfig();
  const targets = configTargets(config.data?.view.hosts ?? []);
  return (
    <Menu>
      <MenuTrigger asChild>
        <Button
          className="mt-6"
          aria-label={t('toolNetwork.fromConfig')}
          icon={<ScrollText aria-hidden="true" className="size-4" strokeWidth={1.9} />}
        >
          <span className="max-[720px]:sr-only">~/.ssh/config</span>
          <ChevronDown aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />
        </Button>
      </MenuTrigger>
      <MenuContent align="end">
        {targets.length === 0 ? (
          <MenuItem disabled onSelect={() => undefined}>
            {t('toolNetwork.noConfigHosts')}
          </MenuItem>
        ) : (
          targets.map((target) => (
            <MenuItem key={target.alias} onSelect={() => onPick(target)}>
              <span className="min-w-0 flex-1 truncate">{target.alias}</span>
              {target.host !== target.alias || target.port !== 22 ? (
                <span className="ml-3 truncate font-mono text-[11.5px] text-subtle">
                  {target.host}
                  {target.port !== 22 ? `:${target.port}` : ''}
                </span>
              ) : null}
            </MenuItem>
          ))
        )}
      </MenuContent>
    </Menu>
  );
}

export function PortField({
  value,
  onChange,
  invalid,
}: {
  value: string;
  onChange: (value: string) => void;
  invalid: boolean;
}) {
  const { t } = useTranslation();
  return (
    <TextField
      label={t('toolNetwork.port')}
      mono
      inputMode="numeric"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      error={invalid ? t('toolNetwork.portInvalid') : undefined}
      className="w-[104px] shrink-0"
    />
  );
}

/**
 * Where a tool's answer appears. It stays in the page while empty, so
 * screen readers announce the answer when it arrives.
 */
export function LiveRegion({ busy, children }: { busy: boolean; children: ReactNode }) {
  return (
    <div aria-live="polite" aria-busy={busy} className="flex flex-col gap-3">
      {children}
    </div>
  );
}

/** A tool's answer: a badge and a headline, then details. */
export function ResultCard({
  tone,
  badge,
  title,
  children,
  className,
}: {
  tone: BadgeTone;
  badge: ReactNode;
  title: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn('glass flex flex-col gap-3 rounded-2xl p-4 animate-fade-in', className)}>
      <div className="flex flex-wrap items-center gap-2.5">
        <Badge tone={tone}>{badge}</Badge>
        <h2 className="selectable min-w-0 flex-1 text-[14.5px] leading-5 font-semibold [overflow-wrap:anywhere]">
          {title}
        </h2>
      </div>
      {children}
    </section>
  );
}

/** A short coloured note inside a result: what to make of it. */
export function Note({
  tone = 'neutral',
  icon,
  children,
}: {
  tone?: 'neutral' | 'warning' | 'critical';
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <p
      className={cn(
        'flex items-start gap-2 rounded-xl border px-3 py-2 text-[12.5px] leading-[18px]',
        tone === 'neutral' && 'border-white/[0.08] bg-white/[0.03] text-fg-2',
        tone === 'warning' && 'border-warning-solid/30 bg-warning-solid/[0.08] text-warning',
        tone === 'critical' && 'border-critical-solid/30 bg-critical-solid/[0.08] text-critical',
      )}
    >
      {icon ? <span className="mt-px flex shrink-0">{icon}</span> : null}
      <span className="selectable min-w-0 [overflow-wrap:anywhere]">{children}</span>
    </p>
  );
}

/** Label and value pairs, two columns where there is room. */
export function Facts({ items }: { items: readonly { label: ReactNode; value: ReactNode }[] }) {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1.5 text-[12.5px]">
      {items.map((item, index) => (
        // Labels can repeat (two names); the order never changes.
        // biome-ignore lint/suspicious/noArrayIndexKey: a fixed list
        <div key={index} className="contents">
          <dt className="text-subtle">{item.label}</dt>
          <dd className="selectable min-w-0 font-mono text-fg-2 [overflow-wrap:anywhere]">
            {item.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** A small muted line under a tool, about what it does on the network. */
export function ToolNote({ children }: { children: ReactNode }) {
  return <p className="px-1 text-[12px] leading-[17px] text-subtle">{children}</p>;
}
