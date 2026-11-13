import { ChevronDown } from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { HostEntry } from '@/bindings/HostEntry';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { CheckboxControl } from '@/components/ui/Checkbox';
import { DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { Text } from '@/features/hosts/Feedback';
import { isConcrete } from '@/features/hosts/model';
import { cn } from '@/lib/cn';
import { formatRelative } from '@/lib/format';
import { type Candidate, moved, newProgress, rotationOrder } from './plan';
import type { StepProps } from './RotateKeyDialog';
import { type Rotation, saveRotation } from './store';

interface HostsStepProps extends StepProps {
  rotation: Rotation | null;
  candidates: Candidate[];
  /** Every block of the config. */
  hosts: HostEntry[];
  loading: boolean;
  hasNewKey: boolean;
}

/** A host as this step lists it. */
interface Row {
  alias: string;
  via: string | null;
  candidate: Candidate | null;
  /** Moved already in this rotation. */
  done: boolean;
}

/** Step 1: the hosts that use the key, ticked as suggested; other hosts on request. */
export function HostsStep({
  progress,
  oldKey,
  go,
  rotation,
  candidates,
  hosts,
  loading,
  hasNewKey,
}: HostsStepProps) {
  const { t, i18n } = useTranslation();
  const labelId = useId();
  const othersId = useId();
  const [selected, setSelected] = useState<Set<string>>(
    () =>
      new Set(
        rotation
          ? rotation.hosts.map((host) => host.alias)
          : candidates.filter((c) => c.suggested).map((c) => c.alias),
      ),
  );
  const [showOthers, setShowOthers] = useState(false);

  const concrete = hosts.filter(isConcrete).filter((host) => host.patterns[0]);
  const viaOf = (alias: string) =>
    concrete.find((host) => host.patterns[0] === alias)?.proxyJump ?? null;
  const progressOf = (alias: string) => rotation?.hosts.find((host) => host.alias === alias);
  const listed = new Set(candidates.map((c) => c.alias));
  const rows: Row[] = [
    ...candidates.map((candidate) => {
      const host = progressOf(candidate.alias);
      return {
        alias: candidate.alias,
        via: candidate.via,
        candidate,
        done: Boolean(host && moved(host)),
      };
    }),
    // Hosts already moving no longer name the old key in their block.
    ...(rotation?.hosts ?? [])
      .filter((host) => !listed.has(host.alias))
      .map((host) => ({
        alias: host.alias,
        via: viaOf(host.alias),
        candidate: null,
        done: moved(host),
      })),
  ];
  const shown = new Set(rows.map((row) => row.alias));
  const others: Row[] = concrete
    .map((host) => host.patterns[0] as string)
    .filter((alias) => !shown.has(alias))
    .map((alias) => ({ alias, via: viaOf(alias), candidate: null, done: false }));

  const toggle = (alias: string, on: boolean) =>
    setSelected((current) => {
      const next = new Set(current);
      if (on) next.add(alias);
      else next.delete(alias);
      return next;
    });

  const proceed = () => {
    const chosen = rotationOrder([...rows, ...others].filter((row) => selected.has(row.alias)));
    const prior = new Map(rotation?.hosts.map((host) => [host.alias, host]));
    saveRotation({
      oldKeyId: oldKey.id,
      oldName: oldKey.name,
      oldFingerprint: oldKey.fingerprint,
      oldPath: oldKey.privatePath,
      oldPublicKey: oldKey.publicKey,
      newKeyId: rotation?.newKeyId ?? null,
      hosts: chosen.map((row) => prior.get(row.alias) ?? newProgress(row.alias)),
      updated: new Date().toISOString(),
    });
    go(hasNewKey ? 'move' : 'key');
  };

  const renderRow = (row: Row) => {
    const candidate = row.candidate;
    const meta: string[] = [];
    if (row.via) meta.push(t('rotation.hosts.via', { host: row.via }));
    if (candidate?.lastSignedIn) {
      meta.push(
        t('rotation.hosts.lastSignedIn', {
          when: formatRelative(new Date(candidate.lastSignedIn), i18n.language),
        }),
      );
    }
    const hint = candidate?.passwordOnly
      ? t('rotation.hosts.passwordHint')
      : candidate?.reason === 'default'
        ? t('rotation.hosts.defaultHint')
        : null;
    const id = `rotate-host-${row.alias}`;
    return (
      <li key={row.alias}>
        <label
          htmlFor={id}
          className={cn(
            'flex w-full cursor-pointer items-start gap-[11px] rounded-[10px] px-2.5 py-2',
            selected.has(row.alias) ? 'bg-ink/[0.04]' : 'hover:bg-fill-subtle',
          )}
        >
          <CheckboxControl
            id={id}
            checked={selected.has(row.alias)}
            onCheckedChange={(next) => toggle(row.alias, next === true)}
            aria-labelledby={`${id}-name`}
            aria-describedby={[
              `${id}-badges`,
              meta.length ? `${id}-meta` : '',
              hint ? `${id}-hint` : '',
            ]
              .filter(Boolean)
              .join(' ')}
            className="mt-[3px]"
          />
          <span className="flex min-w-0 flex-1 flex-col gap-0.5">
            <span className="flex flex-wrap items-center gap-1.5">
              <span id={`${id}-name`} className="truncate font-mono text-[13px] font-medium">
                {row.alias}
              </span>
              <span id={`${id}-badges`} className="contents">
                {candidate?.reason === 'config' ? (
                  <Badge tone="accent">{t('rotation.hosts.reasonConfig')}</Badge>
                ) : null}
                {candidate?.reason === 'pattern' ? (
                  <Badge>{t('rotation.hosts.reasonPattern')}</Badge>
                ) : null}
                {candidate?.reason === 'default' ? (
                  <Badge tone="info">{t('rotation.hosts.reasonDefault')}</Badge>
                ) : null}
                {candidate?.passwordOnly ? (
                  <Badge tone="warning">{t('rotation.hosts.passwordOnly')}</Badge>
                ) : null}
                {row.done ? <Badge tone="accent">{t('rotation.hosts.moved')}</Badge> : null}
              </span>
            </span>
            {meta.length ? (
              <span id={`${id}-meta`} className="text-[12px] text-subtle">
                {meta.join(' · ')}
              </span>
            ) : null}
            {hint ? (
              <span id={`${id}-hint`} className="text-[12px] leading-[17px] text-muted">
                {hint}
              </span>
            ) : null}
          </span>
        </label>
      </li>
    );
  };

  const count = selected.size;
  return (
    <>
      <DialogBody>
        {progress}
        {loading ? (
          <div className="grid place-items-center py-6 text-subtle">
            <Spinner className="size-5" />
          </div>
        ) : (
          <>
            <Text id={labelId}>
              {rows.length
                ? t('rotation.hosts.text', { name: oldKey.name })
                : t('rotation.hosts.none', { name: oldKey.name })}
            </Text>
            {rows.length ? (
              <ul
                aria-labelledby={labelId}
                className="glass flex max-h-[300px] flex-col gap-0.5 overflow-y-auto rounded-[14px] p-1.5"
              >
                {rows.map(renderRow)}
              </ul>
            ) : null}
            {others.length ? (
              <div className="-mt-2 flex flex-col gap-2">
                <Button
                  variant="ghost"
                  size="sm"
                  className="self-start text-[var(--accent-text)]"
                  aria-expanded={showOthers}
                  aria-controls={othersId}
                  icon={
                    <ChevronDown
                      aria-hidden="true"
                      className={cn('size-[15px] transition-transform', showOthers && 'rotate-180')}
                      strokeWidth={2}
                    />
                  }
                  onClick={() => setShowOthers((open) => !open)}
                >
                  {t('rotation.hosts.others', { count: others.length })}
                </Button>
                {showOthers ? (
                  <div id={othersId} className="flex flex-col gap-2">
                    <p className="text-[12px] text-subtle">{t('rotation.hosts.othersHint')}</p>
                    <ul
                      aria-label={t('rotation.hosts.othersLabel')}
                      className="glass flex max-h-[220px] flex-col gap-0.5 overflow-y-auto rounded-[14px] p-1.5"
                    >
                      {others.map(renderRow)}
                    </ul>
                  </div>
                ) : null}
              </div>
            ) : null}
          </>
        )}
      </DialogBody>
      <DialogFooter>
        <span aria-live="polite" className="mr-auto text-[12px] text-subtle">
          {t('rotation.hosts.selected', { count })}
        </span>
        <Button variant="primary" size="lg" disabled={loading} onClick={proceed}>
          {count ? t('rotation.continue') : t('rotation.hosts.continueWithout')}
        </Button>
      </DialogFooter>
    </>
  );
}
