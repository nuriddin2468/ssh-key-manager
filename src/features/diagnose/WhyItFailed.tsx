import { useMutation } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { ChevronDown, ChevronUp, TriangleAlert } from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useEnvironment, useHostsFile } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { Diagnosis } from '@/bindings/Diagnosis';
import type { PortProbe } from '@/bindings/PortProbe';
import { Button } from '@/components/ui/Button';
import { lookupName } from '@/features/hostsFile/model';
import { copyText } from '@/lib/clipboard';
import { displayPath } from '@/lib/format';
import { AppError } from '@/lib/ipc';
import {
  type DiagnoseFix,
  diagnosisMessage,
  type HostFacts,
  messageValues,
  offeredKeys,
  unresolvedName,
} from './model';

/** Fixes the page runs, given the diagnosis they fix. */
export type DiagnoseFixes = Partial<Record<DiagnoseFix, (diagnosis: Diagnosis) => void>>;

interface WhyItFailedProps {
  diagnosis: Diagnosis;
  alias: string;
  facts: HostFacts;
  /** A fix with no handler here is left out, except the ones the panel runs itself. */
  onFix: DiagnoseFixes;
  /** The host key's public line, for "Copy public key". */
  publicKey?: string;
  /** The cause as a heading of this level (the terminal's card); plain text otherwise. */
  heading?: 'h2';
  /** Buttons after the fixes, such as "Try again". */
  actions?: ReactNode;
  /**
   * Announce what the panel's own checks find. Leave it off inside a live
   * region, which announces them already.
   */
  announce?: boolean;
}

/**
 * "Why it failed": the cause of a failed connection in plain words, what
 * ssh said about it, and one or two fixes.
 */
export function WhyItFailed({
  diagnosis,
  alias,
  facts,
  onFix,
  publicKey,
  heading,
  actions,
  announce = false,
}: WhyItFailedProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const home = useEnvironment().data?.paths.home;
  const hostsFile = useHostsFile();
  const message = diagnosisMessage(diagnosis, facts);
  const linesId = useId();
  // Nothing else to go on for an unknown cause: its lines show at once.
  const [linesShown, setLinesShown] = useState(diagnosis.cause.kind === 'unknown');

  const probe = useMutation({
    mutationFn: () => api.diagnoseProbe(alias),
    onError: (error) => {
      if (AppError.from(error).code !== 'unsupported') toastError(t, error);
    },
  });
  const name = unresolvedName(diagnosis);
  const lookup = useMutation({
    mutationFn: api.lookupHost,
    onError: (error) => toastError(t, error),
  });
  const fixPermissions = useMutation({
    mutationFn: api.diagnoseFixPermissions,
    onSuccess: (fixed) => {
      if (fixed) toast.success(t('diagnose.permissionsFixed'));
      else {
        toast.info(t('diagnose.permissionsNotOffered'), {
          action: {
            label: t('diagnose.fix.openAudit'),
            onClick: () => navigate({ page: 'audit' }),
          },
        });
      }
    },
    onError: (error) => toastError(t, error),
  });

  const values = messageValues(message, alias, home);
  const path = diagnosis.cause.kind === 'badPermissions' ? diagnosis.cause.path : null;

  /** The panel's own fixes, then the page's. */
  const run: Partial<Record<DiagnoseFix, () => void>> = {
    probe: () => probe.mutate(),
    ...(name ? { lookup: () => lookup.mutate(name) } : {}),
    ...(path ? { fixPermissions: () => fixPermissions.mutate(path) } : {}),
    unlockVault: () => dialogs.unlockVault(),
    ...(publicKey
      ? {
          copyPublicKey: () =>
            void copyText(publicKey).then(
              () => toast.success(t('diagnose.publicKeyCopied')),
              (error: unknown) => toastError(t, error),
            ),
        }
      : {}),
  };
  for (const fix of Object.keys(onFix) as DiagnoseFix[]) {
    const handler = onFix[fix];
    if (handler && !run[fix]) run[fix] = () => handler(diagnosis);
  }
  const fixes = message.fixes.filter((fix) => run[fix]);
  const busy: Partial<Record<DiagnoseFix, boolean>> = {
    probe: probe.isPending,
    lookup: lookup.isPending,
    fixPermissions: fixPermissions.isPending,
  };
  const label = (fix: DiagnoseFix) =>
    fix === 'editPassword' && diagnosis.cause.kind === 'passwordRequired'
      ? t('diagnose.fix.savePassword')
      : t(`diagnose.fix.${fix}`);

  const Title = heading ?? 'span';
  const keys = offeredKeys(diagnosis.cause);
  const changed = diagnosis.cause.kind === 'hostKeyChanged' ? diagnosis.cause : null;

  return (
    <div className="flex min-w-0 flex-1 flex-col items-start gap-1">
      <span className="text-[11.5px] font-medium text-subtle">
        {t('diagnose.title')}
        {diagnosis.hop ? ` · ${t('diagnose.atHop', { hop: diagnosis.hop })}` : null}
      </span>
      <Title
        className={heading ? 'text-[14px] font-semibold' : 'font-medium'}
        // A long path or host name wraps instead of widening the card.
        style={{ overflowWrap: 'anywhere' }}
      >
        {t(`diagnose.cause.${message.title}`, values)}
      </Title>
      <p className="text-[12.5px] leading-[18px] text-muted" style={{ overflowWrap: 'anywhere' }}>
        {t(`diagnose.cause.${message.detail}`, values)}
      </p>

      {keys.length > 0 ? (
        <div className="mt-1.5 flex w-full min-w-0 flex-col gap-0.5">
          <span className="text-[12px] text-subtle">{t('diagnose.offered')}</span>
          <ul className="flex min-w-0 flex-col gap-0.5">
            {keys.map((key) => (
              // One line each: the name first; a long fingerprint is cut,
              // whole in its tooltip (and when copied or read out).
              <li
                key={`${key.name}${key.fingerprint ?? ''}`}
                className="selectable flex min-w-0 items-baseline gap-1.5 font-mono text-[11.5px] leading-[17px]"
              >
                <span className="max-w-[60%] shrink-0 truncate text-fg-2" title={key.name}>
                  {displayPath(key.name, home)}
                </span>
                {key.keyType ? <span className="shrink-0 text-subtle">{key.keyType}</span> : null}
                {key.fingerprint ? (
                  <span className="min-w-0 truncate text-subtle" title={key.fingerprint}>
                    {key.fingerprint}
                  </span>
                ) : null}
                {key.agent ? (
                  <span className="shrink-0 font-sans text-subtle">{t('diagnose.fromAgent')}</span>
                ) : null}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {changed?.fingerprint || changed?.knownHosts ? (
        <div
          className="selectable mt-1.5 flex flex-col gap-0.5 font-mono text-[11.5px] leading-[17px] text-fg-2"
          style={{ overflowWrap: 'anywhere' }}
        >
          {changed.fingerprint ? (
            <span>{t('diagnose.newKey', { fingerprint: changed.fingerprint })}</span>
          ) : null}
          {changed.knownHosts ? (
            <span>
              {t('diagnose.savedKey', { knownHosts: displayPath(changed.knownHosts, home) })}
            </span>
          ) : null}
        </div>
      ) : null}

      {message.unlockVault ? (
        <p className="text-[12.5px] leading-[18px] text-muted">
          {t('hosts.vault.result.keysRejectedLockedHint')}
        </p>
      ) : null}

      {message.warning ? (
        <p className="mt-0.5 flex gap-1.5 text-[12px] leading-[18px] text-warning">
          <TriangleAlert aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" strokeWidth={2} />
          {t(`diagnose.cause.${message.warning}`)}
        </p>
      ) : null}

      {fixes.length > 0 || actions ? (
        <div className="mt-2 flex flex-wrap gap-2">
          {fixes.map((fix, index) => (
            <Button
              key={fix}
              size="sm"
              variant={index === 0 ? 'primary' : 'secondary'}
              loading={busy[fix]}
              onClick={run[fix]}
            >
              {label(fix)}
            </Button>
          ))}
          {actions}
        </div>
      ) : null}

      {/* What the panel's own checks found. */}
      <div aria-live={announce ? 'polite' : undefined} className="flex flex-col empty:hidden">
        {probe.isPending ? (
          <Note>{t('diagnose.probe.running', { port: values.port || '22' })}</Note>
        ) : probe.data ? (
          <ProbeResult probe={probe.data} />
        ) : null}
        {probe.error && AppError.from(probe.error).code === 'unsupported' ? (
          <Note>{t('diagnose.probe.proxyCommand')}</Note>
        ) : null}
        {name && lookup.data ? (
          <Note>
            {lookupText(t, name, lookup.data, lookupName(hostsFile.data?.view.entries ?? [], name))}
          </Note>
        ) : null}
      </div>

      {diagnosis.lines.length > 0 ? (
        <>
          <Button
            variant="ghost"
            size="sm"
            className="-ml-3"
            aria-expanded={linesShown}
            aria-controls={linesShown ? linesId : undefined}
            onClick={() => setLinesShown((shown) => !shown)}
            icon={
              linesShown ? (
                <ChevronUp aria-hidden="true" className="size-3.5" />
              ) : (
                <ChevronDown aria-hidden="true" className="size-3.5" />
              )
            }
          >
            {t('diagnose.output')}
          </Button>
          {linesShown ? (
            // Scrolls when long, so it takes focus for keyboard scrolling.
            <section
              id={linesId}
              aria-label={t('diagnose.output')}
              // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
              tabIndex={0}
              className="max-h-40 w-full overflow-auto rounded-[11px] border border-ink/[0.07] bg-well px-3 py-2"
            >
              <pre className="selectable font-mono text-[11.5px] leading-[17px] whitespace-pre-wrap text-fg-2">
                {diagnosis.lines.join('\n')}
              </pre>
            </section>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

function Note({ children }: { children: ReactNode }) {
  return (
    <p className="mt-1 text-[12.5px] leading-[18px] text-fg-2" style={{ overflowWrap: 'anywhere' }}>
      {children}
    </p>
  );
}

function ProbeResult({ probe }: { probe: PortProbe }) {
  const { t } = useTranslation();
  const values = { host: probe.host, port: String(probe.port) };
  return <Note>{t(`diagnose.probe.${probe.outcome}` as const, values)}</Note>;
}

/** What the hosts file and DNS say about `name`, as the hosts file page says it. */
function lookupText(
  t: TFunction,
  name: string,
  answer: { addresses: string[] },
  matches: ReturnType<typeof lookupName>,
): string {
  const pinned = matches.find((m) => m.used);
  if (pinned) return t('hostsFile.pinned', { name, address: pinned.entry.address });
  if (answer.addresses.length > 0) {
    return t('hostsFile.resolvesTo', { name, addresses: answer.addresses.join(', ') });
  }
  return t('hostsFile.notFound', { name });
}
