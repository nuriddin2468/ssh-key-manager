import { Check, Circle, Copy, Minus, X } from 'lucide-react';
import { useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { toastError } from '@/api/useAppMutation';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { ErrorBox, Live, OkBox, Text } from '@/features/hosts/Feedback';
import { LoginResult } from '@/features/hosts/LoginResult';
import { useUnlockFix } from '@/features/hosts/useUnlockFix';
import { copyText } from '@/lib/clipboard';
import { cn } from '@/lib/cn';
import { type HostProgress, moved, type StepState } from './plan';
import type { StepProps } from './RotateKeyDialog';
import type { Rotation } from './store';
import type { Failure, HostStep, useRotationRun } from './useRotationRun';

interface MoveStepProps extends StepProps {
  rotation: Rotation;
  newKey: KeyView;
  run: ReturnType<typeof useRotationRun>;
  onClose: () => void;
}

const STEPS = ['install', 'verify', 'config'] as const;

/**
 * Step 3: each host in turn gets the new key (signed in with the old one),
 * lets the user in with the new key alone, then names it in its block. A
 * host that fails stops there and can be tried again, now or later.
 */
export function MoveStep({ progress, oldKey, go, rotation, newKey, run, onClose }: MoveStepProps) {
  const { t } = useTranslation();
  const working = run.active !== null;
  const hosts = rotation.hosts;
  const left = hosts.filter((host) => !moved(host));
  const untried = left.filter((host) => STEPS.every((step) => host[step] !== 'failed'));
  const allMoved = left.length === 0;
  const primary = useRef<HTMLDivElement>(null);
  const focusPrimary = () =>
    requestAnimationFrame(() => primary.current?.querySelector<HTMLElement>('button')?.focus());

  const start = async (aliases: string[]) => {
    await run.move(aliases);
    focusPrimary();
  };

  let label: string;
  let action: () => void;
  if (allMoved) {
    label = t('rotation.continue');
    action = () => go('cleanup');
  } else if (untried.length) {
    label = t('rotation.move.start', { count: untried.length });
    action = () => void start(untried.map((host) => host.alias));
  } else {
    label = t('rotation.move.retryAll', { count: left.length });
    action = () => void start(left.map((host) => host.alias));
  }

  return (
    <>
      <DialogBody>
        {progress}
        <Text>
          {hosts.length
            ? t('rotation.move.text', { old: oldKey.name, key: newKey.name })
            : t('rotation.move.noHosts', { key: newKey.name })}
        </Text>
        {hosts.length ? (
          <ul className="flex flex-col gap-2">
            {hosts.map((host) => (
              <HostRow
                key={host.alias}
                host={host}
                newKey={newKey}
                active={run.active?.alias === host.alias ? run.active.step : null}
                failure={run.failures[host.alias]}
                disabled={working}
                onRetry={() => void start([host.alias])}
                onAddedByHand={() => void run.addedByHand(host.alias)}
                onInstallAgain={() => void run.installAgain(host.alias)}
                onUnlocked={() => void start([host.alias])}
              />
            ))}
          </ul>
        ) : null}
        <Live>
          {allMoved && hosts.length ? (
            <OkBox>{t('rotation.move.allMoved', { key: newKey.name })}</OkBox>
          ) : null}
          {!allMoved && !working && hosts.length ? (
            <span className="sr-only">
              {t('rotation.move.status', {
                moved: hosts.length - left.length,
                total: hosts.length,
                failed: left.length - untried.length,
              })}
            </span>
          ) : null}
        </Live>
      </DialogBody>
      <DialogFooter>
        <Button
          size="lg"
          variant="ghost"
          className="mr-auto"
          disabled={working}
          onClick={() => go('hosts')}
        >
          {t('rotation.back')}
        </Button>
        {!allMoved ? (
          <Button size="lg" disabled={working} onClick={onClose}>
            {t('rotation.later')}
          </Button>
        ) : null}
        {!allMoved && !untried.length && left.length < hosts.length ? (
          <Button size="lg" disabled={working} onClick={() => go('cleanup')}>
            {t('rotation.move.cleanUpNow')}
          </Button>
        ) : null}
        <div ref={primary} className="contents">
          <Button
            variant="primary"
            size="lg"
            className="aria-disabled:opacity-50"
            aria-busy={working || undefined}
            aria-disabled={working || undefined}
            icon={working ? <Spinner className="size-4" /> : undefined}
            onClick={() => {
              if (!working) action();
            }}
          >
            {label}
          </Button>
        </div>
      </DialogFooter>
    </>
  );
}

interface HostRowProps {
  host: HostProgress;
  newKey: KeyView;
  /** The step running on this host now. */
  active: HostStep | null;
  failure: Failure | undefined;
  disabled: boolean;
  onRetry: () => void;
  onAddedByHand: () => void;
  onInstallAgain: () => void;
  onUnlocked: () => void;
}

/** One host: its three steps, and what went wrong with the last one tried. */
function HostRow({
  host,
  newKey,
  active,
  failure,
  disabled,
  onRetry,
  onAddedByHand,
  onInstallAgain,
  onUnlocked,
}: HostRowProps) {
  const { t } = useTranslation();
  const unlockFix = useUnlockFix(onUnlocked);
  const failedStep = STEPS.find((step) => host[step] === 'failed');
  const done = moved(host);
  const stepLabel = (step: HostStep) => t(`rotation.move.step.${step}`);

  const copyPublic = async () => {
    try {
      await copyText(newKey.publicKey ?? '');
      toast.success(t('keys.copiedPublic'));
    } catch (error) {
      toastError(t, error);
    }
  };

  return (
    <li
      className={cn(
        'glass flex flex-col gap-2 rounded-[14px] px-3 py-2.5',
        // `glass` sets the border; this colour has to win over it.
        failedStep && !active && 'border-critical-solid/35!',
      )}
      aria-busy={active ? true : undefined}
    >
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <span className="min-w-0 flex-1 truncate font-mono text-[13px] font-medium">
          {host.alias}
        </span>
        <ol className="flex flex-wrap items-center gap-x-3 gap-y-1">
          {STEPS.map((step) => (
            <StepChip
              key={step}
              label={stepLabel(step)}
              state={host[step]}
              running={active === step}
              skippedLabel={step === 'install' ? t('rotation.move.byHand') : undefined}
            />
          ))}
        </ol>
      </div>

      {failedStep && !active ? (
        <div className="flex flex-col gap-2">
          {failure ? (
            <FailureView
              failure={failure}
              newKey={newKey}
              alias={host.alias}
              unlockFix={unlockFix}
            />
          ) : (
            <p className="text-[12.5px] text-muted">
              {t('rotation.move.failedBefore', { step: stepLabel(failedStep) })}
            </p>
          )}
          <div className="flex flex-wrap gap-1.5">
            <Button size="sm" disabled={disabled} onClick={onRetry}>
              {t('common.retry')}
            </Button>
            {failedStep === 'install' ? (
              <>
                <Button size="sm" variant="ghost" disabled={disabled} onClick={onAddedByHand}>
                  {t('rotation.move.addedByHand')}
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<Copy aria-hidden="true" className="size-[14px]" strokeWidth={2} />}
                  onClick={() => void copyPublic()}
                >
                  {t('rotation.move.copyPublic')}
                </Button>
              </>
            ) : null}
            {failedStep === 'verify' && failure?.kind === 'otherKey' && host.install === 'done' ? (
              <Button size="sm" variant="ghost" disabled={disabled} onClick={onInstallAgain}>
                {t('rotation.move.installAgain')}
              </Button>
            ) : null}
          </div>
          {failedStep === 'install' ? (
            <p className="text-[12px] leading-[17px] text-subtle">
              {t('rotation.move.byHandHint')}
            </p>
          ) : null}
        </div>
      ) : null}
      {done ? <span className="sr-only">{t('rotation.move.hostMoved')}</span> : null}
    </li>
  );
}

function StepChip({
  label,
  state,
  running,
  skippedLabel,
}: {
  label: string;
  state: StepState;
  running: boolean;
  skippedLabel?: string;
}) {
  const { t } = useTranslation();
  const icon = running ? (
    <Spinner className="size-3" />
  ) : state === 'done' ? (
    <Check aria-hidden="true" className="size-3.5 text-ok" strokeWidth={2.5} />
  ) : state === 'failed' ? (
    <X aria-hidden="true" className="size-3.5 text-critical" strokeWidth={2.5} />
  ) : state === 'skipped' ? (
    <Minus aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2.5} />
  ) : (
    <Circle aria-hidden="true" className="size-3 text-subtle" strokeWidth={2} />
  );
  const stateText = running
    ? t('rotation.move.state.running')
    : state === 'skipped' && skippedLabel
      ? skippedLabel
      : t(`rotation.move.state.${state}`);
  return (
    <li
      className={cn(
        'inline-flex items-center gap-1.5 text-[12px]',
        state === 'done' ? 'text-fg-2' : state === 'failed' ? 'text-critical' : 'text-subtle',
        running && 'text-fg',
      )}
    >
      {icon}
      {label}
      <span className="sr-only">: {stateText}</span>
    </li>
  );
}

/** What went wrong with a host's last step, with the fix the result calls for. */
export function FailureView({
  failure,
  newKey,
  alias,
  unlockFix,
}: {
  failure: Failure;
  newKey: KeyView;
  alias: string;
  unlockFix: ReturnType<typeof useUnlockFix>;
}) {
  const { t } = useTranslation();
  switch (failure.kind) {
    case 'login':
      return (
        <LoginResult
          run={failure.run}
          context={
            failure.step === 'verify' ? 'keyLogin' : failure.step === 'install' ? 'install' : 'test'
          }
          alias={alias}
          onAction={unlockFix(failure.run)}
        />
      );
    case 'otherKey':
      return (
        <ErrorBox>
          <span className="flex min-w-0 flex-col gap-0.5">
            <span className="font-medium">{t('rotation.move.otherKey')}</span>
            <span className="text-[12.5px] leading-[18px] text-muted">
              {t('rotation.move.otherKeyHint', { key: newKey.name })}
            </span>
          </span>
        </ErrorBox>
      );
    case 'server':
      return (
        <ErrorBox>
          <span className="flex min-w-0 flex-col gap-1">
            <span className="font-medium">
              {failure.step === 'install'
                ? t('rotation.move.installFailed')
                : t('rotation.cleanup.removeFailed')}
            </span>
            {failure.output ? (
              <pre className="selectable font-mono text-[11.5px] leading-[17px] whitespace-pre-wrap text-fg-2">
                {failure.output}
              </pre>
            ) : null}
          </span>
        </ErrorBox>
      );
    case 'hostGone':
      return <ErrorBox>{t('rotation.move.hostGone', { alias })}</ErrorBox>;
    case 'error':
      return <ErrorBox>{failure.message}</ErrorBox>;
  }
}
