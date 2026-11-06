import { RefreshCw } from 'lucide-react';
import { type ReactNode, useCallback, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  useConfig,
  useConnectionHistory,
  useEnvironment,
  useKeys,
  useVaultStatus,
} from '@/api/queries';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { KeyView } from '@/bindings/KeyView';
import { DialogContent, DialogHeader } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { vaultErrorMessage } from '@/features/hosts/vault';
import { cn } from '@/lib/cn';
import { CleanupStep } from './CleanupStep';
import { HostsStep } from './HostsStep';
import { MoveStep } from './MoveStep';
import { NewKeyStep } from './NewKeyStep';
import { findCandidates, moved } from './plan';
import { type Rotation, useRotation } from './store';
import { useRotationRun } from './useRotationRun';

const STEPS = ['hosts', 'key', 'move', 'cleanup'] as const;
export type Step = (typeof STEPS)[number];

/** Where a rotation goes on: with no new key yet, making it; then moving hosts, then cleaning up. */
function resumeAt(rotation: Rotation | null): Step {
  if (!rotation) return 'hosts';
  if (!rotation.newKeyId) return 'key';
  return rotation.hosts.every(moved) ? 'cleanup' : 'move';
}

/**
 * Replaces a key with a new Ed25519 key on every host that uses it: choose
 * the hosts, make the key, add it to each host and sign in with it alone
 * before the host's config names it, then take the old key off the servers
 * where the new one signed in, and off this computer once nothing needs it.
 * Every outcome is saved as it comes, so the rotation can go on later.
 */
export function RotateKeyDialog({ keyView, onDone }: { keyView: KeyView; onDone: () => void }) {
  const { t } = useTranslation();
  const keys = useKeys();
  const config = useConfig();
  const history = useConnectionHistory();
  const environment = useEnvironment();
  const vaultUnlocked = useVaultStatus().data?.state === 'unlocked';
  const { rotation } = useRotation(keyView.id);

  const all = keys.data?.keys ?? [];
  // The key as listed now (its `usedBy` changes as hosts move); gone once trashed.
  const oldKey = all.find((key) => key.id === keyView.id);
  const newKey = rotation?.newKeyId ? all.find((key) => key.id === rotation.newKeyId) : undefined;
  const sshDir = environment.data?.paths.dir ?? '';
  const home = environment.data?.paths.home;
  const historyData = history.data;

  const stillUsing = useCallback(
    (file: ConfigFile) =>
      new Set(
        findCandidates({
          key: { privatePath: keyView.privatePath },
          config: file,
          history: historyData ?? {},
          sshDir,
        }).map((candidate) => candidate.alias),
      ),
    [keyView.privatePath, historyData, sshDir],
  );
  const describe = useCallback((cause: unknown) => vaultErrorMessage(t, cause), [t]);
  const run = useRotationRun({
    oldKeyId: keyView.id,
    newKey,
    home,
    withVault: vaultUnlocked,
    stillUsing,
    describe,
  });
  const working = run.active !== null;

  const [chosen, setChosen] = useState<Step>(() => resumeAt(rotation));
  // A new key deleted since: make another before going on.
  const keyLost = Boolean(rotation?.newKeyId && keys.data && !newKey);
  const step: Step = (chosen === 'move' || chosen === 'cleanup') && keyLost ? 'key' : chosen;
  const index = STEPS.indexOf(step);

  const candidates = useMemo(
    () =>
      config.data
        ? findCandidates({
            key: { privatePath: keyView.privatePath },
            config: config.data,
            history: historyData ?? {},
            sshDir,
          })
        : [],
    [config.data, keyView.privatePath, historyData, sshDir],
  );

  // Focus follows the step (each heading mounts focused), so screen readers
  // hear where they are.
  const focusOnMount = useCallback((element: HTMLElement | null) => element?.focus(), []);
  const progressText = t('rotation.progress', { step: index + 1, total: STEPS.length });
  const progress: ReactNode = (
    <div className="flex flex-col gap-2">
      <div aria-hidden="true" className="grid grid-cols-4 gap-1">
        {STEPS.map((name, i) => (
          <span
            key={name}
            className={cn(
              'h-1 rounded-sm',
              i < index
                ? 'bg-[linear-gradient(90deg,var(--accent-1),var(--accent-2))]'
                : i === index
                  ? 'bg-[rgb(var(--accent-rgb)/0.45)]'
                  : 'bg-white/10',
            )}
          />
        ))}
      </div>
      <p aria-hidden="true" className="text-[12px] text-subtle">
        {progressText}
      </p>
      <h3
        key={step}
        ref={focusOnMount}
        tabIndex={-1}
        className="text-[15px] leading-[22px] font-semibold tracking-[-0.01em] outline-none"
      >
        <span className="sr-only">{progressText}: </span>
        {t(`rotation.steps.${step}`)}
      </h3>
    </div>
  );

  const shared = { progress, oldKey: oldKey ?? keyView, go: setChosen };

  return (
    <DialogContent section="keys" className="max-w-[640px]" dismissible={!working}>
      <DialogHeader
        icon={
          <Tile tone="teal" size={44} glow>
            <RefreshCw className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('rotation.title', { name: keyView.name })}
        description={t('rotation.description')}
        closable={!working}
      />
      {step === 'hosts' ? (
        <HostsStep
          // Mounted again once the config and history are in, to tick the suggested hosts.
          key={config.isPending || history.isPending ? 'loading' : 'ready'}
          {...shared}
          rotation={rotation}
          candidates={candidates}
          hosts={config.data?.view.hosts ?? []}
          loading={config.isPending || history.isPending}
          hasNewKey={Boolean(newKey)}
        />
      ) : null}
      {step === 'key' ? (
        <NewKeyStep {...shared} rotation={rotation} newKey={newKey} keys={all} onClose={onDone} />
      ) : null}
      {step === 'move' && rotation && newKey ? (
        <MoveStep {...shared} rotation={rotation} newKey={newKey} run={run} onClose={onDone} />
      ) : null}
      {step === 'cleanup' && rotation && newKey ? (
        <CleanupStep
          {...shared}
          rotation={rotation}
          newKey={newKey}
          gone={keys.data !== undefined && !oldKey}
          hosts={config.data?.view.hosts ?? []}
          stillUsing={config.data ? stillUsing(config.data) : new Set()}
          run={run}
          onClose={onDone}
        />
      ) : null}
    </DialogContent>
  );
}

/** What every step gets. */
export interface StepProps {
  /** The stepper and the step's heading, for the top of the body. */
  progress: ReactNode;
  /** The key being replaced, as listed now. */
  oldKey: KeyView;
  go: (step: Step) => void;
}
