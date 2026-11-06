import type { TFunction } from 'i18next';
import { AlertTriangle, Trash2 } from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { CheckboxControl } from '@/components/ui/Checkbox';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogFooter } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { OkBox, Text } from '@/features/hosts/Feedback';
import { useUnlockFix } from '@/features/hosts/useUnlockFix';
import { cn } from '@/lib/cn';
import { FailureView } from './MoveStep';
import { moved, type OldKeyNeed, oldKeyNeeds, type RemovalBlock, removalBlock } from './plan';
import type { StepProps } from './RotateKeyDialog';
import { forgetRotation, type Rotation } from './store';
import type { useRotationRun } from './useRotationRun';

interface CleanupStepProps extends StepProps {
  rotation: Rotation;
  newKey: KeyView;
  /** The old key is no longer in `~/.ssh`. */
  gone: boolean;
  hosts: HostEntry[];
  stillUsing: ReadonlySet<string>;
  run: ReturnType<typeof useRotationRun>;
  onClose: () => void;
}

/**
 * Step 4: takes the old key off the servers where the new one signed in,
 * then, once nothing needs it, off this computer.
 */
export function CleanupStep({
  progress,
  oldKey,
  go,
  rotation,
  newKey,
  gone,
  hosts,
  stillUsing,
  run,
  onClose,
}: CleanupStepProps) {
  const { t } = useTranslation();
  const listId = useId();
  const working = run.active !== null;
  const movedHosts = rotation.hosts.filter(moved);
  const blocks = new Map(
    movedHosts.map((host) => [
      host.alias,
      removalBlock(host.alias, { progress: rotation.hosts, hosts, stillUsing }),
    ]),
  );
  const removable = movedHosts.filter(
    (host) => blocks.get(host.alias) === null && host.removeOld !== 'done',
  );
  const [unticked, setUnticked] = useState<Set<string>>(new Set());
  const chosen = removable.filter((host) => !unticked.has(host.alias));
  const needs = gone ? [] : oldKeyNeeds({ progress: rotation.hosts, oldKey });
  const [trash, setTrash] = useState(false);
  const allMoved = rotation.hosts.every(moved);

  const finish = useAppMutation(
    async (toTrash: boolean) => {
      if (toTrash) {
        if (oldKey.inAgent && oldKey.fingerprint) await api.agentRemove(oldKey.fingerprint);
        await api.trashKey(oldKey.id);
      }
      return toTrash;
    },
    {
      success: (toTrash) =>
        toTrash
          ? t('rotation.cleanup.finishedTrashed', { old: oldKey.name, key: newKey.name })
          : allMoved
            ? t('rotation.cleanup.finished', { old: oldKey.name, key: newKey.name })
            : t('rotation.saved', { name: oldKey.name }),
      onSuccess: (toTrash) => {
        if (toTrash || allMoved || gone) forgetRotation(rotation.oldKeyId);
        void invalidateAll();
        onClose();
      },
    },
  );

  return (
    <>
      <DialogBody>
        {progress}
        <section aria-labelledby={`${listId}-servers`} className="flex flex-col gap-2.5">
          <h4
            id={`${listId}-servers`}
            className="text-[12px] font-semibold tracking-[0.02em] text-subtle"
          >
            {t('rotation.cleanup.serversTitle')}
          </h4>
          {movedHosts.length ? (
            <>
              <Text>{t('rotation.cleanup.serversText', { name: oldKey.name })}</Text>
              <ul className="glass flex flex-col gap-0.5 rounded-[14px] p-1.5">
                {movedHosts.map((host) => (
                  <ServerRow
                    key={host.alias}
                    alias={host.alias}
                    removed={host.removeOld === 'done'}
                    block={blocks.get(host.alias) ?? null}
                    checked={!unticked.has(host.alias)}
                    onCheckedChange={(on) =>
                      setUnticked((current) => {
                        const next = new Set(current);
                        if (on) next.delete(host.alias);
                        else next.add(host.alias);
                        return next;
                      })
                    }
                    running={run.active?.alias === host.alias}
                    disabled={working}
                    failure={run.failures[host.alias]}
                    newKey={newKey}
                  />
                ))}
              </ul>
              {removable.length ? (
                <Button
                  className="self-start"
                  disabled={working || chosen.length === 0}
                  icon={
                    working ? (
                      <Spinner className="size-4" />
                    ) : (
                      <Trash2 aria-hidden="true" className="size-[15px]" strokeWidth={1.9} />
                    )
                  }
                  aria-busy={working || undefined}
                  onClick={() => void run.removeOld(chosen.map((host) => host.alias))}
                >
                  {t('rotation.cleanup.remove', { count: chosen.length })}
                </Button>
              ) : null}
            </>
          ) : (
            <Text>
              {rotation.hosts.length
                ? t('rotation.cleanup.noServers')
                : t('rotation.cleanup.noHosts')}
            </Text>
          )}
        </section>

        <section aria-labelledby={`${listId}-file`} className="flex flex-col gap-2.5">
          <h4
            id={`${listId}-file`}
            className="text-[12px] font-semibold tracking-[0.02em] text-subtle"
          >
            {t('rotation.cleanup.fileTitle')}
          </h4>
          {gone ? (
            <OkBox>{t('rotation.cleanup.gone', { name: oldKey.name })}</OkBox>
          ) : needs.length ? (
            <NeedsBox name={oldKey.name} needs={needs} hosts={hosts} />
          ) : (
            <ChoiceCards
              legend={t('rotation.cleanup.fileTitle')}
              legendHidden
              value={trash ? 'trash' : 'keep'}
              onValueChange={(value) => setTrash(value === 'trash')}
              columns={1}
              options={[
                {
                  value: 'keep',
                  title: t('rotation.cleanup.keep', { name: oldKey.name }),
                  hint: t('rotation.cleanup.keepHint'),
                },
                {
                  value: 'trash',
                  title: t('rotation.cleanup.trash', { name: oldKey.name }),
                  hint: t('rotation.cleanup.trashHint'),
                },
              ]}
            />
          )}
        </section>
      </DialogBody>
      <DialogFooter>
        <Button
          size="lg"
          variant="ghost"
          className="mr-auto"
          disabled={working || finish.isPending}
          onClick={() => go('move')}
        >
          {t('rotation.back')}
        </Button>
        <Button
          variant="primary"
          size="lg"
          loading={finish.isPending}
          disabled={working}
          onClick={() => finish.mutate(trash && needs.length === 0 && !gone)}
        >
          {t('rotation.cleanup.done')}
        </Button>
      </DialogFooter>
    </>
  );
}

interface ServerRowProps {
  alias: string;
  removed: boolean;
  block: RemovalBlock | null;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  running: boolean;
  disabled: boolean;
  failure: ReturnType<typeof useRotationRun>['failures'][string] | undefined;
  newKey: KeyView;
}

function ServerRow({
  alias,
  removed,
  block,
  checked,
  onCheckedChange,
  running,
  disabled,
  failure,
  newKey,
}: ServerRowProps) {
  const { t } = useTranslation();
  const unlockFix = useUnlockFix();
  const id = `rotate-remove-${alias}`;
  const reason = block && !removed ? blockText(t, block) : null;
  const canRemove = !removed && block === null;
  return (
    <li className="flex flex-col gap-2 rounded-[10px] px-2.5 py-2">
      <div className="flex items-start gap-[11px]">
        {canRemove ? (
          <CheckboxControl
            id={id}
            checked={checked}
            disabled={disabled}
            onCheckedChange={(next) => onCheckedChange(next === true)}
            aria-labelledby={`${id}-name`}
            className="mt-[3px]"
          />
        ) : (
          <span aria-hidden="true" className="size-[18px] shrink-0" />
        )}
        <label
          htmlFor={canRemove ? id : undefined}
          className={cn('flex min-w-0 flex-1 flex-col gap-0.5', canRemove && 'cursor-pointer')}
        >
          <span className="flex flex-wrap items-center gap-1.5">
            <span id={`${id}-name`} className="truncate font-mono text-[13px] font-medium">
              {alias}
            </span>
            {removed ? <Badge tone="accent">{t('rotation.cleanup.removed')}</Badge> : null}
            {running ? <Spinner className="size-3.5" /> : null}
          </span>
          {reason ? <span className="text-[12px] leading-[17px] text-subtle">{reason}</span> : null}
        </label>
      </div>
      {failure && !running ? (
        <div className="pl-[29px]">
          <FailureView failure={failure} newKey={newKey} alias={alias} unlockFix={unlockFix} />
        </div>
      ) : null}
    </li>
  );
}

function blockText(t: TFunction, block: RemovalBlock): string {
  switch (block.kind) {
    case 'notMoved':
      return t('rotation.cleanup.blockNotMoved');
    case 'manual':
      return t('rotation.cleanup.blockManual');
    case 'notOnServer':
      return t('rotation.cleanup.blockNotOnServer');
    case 'sharedAccount':
      return t('rotation.cleanup.blockShared', { alias: block.alias });
  }
}

/** What still signs in with the old key, so it stays. */
function NeedsBox({
  name,
  needs,
  hosts,
}: {
  name: string;
  needs: OldKeyNeed[];
  hosts: HostEntry[];
}) {
  const { t } = useTranslation();
  const label = (need: OldKeyNeed) => {
    if (need.kind === 'notMoved') return t('rotation.cleanup.needNotMoved', { alias: need.alias });
    if (need.hostId === null) return t('rotation.cleanup.needGlobal');
    const block = hosts.find((host) => host.id === need.hostId);
    return t('rotation.cleanup.needConfig', {
      patterns: (block?.patterns ?? need.patterns).join(' '),
    });
  };
  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5">
      <AlertTriangle
        aria-hidden="true"
        className="mt-0.5 size-4 shrink-0 text-warning"
        strokeWidth={2}
      />
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <p className="text-[12.5px] leading-[18px] font-medium text-fg">
          {t('rotation.cleanup.stillNeeded', { name })}
        </p>
        <ul className="flex list-disc flex-col gap-0.5 pl-4 text-[12.5px] leading-[18px] text-fg-2">
          {needs.map((need) => (
            <li key={need.kind === 'notMoved' ? `host:${need.alias}` : `block:${need.hostId}`}>
              {label(need)}
            </li>
          ))}
        </ul>
        <p className="text-[12px] leading-[17px] text-subtle">
          {t('rotation.cleanup.stillNeededHint')}
        </p>
      </div>
    </div>
  );
}
