import { Cpu, KeyRound, Lock, LockOpen, RefreshCw } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import {
  invalidateAll,
  useAgent,
  useEnvironment,
  useKeys,
  useVaultEntries,
  useVaultStatus,
} from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import type { AgentIdentityView } from '@/bindings/AgentIdentityView';
import type { KeyView } from '@/bindings/KeyView';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { IconButton } from '@/components/ui/IconButton';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { hasPrivate, isPlain, keyTone } from '@/features/keys/model';
import { findKeyEntry, useVaultKey } from '@/features/keys/vaultKey';
import { formatDuration, shortFingerprint } from '@/lib/format';
import { useSettings } from '@/lib/settings';
import { LifetimeSelect } from './LifetimeSelect';
import { toastAddedFromVault } from './useKeysFromVault';

const STOPPED_COMMANDS = {
  macos: null,
  windows: 'Get-Service ssh-agent | Set-Service -StartupType Automatic\nStart-Service ssh-agent',
  linux: 'eval "$(ssh-agent -s)"',
} as const;

export function AgentPage() {
  const { t, i18n } = useTranslation();
  const agent = useAgent();
  const keys = useKeys();
  const environment = useEnvironment();
  const settings = useSettings();
  const vaultUnlocked = useVaultStatus().data?.state === 'unlocked';
  const entries = useVaultEntries();
  const [confirmLockAll, setConfirmLockAll] = useState(false);

  const lockAll = useAppMutation(api.agentRemoveAll, {
    success: () => t('agent.lockedAll'),
    onSuccess: () => setConfirmLockAll(false),
  });
  const unlockSaved = useAppMutation(() => api.agentAddAllFromVault(settings.defaultLifetime), {
    onSuccess: (report) => toastAddedFromVault(t, i18n.language, report),
  });

  const identities = agent.data?.identities ?? [];
  const running = agent.data?.status.available ?? false;
  const loaded = new Set(identities.map((i) => i.fingerprint));
  const ready = (keys.data?.keys ?? []).filter(
    (key) => hasPrivate(key) && !(key.fingerprint && loaded.has(key.fingerprint)),
  );
  const keysById = new Map((keys.data?.keys ?? []).map((key) => [key.id, key]));
  const platform = environment.data?.platform ?? 'macos';
  const readySaved = vaultUnlocked
    ? ready.filter((key) => !key.hardware && findKeyEntry(entries.data, key.fingerprint))
    : [];

  return (
    <>
      <Toolbar title={t('agent.title')} meta={running ? 'ssh-agent' : t('agent.notRunning')}>
        <IconButton
          label={t('common.refresh')}
          variant="secondary"
          icon={<RefreshCw className="size-[15px]" strokeWidth={1.9} />}
          onClick={() => void invalidateAll()}
        />
      </Toolbar>

      <PageBody className="gap-[18px]">
        {agent.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-6" />
          </div>
        ) : (
          <>
            <section
              aria-labelledby="agent-title"
              className="relative flex flex-wrap items-center gap-[22px] overflow-hidden rounded-[20px] border border-violet-400/20 bg-[linear-gradient(135deg,rgb(124_58_237/0.2),rgb(255_255_255/0.03)_60%)] px-6 py-[22px] shadow-[inset_0_1px_0_rgb(255_255_255/0.06)]"
            >
              <div
                aria-hidden="true"
                className="relative grid size-[92px] shrink-0 place-items-center"
              >
                {running ? (
                  <span className="absolute inset-0 animate-pulse-ring rounded-[28px] bg-violet-400/45" />
                ) : null}
                <span
                  className="relative grid size-20 place-items-center rounded-3xl text-white"
                  style={{
                    background: running
                      ? 'linear-gradient(145deg, #DDD6FE 0%, #8B5CF6 45%, #4C1D95 100%)'
                      : 'linear-gradient(145deg, #CBD5E1, #475569)',
                    boxShadow:
                      '0 24px 44px -16px rgb(124 58 237 / 0.9), inset 0 1px 0 rgb(255 255 255 / 0.5)',
                  }}
                >
                  <Cpu className="size-[38px]" strokeWidth={1.6} />
                </span>
              </div>
              <div className="flex min-w-[280px] flex-1 flex-col gap-1">
                <span className="inline-flex items-center gap-2 text-[12.5px] font-medium text-violet-200">
                  <span
                    aria-hidden="true"
                    className={
                      running
                        ? 'size-2 rounded-full bg-violet-400 shadow-[0_0_10px_#A78BFA]'
                        : 'size-2 rounded-full bg-faint'
                    }
                  />
                  {running ? t('agent.running') : t('agent.notRunning')}
                </span>
                <h2
                  id="agent-title"
                  className="text-[26px] leading-8 font-semibold tracking-[-0.02em]"
                >
                  {running
                    ? t('agent.headline', { count: identities.length })
                    : t('agent.stoppedTitle')}
                </h2>
                {agent.data?.status.socket ? (
                  <span className="selectable font-mono text-[12px] [overflow-wrap:anywhere] text-muted">
                    SSH_AUTH_SOCK={agent.data.status.socket}
                  </span>
                ) : null}
              </div>
              {running && identities.length > 0 ? (
                <Button
                  size="lg"
                  icon={<Lock className="size-4" strokeWidth={1.75} />}
                  onClick={() => setConfirmLockAll(true)}
                >
                  {t('agent.lockAll')}
                </Button>
              ) : null}
            </section>

            {!running ? (
              <section className="glass flex flex-col gap-2 rounded-2xl p-5">
                <p className="text-muted">
                  {platform === 'macos'
                    ? t('agent.stoppedMac')
                    : platform === 'windows'
                      ? t('agent.stoppedWindows')
                      : t('agent.stoppedLinux')}
                </p>
                {STOPPED_COMMANDS[platform] ? (
                  <pre className="selectable rounded-xl border border-white/[0.06] bg-black/40 px-3.5 py-3 font-mono text-[12px] leading-5 text-fg-2">
                    {STOPPED_COMMANDS[platform]}
                  </pre>
                ) : null}
              </section>
            ) : (
              <>
                <section aria-labelledby="loaded-h" className="flex flex-col gap-2.5">
                  <h2 id="loaded-h" className="text-[14px] leading-5 font-semibold">
                    {t('agent.unlockedNow')}
                  </h2>
                  <div className="flex flex-wrap gap-3">
                    {identities.map((identity) => (
                      <LoadedCard
                        key={identity.fingerprint}
                        identity={identity}
                        keyView={identity.keyId ? keysById.get(identity.keyId) : undefined}
                      />
                    ))}
                    {identities.length === 0 ? (
                      <p className="flex-[1_1_100%] rounded-2xl border border-dashed border-white/[0.14] px-4 py-[26px] text-center text-muted">
                        {t('agent.noneUnlocked')}
                      </p>
                    ) : null}
                  </div>
                </section>

                <section aria-labelledby="ready-h" className="flex flex-col gap-2.5">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <h2 id="ready-h" className="text-[14px] leading-5 font-semibold">
                      {t('agent.readyToUnlock')}
                    </h2>
                    <span className="text-[12.5px] text-subtle">{t('agent.readyHint')}</span>
                    {readySaved.length > 0 ? (
                      <Button
                        variant="soft"
                        size="sm"
                        className="ml-auto self-center"
                        loading={unlockSaved.isPending}
                        icon={<LockOpen aria-hidden="true" className="size-3.5" strokeWidth={2} />}
                        onClick={() => unlockSaved.mutate(undefined)}
                      >
                        {t('agent.unlockSaved', { count: readySaved.length })}
                      </Button>
                    ) : null}
                  </div>
                  {ready.length > 0 ? (
                    <div className="glass flex flex-col overflow-hidden rounded-2xl">
                      {ready.map((key) => (
                        <ReadyRow key={key.id} keyView={key} />
                      ))}
                    </div>
                  ) : (
                    <p className="text-[12.5px] text-subtle">{t('agent.allUnlocked')}</p>
                  )}
                </section>
              </>
            )}

            <p className="mt-auto flex gap-2.5 text-[12.5px] leading-[19px] text-subtle">
              {t('agent.note')}
            </p>
          </>
        )}
      </PageBody>

      <ConfirmDialog
        open={confirmLockAll}
        onOpenChange={setConfirmLockAll}
        title={t('agent.lockAllTitle')}
        description={t('agent.lockAllText')}
        confirmLabel={t('agent.lockAll')}
        busy={lockAll.isPending}
        onConfirm={() => lockAll.mutate(undefined)}
      />
    </>
  );
}

function LoadedCard({ identity, keyView }: { identity: AgentIdentityView; keyView?: KeyView }) {
  const { t, i18n } = useTranslation();
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!identity.expiresAt) return;
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, [identity.expiresAt]);

  const lock = useAppMutation(() => api.agentRemove(identity.fingerprint), {
    success: () => t('keys.locked', { name: keyView?.name ?? identity.comment }),
  });

  const expires = identity.expiresAt ? new Date(identity.expiresAt).getTime() : null;
  const remaining = expires ? Math.max(0, (expires - now) / 1000) : null;
  // The ring shows the share left of the longest standard lifetime (8 h).
  const share = remaining === null ? 1 : Math.min(1, remaining / (8 * 3600));
  const name = keyView?.name ?? identity.comment;

  return (
    <div className="glass-raised flex min-w-0 flex-[1_1_280px] items-center gap-3.5 rounded-2xl px-4 py-3.5">
      <span className="relative grid size-12 shrink-0 place-items-center">
        {remaining !== null ? (
          <svg
            aria-hidden="true"
            width="48"
            height="48"
            viewBox="0 0 48 48"
            className="absolute inset-0"
          >
            <circle
              cx="24"
              cy="24"
              r="20"
              fill="none"
              stroke="rgb(255 255 255 / 0.08)"
              strokeWidth="4"
            />
            <circle
              cx="24"
              cy="24"
              r="20"
              fill="none"
              stroke="#A78BFA"
              strokeWidth="4"
              strokeLinecap="round"
              strokeDasharray="125.66"
              strokeDashoffset={(125.66 * (1 - share)).toFixed(2)}
              transform="rotate(-90 24 24)"
            />
          </svg>
        ) : null}
        <Tile tone={keyView ? keyTone(keyView) : 'slate'} size={32}>
          <KeyRound className="size-4" strokeWidth={2} />
        </Tile>
      </span>
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="truncate font-mono font-medium">{name}</span>
        <span
          className={
            remaining !== null ? 'text-[12.5px] text-violet-200' : 'text-[12.5px] text-muted'
          }
        >
          {remaining !== null
            ? t('agent.locksIn', { time: formatDuration(remaining, i18n.language) })
            : keyView
              ? t('agent.untilLogout')
              : t('agent.notFromSsh')}
        </span>
        <span className="truncate font-mono text-[11px] text-subtle">
          {shortFingerprint(identity.fingerprint)}
        </span>
      </span>
      <Button size="sm" loading={lock.isPending} onClick={() => lock.mutate(undefined)}>
        {t('agent.lock')}
      </Button>
    </div>
  );
}

function ReadyRow({ keyView: key }: { keyView: KeyView }) {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const settings = useSettings();
  const [lifetime, setLifetime] = useState(settings.defaultLifetime);
  const vault = useVaultKey(key.fingerprint);
  const inVault =
    (vault.vault === 'unlocked' && vault.entry !== undefined) ||
    (vault.vault === 'locked' && vault.saved);
  const note = key.hardware
    ? t('agent.hardware')
    : isPlain(key)
      ? t('agent.plain')
      : inVault
        ? t('agent.inVault')
        : t('agent.passphraseSaved');
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-3 border-b border-white/[0.05] px-4 py-3 last:border-b-0">
      <Tile tone={keyTone(key)} size={32}>
        <KeyRound className="size-4" strokeWidth={2} />
      </Tile>
      <span className="flex min-w-[200px] flex-[2_1_200px] flex-col">
        <span className="font-mono font-medium">{key.name}</span>
        <span className={isPlain(key) ? 'text-[12px] text-warning' : 'text-[12px] text-subtle'}>
          {note}
        </span>
      </span>
      <span className="flex flex-[1_1_150px] items-center gap-2 text-[12.5px] text-muted">
        {t('agent.for')}
        <LifetimeSelect
          value={lifetime}
          onChange={setLifetime}
          size="sm"
          ariaLabel={`${t('agent.for')} ${key.name}`}
        />
      </span>
      <Button
        size="sm"
        className="bg-[linear-gradient(135deg,#C4B5FD,#8B5CF6)] font-semibold text-[#1E0B47] shadow-[0_8px_20px_-8px_rgb(139_92_246/0.85)]"
        variant="ghost"
        icon={<LockOpen className="size-3.5" strokeWidth={2} />}
        onClick={() => dialogs.unlockKey(key, lifetime)}
      >
        {t('agent.unlock')}
      </Button>
    </div>
  );
}
