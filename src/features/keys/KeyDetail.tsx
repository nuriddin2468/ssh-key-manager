import { isTauri } from '@tauri-apps/api/core';
import { revealItemInDir } from '@tauri-apps/plugin-opener';
import {
  AlertOctagon,
  AlertTriangle,
  Copy,
  Cpu,
  FileKey,
  FolderOpen,
  Info,
  KeyRound,
  Lock,
  MoreHorizontal,
  Send,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import { type CSSProperties, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useEnvironment, useKeys } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { Finding } from '@/bindings/Finding';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/components/ui/Menu';
import { Tile, TONES } from '@/components/ui/Tile';
import { findingText, findingTitle } from '@/features/audit/model';
import { fixLabelKey, useFix } from '@/features/audit/useFix';
import { SendDialog } from '@/features/nearby/SendDialog';
import { SavedSecret } from '@/features/passwords/SavedSecret';
import { copyText } from '@/lib/clipboard';
import { cn } from '@/lib/cn';
import { displayPath } from '@/lib/format';
import { fileManagerName } from '@/lib/platform';
import { algorithmDescription, hasPrivate, isPlain, keyTone } from './model';
import { VaultIcon } from './VaultControls';
import { useVaultKey } from './vaultKey';

const SEVERITY_STYLE = {
  critical: {
    box: 'border-critical-solid/30 bg-critical-solid/10',
    icon: 'text-critical',
    Icon: AlertOctagon,
  },
  warning: {
    box: 'border-warning-solid/30 bg-warning-solid/[0.09]',
    icon: 'text-warning',
    Icon: AlertTriangle,
  },
  info: { box: 'border-info-solid/30 bg-info-solid/[0.09]', icon: 'text-info', Icon: Info },
} as const;

export function KeyDetail({ keyView: key, findings }: { keyView: KeyView; findings: Finding[] }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const environment = useEnvironment();
  const keys = useKeys();
  const [confirmTrash, setConfirmTrash] = useState(false);
  const [sending, setSending] = useState(false);
  const home = environment.data?.paths.home;
  const tone = keyTone(key);
  const keysById = new Map((keys.data?.keys ?? []).map((k) => [k.id, k]));
  const { fix } = useFix(keysById);
  const vault = useVaultKey(key.fingerprint);
  // While the vault is locked the entry is unknown; showing the passphrase
  // opens the vault first.
  const savedIn =
    vault.vault === 'unlocked' && vault.entry
      ? { entry: vault.entry }
      : vault.vault === 'locked' && vault.saved
        ? { entry: undefined }
        : undefined;

  const lock = useAppMutation((fingerprint: string) => api.agentRemove(fingerprint), {
    success: () => t('keys.locked', { name: key.name }),
  });
  const regenerate = useAppMutation(() => api.regeneratePublic(key.id), {
    success: () => t('keys.publicRegenerated', { name: key.name }),
  });
  const trash = useAppMutation(() => api.trashKey(key.id), {
    success: () => t('keys.trashed', { name: key.name }),
    onSuccess: () => {
      setConfirmTrash(false);
      navigate({ page: 'keys' });
    },
  });

  const copy = async (text: string, message: string) => {
    try {
      await copyText(text);
      toast.success(message);
    } catch (error) {
      toastError(t, error);
    }
  };
  const reveal = async () => {
    const path = key.privatePath ?? key.publicPath;
    if (!path || !isTauri()) return;
    try {
      await revealItemInDir(path);
    } catch (error) {
      toastError(t, error);
    }
  };

  const path = key.privatePath ?? key.publicPath ?? '';
  const passLabel = !hasPrivate(key)
    ? '—'
    : key.hardware
      ? t('keys.passHardware')
      : key.encrypted
        ? t('keys.passProtected')
        : t('keys.passNone');
  const perms = key.permissions;
  const permsLabel = perms.ok
    ? t('keys.permsOk')
    : perms.problem === 'checkFailed' || perms.problem === 'notFound'
      ? t('keys.permsUnknown')
      : t('keys.permsBad');

  return (
    <aside
      aria-label={t('keys.detailLabel')}
      className="glass-raised relative flex w-[340px] shrink-0 flex-col overflow-hidden rounded-2xl xl:w-[380px]"
    >
      <div
        aria-hidden="true"
        className="soft-glow absolute -top-[178px] -left-[128px] h-[396px] w-[476px]"
        style={
          {
            '--glow-color': `color-mix(in srgb, ${TONES[tone][1]} 53%, transparent)`,
          } as CSSProperties
        }
      />
      <div className="relative flex flex-col gap-3.5 border-b border-white/[0.07] px-5 pt-5 pb-4">
        <div className="flex items-start gap-3">
          <Tile tone={tone} size={48}>
            <KeyRound className="size-6" strokeWidth={1.9} />
          </Tile>
          <div className="min-w-0 flex-1">
            <h2 className="selectable truncate font-mono text-[16px] leading-6 font-semibold">
              {key.name}
            </h2>
            <p className="truncate text-[12.5px] text-muted">{key.comment || '—'}</p>
          </div>
          <Menu>
            <MenuTrigger asChild>
              <IconButton
                label={t('keys.more')}
                variant="secondary"
                size="md"
                icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
              />
            </MenuTrigger>
            <MenuContent>
              {hasPrivate(key) && key.format === 'openssh' && !key.hardware ? (
                <MenuItem
                  icon={<Lock className="size-4" />}
                  onSelect={() => dialogs.editPassphrase(key)}
                >
                  {key.encrypted ? t('keys.changePassphrase') : t('keys.addPassphrase')}
                </MenuItem>
              ) : null}
              {hasPrivate(key) && (!key.publicPath || key.pairMismatch) ? (
                <MenuItem
                  icon={<FileKey className="size-4" />}
                  onSelect={() => regenerate.mutate(undefined)}
                >
                  {t('keys.regeneratePublic')}
                </MenuItem>
              ) : null}
              {key.fingerprint ? (
                <MenuItem
                  icon={<Copy className="size-4" />}
                  onSelect={() => void copy(key.fingerprint ?? '', t('keys.copiedFingerprint'))}
                >
                  {t('keys.copyFingerprint')}
                </MenuItem>
              ) : null}
              <MenuItem
                icon={<Copy className="size-4" />}
                onSelect={() => void copy(path, t('common.copied'))}
              >
                {t('keys.copyPath')}
              </MenuItem>
              <MenuSeparator />
              <MenuItem
                destructive
                icon={<Trash2 className="size-4" />}
                onSelect={() => setConfirmTrash(true)}
              >
                {t('keys.trash')}
              </MenuItem>
            </MenuContent>
          </Menu>
        </div>
        <div className="flex flex-wrap gap-2">
          {key.publicKey ? (
            <Button
              variant="primary"
              icon={<Copy className="size-[15px]" strokeWidth={2} />}
              onClick={() => void copy(key.publicKey ?? '', t('keys.copiedPublic'))}
            >
              {t('keys.copyPublic')}
            </Button>
          ) : null}
          {key.publicKey ? (
            <Button
              icon={<Send className="size-[15px]" strokeWidth={1.9} />}
              onClick={() => setSending(true)}
            >
              {t('keys.sendPublic')}
            </Button>
          ) : null}
          {hasPrivate(key) && !key.inAgent ? (
            <Button
              className="border border-violet-400/35 bg-violet-400/12 text-violet-200 hover:bg-violet-400/20"
              variant="ghost"
              icon={<Cpu className="size-[15px]" strokeWidth={1.75} />}
              onClick={() => dialogs.unlockKey(key)}
            >
              {t('keys.unlock')}
            </Button>
          ) : null}
          {key.inAgent && key.fingerprint ? (
            <Button
              icon={<Lock className="size-[15px]" strokeWidth={1.75} />}
              loading={lock.isPending}
              onClick={() => lock.mutate(key.fingerprint ?? '')}
            >
              {t('keys.lock')}
            </Button>
          ) : null}
        </div>
      </div>

      <div className="relative flex min-h-0 flex-1 flex-col gap-[18px] overflow-y-auto px-5 pt-4 pb-[18px]">
        <Section title={t('keys.fingerprint')}>
          <div className="flex items-center gap-2">
            <span className="selectable min-w-0 flex-1 font-mono text-[12px] [overflow-wrap:anywhere]">
              {key.fingerprint ?? '—'}
            </span>
            {key.fingerprint ? (
              <IconButton
                label={t('keys.copyFingerprint')}
                icon={<Copy className="size-[15px]" strokeWidth={1.75} />}
                onClick={() => void copy(key.fingerprint ?? '', t('keys.copiedFingerprint'))}
              />
            ) : null}
          </div>
        </Section>

        {key.publicKey ? (
          <Section title={t('keys.publicKey')}>
            <p className="selectable max-h-[70px] overflow-hidden rounded-[10px] border border-white/[0.06] bg-black/35 px-3 py-2.5 font-mono text-[11.5px] leading-[17px] break-all text-fg-2">
              {key.publicKey}
            </p>
          </Section>
        ) : null}

        <dl className="grid grid-cols-[100px_minmax(0,1fr)] gap-x-3 gap-y-2 text-[12.5px]">
          <dt className="text-subtle">{t('keys.algorithm')}</dt>
          <dd>{algorithmDescription(key, (bits) => t('keys.bits', { bits }))}</dd>
          <dt className="text-subtle">{t('keys.passphrase')}</dt>
          <dd className="flex flex-col gap-1">
            <span className={cn(isPlain(key) && 'text-warning')}>{passLabel}</span>
            {savedIn ? (
              <span className="flex min-w-0 flex-col gap-1.5">
                <span className="inline-flex items-center gap-1.5 text-fg-2">
                  <VaultIcon className="size-3.5 text-[var(--accent-text)]" />
                  {t('keys.savedInVault')}
                </span>
                <SavedSecret
                  id={`key:${key.fingerprint ?? key.id}`}
                  entryId={savedIn.entry?.id}
                  locked={vault.vault === 'locked'}
                  unlockReason={t('keys.unlockToShow', { name: key.name })}
                  labels={{
                    show: t('keys.showPassphrase'),
                    hide: t('keys.hidePassphrase'),
                    copy: t('keys.copyPassphrase'),
                    copied: t('keys.passphraseCopied'),
                  }}
                />
              </span>
            ) : null}
          </dd>
          <dt className="text-subtle">{t('keys.location')}</dt>
          <dd className="selectable font-mono text-[12px] [overflow-wrap:anywhere]">
            {displayPath(path, home)}
          </dd>
          <dt className="text-subtle">{t('keys.permissions')}</dt>
          <dd className={cn(!perms.ok && 'text-critical')}>
            {perms.mode ? `${perms.mode} · ${permsLabel}` : permsLabel}
          </dd>
          <dt className="text-subtle">{t('keys.usedBy')}</dt>
          <dd className="flex flex-wrap gap-1.5">
            {key.usedBy.length === 0 ? (
              <span className="text-subtle">{t('keys.noHosts')}</span>
            ) : (
              key.usedBy.map((usage) => (
                <button
                  key={`${usage.hostId}-${usage.patterns.join(' ')}`}
                  type="button"
                  onClick={() => navigate({ page: 'hosts', hostId: usage.hostId ?? undefined })}
                  className="inline-flex h-[22px] items-center rounded-md border border-blue-400/30 bg-blue-400/12 px-2 font-mono text-[11.5px] text-blue-200 hover:bg-blue-400/20"
                >
                  {usage.patterns.join(' ') || '*'}
                </button>
              ))
            )}
          </dd>
        </dl>

        <Section title={t('keys.health')}>
          {findings.length === 0 ? (
            <p className="flex items-center gap-2 rounded-xl border border-ok/25 bg-ok/[0.08] px-3 py-2.5 text-[12.5px] text-teal-200">
              <ShieldCheck aria-hidden="true" className="size-4" strokeWidth={2} />
              {t('keys.healthy')}
            </p>
          ) : (
            findings.map((finding) => {
              const style = SEVERITY_STYLE[finding.severity];
              return (
                <div
                  key={finding.id}
                  className={cn('flex gap-2.5 rounded-xl border px-3 py-2.5', style.box)}
                >
                  <style.Icon
                    aria-hidden="true"
                    className={cn('mt-0.5 size-4 shrink-0', style.icon)}
                    strokeWidth={2}
                  />
                  <div className="flex min-w-0 flex-1 flex-col gap-0.5">
                    <span className="font-medium">{findingTitle(t, finding)}</span>
                    <span className="text-[12.5px] text-muted">{findingText(t, finding)}</span>
                    {finding.fix ? (
                      <Button size="sm" className="mt-1.5 self-start" onClick={() => fix(finding)}>
                        {t(fixLabelKey(finding))}
                      </Button>
                    ) : null}
                  </div>
                </div>
              );
            })
          )}
        </Section>
      </div>

      <div className="relative flex flex-wrap items-center gap-2 border-t border-white/[0.07] px-3.5 py-2.5">
        <Button
          variant="ghost"
          size="sm"
          icon={<FolderOpen className="size-[15px]" strokeWidth={1.75} />}
          onClick={reveal}
        >
          {t('keys.showIn', { app: fileManagerName })}
        </Button>
        <Button
          variant="danger"
          size="sm"
          className="ml-auto"
          icon={<Trash2 className="size-[15px]" strokeWidth={1.75} />}
          onClick={() => setConfirmTrash(true)}
        >
          {t('keys.trash')}
        </Button>
      </div>

      <Dialog open={sending} onOpenChange={setSending}>
        {sending ? (
          <SendDialog
            what={{ type: 'publicKey', keyId: key.id }}
            name={key.name}
            onStarted={() => setSending(false)}
          />
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={confirmTrash}
        onOpenChange={setConfirmTrash}
        title={t('keys.trashTitle', { name: key.name })}
        description={t('keys.trashText')}
        confirmLabel={t('keys.trash')}
        destructive
        busy={trash.isPending}
        onConfirm={() => trash.mutate(undefined)}
      />
    </aside>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="flex flex-col gap-1.5">
      <h3 className="text-[11.5px] leading-4 font-semibold tracking-[0.02em] text-subtle">
        {title}
      </h3>
      {children}
    </section>
  );
}
