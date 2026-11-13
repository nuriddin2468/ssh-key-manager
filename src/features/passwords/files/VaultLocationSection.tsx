import { isTauri } from '@tauri-apps/api/core';
import { revealItemInDir } from '@tauri-apps/plugin-opener';
import type { TFunction } from 'i18next';
import { Cloud, FolderInput, FolderOpen, RotateCcw, Vault } from 'lucide-react';
import { type ReactNode, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useEnvironment } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { VaultLocation } from '@/bindings/VaultLocation';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { cn } from '@/lib/cn';
import { displayPath } from '@/lib/format';
import { fileManagerName } from '@/lib/platform';
import { showFileError } from './errors';
import { baseName, folderOf, pickFile, pickFolder } from './pickers';
import { useVaultLocation } from './queries';

export interface VaultLocationSectionProps {
  className?: string;
}

type Pending =
  | { kind: 'move'; folder: string }
  | { kind: 'useFile'; path: string }
  | { kind: 'default'; moveFiles: boolean };

const DEV_KDBX = '/Users/dev/Library/CloudStorage/Dropbox/Passwords.kdbx';

/**
 * Where the vault's files are, for the Settings page: move them (e.g. into
 * a synced folder), switch to another KeePass file, or go back to the
 * default place. Styled like the page's other groups.
 */
export function VaultLocationSection({ className }: VaultLocationSectionProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const location = useVaultLocation();
  const home = useEnvironment().data?.paths.home;
  const [pending, setPending] = useState<Pending | null>(null);
  const loc = location.data;
  const close = () => setPending(null);
  const shown = (path: string) => displayPath(path, home);

  const errors = {
    already_exists: t('vaultFiles.location.targetExists'),
    invalid_input: t('vaultFiles.location.alreadyThere'),
    parse: t('vaultFiles.location.notKeepass'),
    unsupported: t('vaultFiles.location.oldKeepass'),
  };
  const move = useAppMutation((folder: string) => api.vaultMove(folder), {
    success: (next) =>
      t('vaultFiles.location.moved', { folder: shown(folderOf(next.paths.database)) }),
    onSuccess: close,
    onError: (error) => showFileError(t, error, errors),
  });
  const switchFile = useAppMutation((path: string) => api.vaultUseFile(path), {
    success: (next) => t('vaultFiles.location.switched', { file: baseName(next.paths.database) }),
    onSuccess: close,
    onError: (error) => showFileError(t, error, errors),
  });
  const backToDefault = useAppMutation((moveFiles: boolean) => api.vaultUseDefault(moveFiles), {
    success: (_, moveFiles) =>
      moveFiles ? t('vaultFiles.location.movedBack') : t('vaultFiles.location.switchedBack'),
    onSuccess: close,
    onError: (error) => showFileError(t, error, errors),
  });
  const busy = move.isPending || switchFile.isPending || backToDefault.isPending;

  const chooseFolder = async () => {
    try {
      const folder = await pickFolder(t('vaultFiles.location.pickFolderTitle'));
      if (folder) setPending({ kind: 'move', folder });
    } catch (error) {
      toastError(t, error);
    }
  };
  const chooseFile = async () => {
    try {
      const path = await pickFile(
        t('vaultFiles.location.pickFileTitle'),
        { name: t('vaultFiles.location.keepassFiles'), extensions: ['kdbx'] },
        DEV_KDBX,
      );
      if (path) setPending({ kind: 'useFile', path });
    } catch (error) {
      toastError(t, error);
    }
  };
  const reveal = async (path: string) => {
    if (!isTauri()) return;
    try {
      await revealItemInDir(path);
    } catch (error) {
      toastError(t, error);
    }
  };

  const confirm = loc && pending ? confirmation(t, pending, loc, shown) : null;

  return (
    <section aria-labelledby={titleId} className={cn('flex flex-col gap-2', className)}>
      <h2 id={titleId} className="px-1 text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {t('vaultFiles.location.title')}
      </h2>
      <div className="glass flex flex-col divide-y divide-line-soft overflow-hidden rounded-2xl">
        <Row label={t('vaultFiles.location.path')}>
          {loc ? (
            <>
              {/* The folder gives way first, so the file name stays visible. */}
              <span
                className="selectable flex min-w-0 flex-1 justify-end font-mono text-[12px] text-muted"
                title={loc.paths.database}
              >
                <span className="truncate">
                  {shown(folderOf(loc.paths.database))}
                  {loc.paths.database.charAt(folderOf(loc.paths.database).length)}
                </span>
                <span className="shrink-0">{baseName(loc.paths.database)}</span>
              </span>
              {loc.isDefault ? <Badge>{t('vaultFiles.location.default')}</Badge> : null}
              {loc.exists ? (
                <Button
                  size="sm"
                  variant="ghost"
                  icon={<FolderOpen className="size-[15px]" strokeWidth={1.75} />}
                  onClick={() => void reveal(loc.paths.database)}
                >
                  {t('keys.showIn', { app: fileManagerName })}
                </Button>
              ) : (
                <Badge tone="info">{t('vaultFiles.location.missing')}</Badge>
              )}
            </>
          ) : null}
        </Row>
        <div className="flex flex-wrap items-center gap-2 px-4 py-3">
          <Button
            size="sm"
            icon={<FolderInput className="size-[15px]" strokeWidth={1.75} />}
            disabled={!loc?.exists || busy}
            onClick={() => void chooseFolder()}
          >
            {t('vaultFiles.location.move')}
          </Button>
          <Button
            size="sm"
            icon={<Vault className="size-[15px]" strokeWidth={1.75} />}
            disabled={!loc || busy}
            onClick={() => void chooseFile()}
          >
            {t('vaultFiles.location.useFile')}
          </Button>
          {loc && !loc.isDefault ? (
            <Button
              size="sm"
              variant="ghost"
              icon={<RotateCcw className="size-[15px]" strokeWidth={1.75} />}
              disabled={busy}
              onClick={() =>
                setPending({ kind: 'default', moveFiles: !loc.defaultExists && loc.exists })
              }
            >
              {t('vaultFiles.location.backToDefault')}
            </Button>
          ) : null}
        </div>
        <p className="flex gap-2.5 px-4 py-3 text-[12.5px] leading-[19px] text-subtle">
          <Cloud aria-hidden="true" className="mt-0.5 size-4 shrink-0" strokeWidth={1.75} />
          <span>{t('vaultFiles.location.sync')}</span>
        </p>
      </div>

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => (open ? undefined : close())}
        title={confirm?.title ?? ''}
        description={confirm?.description ?? ''}
        confirmLabel={confirm?.label ?? ''}
        busy={busy}
        onConfirm={() => {
          if (!pending) return;
          if (pending.kind === 'move') move.mutate(pending.folder);
          else if (pending.kind === 'useFile') switchFile.mutate(pending.path);
          else backToDefault.mutate(pending.moveFiles);
        }}
      />
    </section>
  );
}

function confirmation(
  t: TFunction,
  action: Pending,
  current: VaultLocation,
  show: (path: string) => string,
): { title: string; description: string; label: string } {
  const folder = show(folderOf(current.paths.database));
  switch (action.kind) {
    case 'move':
      return {
        title: t('vaultFiles.location.moveTitle', { folder: show(action.folder) }),
        description: t('vaultFiles.location.moveText'),
        label: t('vaultFiles.location.moveConfirm'),
      };
    case 'useFile':
      return {
        title: t('vaultFiles.location.useFileTitle', { file: baseName(action.path) }),
        description: t('vaultFiles.location.useFileText'),
        label: t('vaultFiles.location.useFileConfirm'),
      };
    default:
      return action.moveFiles
        ? {
            title: t('vaultFiles.location.moveBackTitle'),
            description: t('vaultFiles.location.moveBackText', { folder }),
            label: t('vaultFiles.location.moveBackConfirm'),
          }
        : {
            title: t('vaultFiles.location.switchBackTitle'),
            description: t('vaultFiles.location.switchBackText', {
              file: baseName(current.paths.database),
            }),
            label: t('vaultFiles.location.switchBackConfirm'),
          };
  }
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-h-[52px] items-center gap-3 px-4 py-2">
      <span className="shrink-0 font-medium">{label}</span>
      <span className="ml-auto flex min-w-0 items-center justify-end gap-2">{children}</span>
    </div>
  );
}
