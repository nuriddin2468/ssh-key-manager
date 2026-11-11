import { FilePlus2, MoreHorizontal, Unlink } from 'lucide-react';
import { useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useRouter } from '@/app/router';
import type { EnvFile } from '@/bindings/EnvFile';
import type { EnvFileStatus } from '@/bindings/EnvFileStatus';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/components/ui/Menu';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { cn } from '@/lib/cn';
import { envLabel } from '../model';
import { announceSynced } from './announce';
import { BindFileDialog } from './BindFileDialog';
import { FileCompareDialog } from './FileCompareDialog';
import {
  bindingPath,
  fileName,
  needsAction,
  sameFile,
  stateLabel,
  stateLook,
  stateText,
  TONE_CLASSES,
} from './model';
import { useFileStatuses } from './queries';

type Open = { kind: 'bind' } | { kind: 'compare'; file: EnvFile };

interface FilesSectionProps {
  env: EnvSummary;
  /** The files it is written to, in the order they were added. */
  files: EnvFile[];
}

/**
 * Where an environment is written: its files and where each stands against
 * the vault, with the action a file needs. A remote environment gets none.
 */
export function FilesSection({ env, files }: FilesSectionProps) {
  const { t } = useTranslation();
  const headingId = useId();
  const statuses = useFileStatuses();
  const [open, setOpen] = useState<Open | null>(null);
  const [stopping, setStopping] = useState<EnvFile | null>(null);
  const label = envLabel(env);
  const makeLocal = useVaultMutation(() => api.envsSetKind(env.id, 'local'), {
    success: () => t('envs.kind.nowLocal', { name: label }),
  });
  const statusOf = (file: EnvFile): EnvFileStatus | undefined =>
    statuses.data?.find((status) => status.envId === env.id && sameFile(status.file, file));

  if (env.inTrash) return null;

  return (
    <section aria-labelledby={headingId} className="flex flex-col gap-2.5">
      <div className="flex items-center gap-2">
        <h3 id={headingId} className="text-[13px] font-semibold">
          {t('envs.files.title')}
          {files.length > 0 ? (
            <span className="ml-1.5 font-normal text-subtle tabular-nums">{files.length}</span>
          ) : null}
        </h3>
        {env.kind === 'local' ? (
          <Button
            variant="soft"
            size="sm"
            className="ml-auto"
            icon={<FilePlus2 className="size-3.5" strokeWidth={2.2} />}
            onClick={() => setOpen({ kind: 'bind' })}
          >
            {t('envs.files.add')}
          </Button>
        ) : null}
      </div>

      {env.kind === 'remote' && files.length === 0 ? (
        <div className="flex flex-wrap items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.025] px-3 py-2">
          <p className="min-w-0 flex-1 text-[12.5px] text-muted">{t('envs.files.remoteNote')}</p>
          <Button
            variant="ghost"
            size="sm"
            loading={makeLocal.isPending}
            onClick={() => makeLocal.mutate(undefined)}
          >
            {t('envs.kind.makeLocal')}
          </Button>
        </div>
      ) : files.length === 0 ? (
        <p className="rounded-xl border border-dashed border-white/[0.14] px-3 py-3 text-[12.5px] leading-[19px] text-muted">
          {t('envs.files.emptyText')}
        </p>
      ) : (
        <ul
          aria-label={t('envs.files.listLabel', { env: label })}
          className="flex flex-col gap-1.5"
        >
          {files.map((file) => (
            <FileRow
              key={`${file.folder}\n${file.path}`}
              envId={env.id}
              file={file}
              status={statusOf(file)}
              onCompare={() => setOpen({ kind: 'compare', file })}
              onStop={() => setStopping(file)}
            />
          ))}
        </ul>
      )}

      <Dialog open={open !== null} onOpenChange={(next) => (next ? undefined : setOpen(null))}>
        {open?.kind === 'bind' ? (
          <BindFileDialog
            env={env}
            bound={files}
            onDone={(conflict) => setOpen(conflict ? { kind: 'compare', file: conflict } : null)}
          />
        ) : null}
        {open?.kind === 'compare' ? (
          <FileCompareDialog envId={env.id} file={open.file} onDone={() => setOpen(null)} />
        ) : null}
      </Dialog>
      <StopDialog envId={env.id} file={stopping} onDone={() => setStopping(null)} />
    </section>
  );
}

interface FileRowProps {
  envId: string;
  file: EnvFile;
  status: EnvFileStatus | undefined;
  onCompare: () => void;
  onStop: () => void;
}

/** One file: where it is, where it stands, and the action it needs. */
function FileRow({ envId, file, status, onCompare, onStop }: FileRowProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const state = status?.state;
  const look = state ? stateLook(state) : null;
  const tone = TONE_CLASSES[look?.tone ?? 'neutral'];
  const name = bindingPath(file);
  const writeAgain = useVaultMutation(() => api.envsFilesResolve(envId, file, 'vault', null), {
    onSuccess: (synced) => announceSynced(t, synced, navigate),
  });
  const Icon = look?.icon;
  return (
    <li className="flex items-center gap-2.5 rounded-xl border border-white/[0.07] bg-white/[0.025] px-3 py-2">
      <span
        aria-hidden="true"
        className={cn('grid size-7 shrink-0 place-items-center rounded-lg border', tone.tile)}
      >
        {Icon ? <Icon className="size-[14px]" strokeWidth={2} /> : null}
      </span>
      <span className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span
          className="selectable truncate font-mono text-[12.5px] text-fg"
          title={status?.location ?? `${file.folder}/${file.path}`}
        >
          <span className="text-subtle">{file.folder}/</span>
          {file.path}
        </span>
        <span className={cn('text-[12px]', tone.text)}>
          {state ? stateLabel(t, state) : t('common.loading')}
        </span>
        {state && needsAction(state) ? (
          <span className="text-[12px] leading-[17px] text-muted">{stateText(t, state)}</span>
        ) : null}
      </span>
      {state?.type === 'conflict' ? (
        <Button
          size="sm"
          aria-label={t('envs.files.compareLabel', { file: name })}
          onClick={onCompare}
        >
          {t('envs.files.compare')}
        </Button>
      ) : null}
      {state?.type === 'missing' ? (
        <Button
          size="sm"
          aria-label={t('envs.files.writeAgainLabel', { file: name })}
          loading={writeAgain.isPending}
          onClick={() => writeAgain.mutate(undefined)}
        >
          {t('envs.files.writeAgain')}
        </Button>
      ) : null}
      <Menu>
        <MenuTrigger asChild>
          <IconButton
            label={t('envs.files.fileMenu', { file: name })}
            icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
          />
        </MenuTrigger>
        <MenuContent align="end">
          <MenuItem icon={<Unlink className="size-4" />} onSelect={onStop}>
            {t('envs.files.stop')}
          </MenuItem>
        </MenuContent>
      </Menu>
    </li>
  );
}

interface StopDialogProps {
  envId: string;
  file: EnvFile | null;
  onDone: () => void;
}

/** Stops writing to a file, and deletes it too if asked (only when nothing is lost). */
function StopDialog({ envId, file, onDone }: StopDialogProps) {
  const { t } = useTranslation();
  const [deleteFile, setDeleteFile] = useState(false);
  const name = file ? fileName(file) : '';
  const close = () => {
    setDeleteFile(false);
    onDone();
  };
  const stop = useVaultMutation(
    (target: EnvFile) => api.envsFilesUnbind(envId, target, deleteFile),
    {
      success: () =>
        deleteFile
          ? t('envs.files.unbind.deleted', { file: name })
          : t('envs.files.unbind.done', { file: name }),
      onSuccess: close,
    },
  );
  return (
    <Dialog open={file !== null} onOpenChange={(next) => (next ? undefined : close())}>
      <DialogContent section="envs" className="max-w-[460px]">
        <DialogHeader
          icon={
            <Tile tone="slate" size={44}>
              <Unlink className="size-[20px]" strokeWidth={2} />
            </Tile>
          }
          title={t('envs.files.unbind.title', { file: name })}
          description={t('envs.files.unbind.text')}
        />
        <DialogBody>
          <div className="flex flex-col gap-1">
            <Checkbox
              checked={deleteFile}
              onCheckedChange={setDeleteFile}
              label={t('envs.files.unbind.delete')}
            />
            <p className="pl-[28px] text-[12px] text-subtle">{t('envs.files.unbind.deleteHint')}</p>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={close}>
            {t('common.cancel')}
          </Button>
          <Button
            size="lg"
            variant={deleteFile ? 'danger' : 'primary'}
            loading={stop.isPending}
            onClick={() => file && stop.mutate(file)}
          >
            {t('envs.files.unbind.confirm')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
