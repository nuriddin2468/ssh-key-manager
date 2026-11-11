import { useQuery } from '@tanstack/react-query';
import { ArrowLeftRight, Check, Equal, GitCompareArrows, Minus, Plus } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { errorMessage } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { EnvFile } from '@/bindings/EnvFile';
import type { KeepSide } from '@/bindings/KeepSide';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { useVaultMutation } from '@/features/passwords/vault';
import { Group } from '../CompareDialog';
import { announceSynced } from './announce';
import { isFileConflict } from './errors';
import { bindingPath, fileName, sameFile } from './model';

interface FileCompareDialogProps {
  envId: string;
  file: EnvFile;
  onDone: () => void;
}

/**
 * A file and the vault that both changed: which names differ, by name only
 * (values are compared in the backend), and which side to keep. Keeping is
 * tied to the comparison shown: a file that changed meanwhile is compared
 * again instead of being settled.
 */
export function FileCompareDialog({ envId, file, onDone }: FileCompareDialogProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const [changedSince, setChangedSince] = useState(false);
  const alert = useRef<HTMLParagraphElement>(null);
  // The buttons were busy while the file was checked: the news gets focus.
  useEffect(() => {
    if (changedSince) alert.current?.focus();
  }, [changedSince]);
  const comparison = useQuery({
    queryKey: ['vault', 'envs', 'files', 'compare', envId, file.folder, file.path],
    queryFn: () => api.envsFilesCompare(envId, file),
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const result = comparison.data;
  // A refetch (another round, the window coming back) that finds the file
  // changed must not move what Keep settles without the user seeing it.
  const [shown, setShown] = useState<string | null | undefined>(undefined);
  useEffect(() => {
    if (!result) return;
    if (shown !== undefined && result.revision !== shown) setChangedSince(true);
    setShown(result.revision);
  }, [result, shown]);
  const keep = useVaultMutation(
    (side: KeepSide) => api.envsFilesResolve(envId, file, side, result?.revision ?? null),
    {
      onSuccess: (synced, side) => {
        announceSynced(t, synced, navigate);
        const written = synced.written.some(
          (status) => status.envId === envId && sameFile(status.file, file),
        );
        if (side === 'vault' && written) {
          toast.success(t('envs.files.conflict.keptVault', { file: fileName(file) }));
        }
        onDone();
      },
      onError: (error) => {
        // The vault's own conflicts (another computer saved it) are the
        // vault's to explain.
        if (!isFileConflict(error)) return false;
        setChangedSince(true);
        void comparison.refetch();
        return true;
      },
    },
  );
  const differences = result
    ? result.onlyLeft.length + result.onlyRight.length + result.changed.length
    : 0;

  return (
    <DialogContent section="envs" className="max-w-[600px]">
      <DialogHeader
        icon={
          <Tile tone="amber" size={44} glow>
            <GitCompareArrows className="size-[22px]" strokeWidth={2} />
          </Tile>
        }
        title={t('envs.files.conflict.title', { file: fileName(file) })}
        description={t('envs.files.conflict.description')}
      />
      <DialogBody>
        <p
          className="selectable truncate font-mono text-[12px] text-subtle"
          title={bindingPath(file)}
        >
          {bindingPath(file)}
        </p>
        {changedSince ? (
          <p
            ref={alert}
            role="alert"
            tabIndex={-1}
            className="rounded-xl border border-warning-solid/30 outline-none bg-warning-solid/[0.08] px-3 py-2 text-[12.5px] text-fg-2"
          >
            {t('envs.files.conflict.changedSince')}
          </p>
        ) : null}
        {comparison.isPending ? (
          <div className="grid place-items-center py-8 text-subtle">
            <Spinner className="size-5" />
          </div>
        ) : comparison.isError ? (
          <p role="alert" className="text-[12.5px] text-critical">
            {errorMessage(t, comparison.error)}
          </p>
        ) : result ? (
          <div aria-live="polite" className="flex flex-col gap-3">
            {differences === 0 ? (
              <p className="flex items-center gap-2 rounded-xl border border-white/[0.08] bg-white/[0.03] px-3.5 py-3 text-fg-2">
                <Check aria-hidden="true" className="size-4 text-ok" strokeWidth={2.2} />
                {t('envs.compareDialog.identical', { count: result.same.length })}
              </p>
            ) : null}
            <Group
              icon={<Minus className="size-3.5" strokeWidth={2.4} />}
              tone="critical"
              title={t('envs.files.conflict.onlyVault')}
              names={result.onlyLeft}
            />
            <Group
              icon={<Plus className="size-3.5" strokeWidth={2.4} />}
              tone="info"
              title={t('envs.files.conflict.onlyFile')}
              names={result.onlyRight}
            />
            <Group
              icon={<ArrowLeftRight className="size-3.5" strokeWidth={2.2} />}
              tone="warning"
              title={t('envs.files.conflict.different')}
              names={result.changed}
            />
            <Group
              icon={<Equal className="size-3.5" strokeWidth={2.2} />}
              tone="neutral"
              title={t('envs.files.conflict.same')}
              names={result.same}
              folded
            />
          </div>
        ) : null}
      </DialogBody>
      <DialogFooter>
        <Button size="lg" variant="ghost" onClick={onDone}>
          {t('common.cancel')}
        </Button>
        <Button
          size="lg"
          disabled={
            !result || comparison.isFetching || (keep.isPending && keep.variables !== 'file')
          }
          loading={keep.isPending && keep.variables === 'file'}
          onClick={() => keep.mutate('file')}
        >
          {t('envs.files.conflict.keepFile')}
        </Button>
        <Button
          size="lg"
          disabled={
            !result || comparison.isFetching || (keep.isPending && keep.variables !== 'vault')
          }
          loading={keep.isPending && keep.variables === 'vault'}
          onClick={() => keep.mutate('vault')}
        >
          {t('envs.files.conflict.keepVault')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
