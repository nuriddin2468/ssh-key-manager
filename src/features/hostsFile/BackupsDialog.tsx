import { useQuery } from '@tanstack/react-query';
import { History } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { useHostsApply } from './useHostsApply';

/** Copies saved before each change, any of which can be put back. */
export function BackupsDialog({ onDone }: { onDone: () => void }) {
  const { t, i18n } = useTranslation();
  const backups = useQuery({ queryKey: ['hosts-file', 'backups'], queryFn: api.hostsBackups });
  const { restore } = useHostsApply();
  const format = (iso: string | null) =>
    iso
      ? new Intl.DateTimeFormat(i18n.language, { dateStyle: 'medium', timeStyle: 'short' }).format(
          new Date(iso),
        )
      : t('common.dash');

  return (
    <DialogContent section="hostsFile" className="max-w-[540px]">
      <DialogHeader
        icon={
          <Tile tone="indigo" size={44} glow>
            <History className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('hostsFile.backupsTitle')}
        description={t('hostsFile.backupsDescription')}
      />
      <DialogBody>
        {backups.isPending ? (
          <div className="grid h-24 place-items-center text-subtle">
            <Spinner className="size-5" />
          </div>
        ) : (backups.data ?? []).length === 0 ? (
          <p className="py-4 text-center text-[12.5px] text-muted">{t('hostsFile.backupsEmpty')}</p>
        ) : (
          <ul className="flex max-h-[46vh] flex-col gap-1 overflow-y-auto">
            {(backups.data ?? []).map((backup) => (
              <li
                key={backup.path}
                className="flex items-center gap-3 rounded-xl border border-line bg-fill-subtle px-3 py-2"
              >
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="font-medium">{format(backup.saved)}</span>
                  <span className="text-[12px] text-subtle">
                    {t('hostsFile.entries', { count: backup.entries })}
                  </span>
                </span>
                <Button
                  size="sm"
                  loading={restore.isPending && restore.variables?.path === backup.path}
                  disabled={restore.isPending}
                  onClick={() =>
                    restore.mutate(
                      { path: backup.path, flushDns: true },
                      { onSuccess: (result) => result.outcome === 'applied' && onDone() },
                    )
                  }
                >
                  {t('hostsFile.restore')}
                </Button>
              </li>
            ))}
          </ul>
        )}
      </DialogBody>
      <DialogFooter>
        <Button size="lg" onClick={onDone}>
          {t('common.close')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
