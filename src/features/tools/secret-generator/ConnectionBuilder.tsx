import { useMutation } from '@tanstack/react-query';
import { Copy, Database } from 'lucide-react';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { toastError } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { TextField } from '@/components/ui/TextField';
import { parsePort } from '../network/model';
import { type Connection, connectionString, DATABASES, type DatabaseKind } from './model';

/** Builds a database URL around the generated password. */
export function ConnectionBuilder({
  password,
  connection,
  onChange,
}: {
  password: string;
  connection: Connection;
  onChange: (connection: Connection) => void;
}) {
  const { t } = useTranslation();
  const titleId = useId();
  const url = password ? connectionString(connection, password) : '';
  const db = DATABASES[connection.kind];
  const portInvalid = connection.port.trim() !== '' && parsePort(connection.port) === null;
  const copy = useMutation({
    mutationFn: api.toolsCopySecret,
    gcTime: 0,
    onSuccess: (result) =>
      toast.success(t('toolGenerator.connection.copied'), {
        id: 'tools-copy',
        description:
          result.clearsInSecs !== null
            ? t('passwords.clearsIn', { seconds: result.clearsInSecs })
            : undefined,
      }),
    onError: (error) => toastError(t, error),
  });
  const set = (patch: Partial<Connection>) => onChange({ ...connection, ...patch });

  return (
    <section
      aria-labelledby={titleId}
      className="glass @container flex flex-col gap-3.5 rounded-2xl p-4"
    >
      <div className="flex items-start gap-3">
        <Database
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-subtle"
          strokeWidth={1.9}
        />
        <div className="flex flex-col gap-0.5">
          <h2 id={titleId} className="text-[14px] font-semibold">
            {t('toolGenerator.connection.title')}
          </h2>
          <p className="text-[12.5px] leading-[18px] text-muted">
            {t('toolGenerator.connection.description')}
          </p>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-2.5 @[700px]:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)_minmax(0,1.6fr)_88px_minmax(0,1fr)]">
        <Select
          label={t('toolGenerator.connection.database')}
          value={connection.kind}
          onValueChange={(kind) => set({ kind: kind as DatabaseKind })}
          options={Object.entries(DATABASES).map(([value, item]) => ({
            value,
            label: item.label,
          }))}
        />
        <TextField
          label={t('toolGenerator.connection.user')}
          mono
          value={connection.user}
          onChange={(event) => set({ user: event.target.value })}
          placeholder={connection.kind === 'redis' ? 'default' : 'app'}
        />
        <TextField
          label={t('toolGenerator.connection.host')}
          mono
          value={connection.host}
          onChange={(event) => set({ host: event.target.value })}
          placeholder="localhost"
        />
        <TextField
          label={t('toolGenerator.connection.port')}
          mono
          inputMode="numeric"
          value={connection.port}
          onChange={(event) => set({ port: event.target.value })}
          placeholder={String(db.port)}
          error={portInvalid ? t('toolGenerator.connection.portInvalid') : undefined}
        />
        <TextField
          label={
            connection.kind === 'redis'
              ? t('toolGenerator.connection.number')
              : t('toolGenerator.connection.name')
          }
          mono
          value={connection.database}
          onChange={(event) => set({ database: event.target.value })}
          placeholder={connection.kind === 'redis' ? '0' : 'app'}
        />
      </div>
      <div className="flex flex-wrap items-center gap-2.5">
        <code className="selectable min-w-0 flex-1 rounded-xl border border-line bg-shade/35 px-3 py-2 font-mono text-[12.5px] leading-[19px] text-fg [overflow-wrap:anywhere]">
          {url || ' '}
        </code>
        <Button
          icon={<Copy aria-hidden="true" className="size-4" strokeWidth={1.9} />}
          disabled={!url || portInvalid}
          loading={copy.isPending}
          onClick={() => copy.mutate(url)}
        >
          {t('toolGenerator.connection.copy')}
        </Button>
      </div>
    </section>
  );
}
