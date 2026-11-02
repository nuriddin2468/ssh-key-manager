import { CheckCircle2, ShieldCheck, Terminal, Trash2, X, XCircle } from 'lucide-react';
import { type FormEvent, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { HostEntry } from '@/bindings/HostEntry';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { IconButton } from '@/components/ui/IconButton';
import { Tile } from '@/components/ui/Tile';
import { HostResolution } from '@/features/hostsFile/HostResolution';
import { cn } from '@/lib/cn';
import { ConfigPreview, HostFields, useHostErrors } from './HostFields';
import {
  editFromForm,
  formFromHost,
  type HostForm,
  hostLabel,
  hostMonogram,
  optionProblem,
  previewLines,
} from './model';
import { OtherOptions } from './OtherOptions';

interface HostEditorProps {
  host: HostEntry;
  hosts: HostEntry[];
}

export function HostEditor({ host, hosts }: HostEditorProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const initial = useMemo(() => formFromHost(host), [host]);
  const [form, setForm] = useState<HostForm>(initial);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [test, setTest] = useState<ConnectionTest | null>(null);
  const set = <K extends keyof HostForm>(key: K, value: HostForm[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const readOnly = host.kind === 'match';
  const edit = editFromForm(form, host.id);
  const dirty = JSON.stringify(edit) !== JSON.stringify(editFromForm(initial, host.id));
  const errors = useHostErrors(form, edit, hosts);
  const invalid = Boolean(errors.alias || errors.port) || form.other.some((o) => optionProblem(o));
  const name = edit.patterns.join(' ') || hostLabel(host);
  const mono = hostMonogram(host);

  const save = useAppMutation(api.saveHost, {
    success: () => t('hosts.saved', { name }),
    onSuccess: (saved) => navigate({ page: 'hosts', hostId: saved.id }),
  });
  const remove = useAppMutation((id: number) => api.deleteHost(id), {
    success: () => t('hosts.deleted', { name }),
    onSuccess: () => {
      setConfirmDelete(false);
      navigate({ page: 'hosts' });
    },
  });
  const connect = useAppMutation((alias: string) => api.testConnection(alias), {
    onSuccess: setTest,
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (readOnly || invalid || save.isPending) return;
    save.mutate(edit);
  };
  const testable = host.kind === 'host' && !host.isWildcard && !dirty;

  return (
    <form
      onSubmit={submit}
      aria-labelledby="host-title"
      className="glass-raised relative flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl"
    >
      <div
        aria-hidden="true"
        className="soft-glow absolute -top-[215px] -right-[165px] h-[430px] w-[530px] [--glow-color:rgb(37_99_235/0.32)]"
      />
      <div className="relative flex flex-wrap items-center gap-2.5 px-5 pt-[18px] pb-3.5">
        <Tile tone={mono.tone} size={44}>
          <span className="font-mono text-[14px] font-semibold">{mono.text}</span>
        </Tile>
        <div className="min-w-[200px] flex-1">
          <h2 id="host-title" className="truncate font-mono text-[17px] leading-6 font-semibold">
            {hostLabel(host)}
          </h2>
          <p className="text-[12.5px] text-muted">
            {host.lineEnd > host.lineStart
              ? t('hosts.lines', { start: host.lineStart, end: host.lineEnd })
              : t('hosts.line', { start: host.lineStart })}
          </p>
        </div>
        {testable ? (
          <Button
            variant="soft"
            icon={<Terminal className="size-[15px]" strokeWidth={1.75} />}
            loading={connect.isPending}
            onClick={() => connect.mutate(host.patterns[0] ?? '')}
          >
            {t('hosts.testConnection')}
          </Button>
        ) : null}
        <IconButton
          label={t('hosts.deleteHost')}
          variant="danger"
          size="md"
          icon={<Trash2 className="size-[15px]" strokeWidth={1.75} />}
          onClick={() => setConfirmDelete(true)}
        />
      </div>

      {test ? (
        <div
          role="status"
          className={cn(
            'relative mx-5 mb-3 flex gap-2.5 rounded-xl border px-3 py-2.5',
            test.ok ? 'border-ok/30 bg-ok/[0.08]' : 'border-critical-solid/30 bg-critical-solid/10',
          )}
        >
          {test.ok ? (
            <CheckCircle2
              aria-hidden="true"
              className="mt-0.5 size-4 shrink-0 text-ok"
              strokeWidth={2}
            />
          ) : (
            <XCircle
              aria-hidden="true"
              className="mt-0.5 size-4 shrink-0 text-critical"
              strokeWidth={2}
            />
          )}
          <div className="flex min-w-0 flex-1 flex-col gap-1">
            <span className="font-medium">
              {test.ok ? t('hosts.testOk') : t('hosts.testFailed')}
            </span>
            {test.output ? (
              <pre className="selectable max-h-24 overflow-auto font-mono text-[11.5px] leading-[17px] whitespace-pre-wrap text-fg-2">
                {test.output}
              </pre>
            ) : null}
          </div>
          <IconButton
            label={t('common.close')}
            icon={<X className="size-3.5" />}
            onClick={() => setTest(null)}
          />
        </div>
      ) : null}

      <div className="relative flex min-h-0 flex-1 flex-wrap gap-[18px] overflow-y-auto px-5 pt-0.5 pb-[18px]">
        {readOnly ? (
          <div className="flex min-w-0 flex-[3_1_300px] flex-col gap-3">
            <p className="rounded-xl border border-info-solid/30 bg-info-solid/[0.09] px-3 py-2.5 text-[12.5px] text-info">
              {t('hosts.matchReadOnly')}
            </p>
          </div>
        ) : (
          <fieldset className="flex min-w-0 flex-[3_1_300px] flex-col gap-3.5">
            <HostFields
              form={form}
              set={set}
              hosts={hosts}
              hostId={host.id}
              errors={dirty ? errors : { port: errors.port }}
            />

            <HostResolution form={form} />

            <OtherOptions rows={form.other} onChange={(rows) => set('other', rows)} />
          </fieldset>
        )}

        <div className="flex min-w-0 flex-[2_1_220px] flex-col gap-2">
          <h3 className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
            {t('hosts.preview')}
          </h3>
          <ConfigPreview
            className="flex-1"
            lines={
              readOnly
                ? [
                    { key: 'Match', value: host.criteria ?? '', header: true },
                    ...host.options.map((o) => ({ ...o, header: false })),
                  ]
                : previewLines(edit)
            }
          />
          <p className="flex gap-2 text-[12px] leading-[18px] text-subtle">
            <ShieldCheck
              aria-hidden="true"
              className="mt-0.5 size-3.5 shrink-0"
              strokeWidth={1.75}
            />
            {t('hosts.backupNote')}
          </p>
        </div>
      </div>

      {!readOnly ? (
        <footer className="relative flex flex-wrap items-center justify-end gap-2.5 border-t border-white/[0.07] px-5 py-3">
          {dirty ? (
            <span className="mr-auto inline-flex items-center gap-2 text-[12.5px] text-warning">
              <span aria-hidden="true" className="size-[7px] rounded-full bg-warning" />
              {t('hosts.unsaved')}
            </span>
          ) : null}
          <Button disabled={!dirty} onClick={() => setForm(initial)}>
            {t('common.discard')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            loading={save.isPending}
            disabled={!dirty || invalid}
          >
            {t('common.save')}
          </Button>
        </footer>
      ) : null}

      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={t('hosts.deleteTitle', { name: hostLabel(host) })}
        description={t('hosts.deleteText')}
        confirmLabel={t('common.delete')}
        destructive
        busy={remove.isPending}
        onConfirm={() => remove.mutate(host.id)}
      />
    </form>
  );
}
