import { Plus, ShieldCheck } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useConfig } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { ConfigPreview, HostFields, useHostErrors } from './HostFields';
import { EMPTY_FORM, editFromForm, type HostForm, previewLines } from './model';

/** Creates a `Host` block; the editor on the Hosts page takes over afterwards. */
export function AddHostDialog({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const config = useConfig();
  const hosts = config.data?.view.hosts ?? [];
  const [form, setForm] = useState<HostForm>(EMPTY_FORM);
  const [touched, setTouched] = useState(false);
  const set = <K extends keyof HostForm>(key: K, value: HostForm[K]) => {
    setTouched(true);
    setForm((f) => ({ ...f, [key]: value }));
  };

  const edit = editFromForm(form, null);
  const errors = useHostErrors(form, edit, hosts);
  const invalid = Boolean(errors.alias || errors.port);

  const add = useAppMutation(api.saveHost, {
    success: () => t('hosts.added', { name: edit.patterns.join(' ') }),
    onSuccess: (saved) => {
      navigate({ page: 'hosts', hostId: saved.id });
      onDone();
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTouched(true);
    if (invalid || add.isPending) return;
    add.mutate(edit);
  };

  return (
    <DialogContent section="hosts" className="max-w-[680px]">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="blue" size={44} glow>
              <Plus className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={t('hosts.addTitle')}
          description={t('hosts.addDescription')}
        />
        <DialogBody>
          <HostFields
            form={form}
            set={set}
            hosts={hosts}
            // Don't shout "required" at an empty form the user has not touched yet.
            errors={touched ? errors : { port: errors.port }}
            autoFocus
          />
          <div className="flex flex-col gap-1.5">
            <span className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
              {t('hosts.preview')}
            </span>
            <ConfigPreview lines={previewLines(edit)} />
            <p className="flex gap-2 text-[12px] leading-[18px] text-subtle">
              <ShieldCheck
                aria-hidden="true"
                className="mt-0.5 size-3.5 shrink-0"
                strokeWidth={1.75}
              />
              {t('hosts.backupNote')}
            </p>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={add.isPending}
            disabled={touched && invalid}
            icon={<Plus className="size-4" strokeWidth={2.25} />}
          >
            {t('hosts.addHost')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
