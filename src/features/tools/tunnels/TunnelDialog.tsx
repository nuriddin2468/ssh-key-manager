import { ArrowDownToLine, ArrowUpFromLine, Cable, Globe } from 'lucide-react';
import { type FormEvent, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import type { TunnelKind } from '@/bindings/TunnelKind';
import type { TunnelView } from '@/bindings/TunnelView';
import { Button } from '@/components/ui/Button';
import { ChoiceCards, type ChoiceIcon } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Select } from '@/components/ui/Select';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { useHostAliases } from '../ssh/parts';
import {
  commandText,
  formOf,
  formProblems,
  KIND_TONE,
  KINDS,
  type TunnelForm,
  tunnelOf,
} from './model';

export const KIND_ICON: Record<TunnelKind, ChoiceIcon> = {
  local: ArrowDownToLine,
  remote: ArrowUpFromLine,
  dynamic: Globe,
};

/** Adds a tunnel (`editing` null) or changes one. Render inside an open `<Dialog>`. */
export function TunnelDialog({
  editing,
  onDone,
}: {
  editing: TunnelView | null;
  onDone: () => void;
}) {
  const { t } = useTranslation();
  const aliases = useHostAliases();
  const [form, setForm] = useState<TunnelForm>(() => formOf(editing?.tunnel ?? null, ''));
  const [shown, setShown] = useState(false);
  const [taken, setTaken] = useState(false);
  const set = (patch: Partial<TunnelForm>) => {
    setForm((current) => ({ ...current, ...patch }));
    if ('listenPort' in patch || 'kind' in patch || 'alias' in patch) setTaken(false);
  };
  const problems = formProblems(form);
  const invalid = Object.values(problems).some(Boolean);
  const save = useAppMutation(() => api.tunnelSave(tunnelOf(form)), {
    onSuccess: onDone,
    onError: (error) => {
      if (error.code !== 'already_exists') return false;
      setTaken(true);
      return true;
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setShown(true);
    if (!invalid) save.mutate(undefined);
  };
  const remote = form.kind === 'remote';
  const forward = form.kind !== 'dynamic';
  const tunnel = tunnelOf(form);

  return (
    <DialogContent section="tools" className="max-w-[600px]">
      <DialogHeader
        icon={
          <Tile tone={KIND_TONE[form.kind]} size={40} glow>
            <Cable className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={editing ? t('tunnels.dialog.editTitle') : t('tunnels.dialog.newTitle')}
        description={t('tunnels.dialog.description')}
      />
      <form onSubmit={submit} className="contents" noValidate>
        <DialogBody>
          <ChoiceCards
            legend={t('tunnels.dialog.kind')}
            value={form.kind}
            onValueChange={(kind) => set({ kind })}
            options={KINDS.map((kind) => ({
              value: kind,
              title: t(`tunnels.kind.${kind}`),
              hint: t(`tunnels.kindHint.${kind}`),
              tone: KIND_TONE[kind],
              icon: KIND_ICON[kind],
            }))}
            columns={3}
            layout="stack"
          />
          <div className="grid grid-cols-2 gap-3">
            <Select
              label={t('tunnels.dialog.host')}
              value={form.alias}
              onValueChange={(alias) => set({ alias })}
              options={aliases.map((alias) => ({ value: alias, label: alias }))}
              placeholder={t('tunnels.dialog.hostPlaceholder')}
              hint={aliases.length === 0 ? t('tunnels.dialog.noHosts') : undefined}
              mono
            />
            <TextField
              label={t('tunnels.dialog.name')}
              value={form.name}
              onChange={(event) => set({ name: event.target.value })}
              placeholder={t('tunnels.dialog.namePlaceholder')}
              maxLength={64}
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <TextField
              label={remote ? t('tunnels.dialog.listenRemote') : t('tunnels.dialog.listenLocal')}
              value={form.listenPort}
              onChange={(event) => set({ listenPort: event.target.value })}
              inputMode="numeric"
              placeholder={form.kind === 'dynamic' ? '1080' : '8080'}
              mono
              error={
                taken
                  ? t('tunnels.dialog.portTaken')
                  : shown && problems.listenPort
                    ? t('tunnels.dialog.portInvalid')
                    : undefined
              }
            />
            <Select
              label={t('tunnels.dialog.bind')}
              value={form.all ? 'all' : 'default'}
              onValueChange={(value) => set({ all: value === 'all' })}
              options={[
                {
                  value: 'default',
                  label: remote ? t('tunnels.dialog.bindServer') : t('tunnels.dialog.bindLoopback'),
                },
                { value: 'all', label: t('tunnels.dialog.bindAll') },
              ]}
              hint={form.all ? t('tunnels.exposed') : undefined}
            />
          </div>
          {forward ? (
            <div className="grid grid-cols-[1fr_120px] gap-3">
              <TextField
                label={remote ? t('tunnels.dialog.targetRemote') : t('tunnels.dialog.targetLocal')}
                value={form.targetHost}
                onChange={(event) => set({ targetHost: event.target.value })}
                placeholder="localhost"
                mono
                error={shown && problems.targetHost ? t('tunnels.dialog.hostInvalid') : undefined}
              />
              <TextField
                label={t('tunnels.dialog.targetPort')}
                value={form.targetPort}
                onChange={(event) => set({ targetPort: event.target.value })}
                inputMode="numeric"
                placeholder="80"
                mono
                error={shown && problems.targetPort ? t('tunnels.dialog.portInvalid') : undefined}
              />
            </div>
          ) : null}
          <SwitchGroup>
            <SwitchRow
              label={t('tunnels.dialog.autoReconnect')}
              hint={t('tunnels.dialog.autoReconnectHint')}
              checked={form.autoReconnect}
              onCheckedChange={(autoReconnect) => set({ autoReconnect })}
            />
          </SwitchGroup>
          <div className="flex flex-col gap-1.5">
            <span className="text-[12px] font-semibold text-fg-2">
              {t('tunnels.dialog.command')}
            </span>
            <code className="selectable rounded-[10px] border border-white/[0.07] bg-terminal px-3 py-2 font-mono text-[12px] break-all text-fg-2">
              {commandText(tunnel)}
            </code>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="ghost" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            loading={save.isPending}
            disabled={aliases.length === 0}
          >
            {editing ? t('tunnels.dialog.save') : t('tunnels.dialog.add')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
