import { ShieldCheck, Terminal, Trash2 } from 'lucide-react';
import { type FormEvent, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { HostEntry } from '@/bindings/HostEntry';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { CheckHostKeyDialog } from '@/features/known/CheckHostKeyDialog';
import { AppError } from '@/lib/ipc';
import { ConfigPreview, HostFields, useHostErrors } from './HostFields';
import { HostPassword } from './HostPassword';
import { HostPasswordDialog } from './HostPasswordDialog';
import { LoginResult } from './LoginResult';
import type { MessageAction } from './login';
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
import { SwitchToKeyDialog } from './SwitchToKeyDialog';
import { useDialog } from './useDialog';
import { useHostVault, vaultErrorMessage } from './vault';

interface HostEditorProps {
  host: HostEntry;
  hosts: HostEntry[];
}

const sameEdit = (a: HostForm, b: HostForm, id: number) =>
  JSON.stringify(editFromForm(a, id)) === JSON.stringify(editFromForm(b, id));

export function HostEditor({ host, hosts }: HostEditorProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const initial = useMemo(() => formFromHost(host), [host]);
  const [form, setForm] = useState<HostForm>(initial);
  // The block changed on disk (the switch to a key saved it, or a terminal
  // did): take the new version unless the form has edits of its own.
  const [base, setBase] = useState(initial);
  if (base !== initial) {
    setBase(initial);
    if (!sameEdit(initial, base, host.id) && sameEdit(form, base, host.id)) setForm(initial);
  }
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [test, setTest] = useState<{ run: ConnectionTest; withVault: boolean } | null>(null);
  // Recycling the password at the end removes the button that opened the
  // switch to a key; focus then goes to the password section's first one.
  const passwordSection = useRef<HTMLElement>(null);
  const sectionButton = () => passwordSection.current?.querySelector<HTMLElement>('button');
  // `otp`: opened to add a 2FA secret, so that field takes focus.
  const [passwordOpen, openPassword, closePassword] = useDialog<'edit' | 'otp'>(sectionButton);
  const [hostKeyOpen, openHostKey, closeHostKey] = useDialog<true>();
  // Captured when it opens, so it stays put if the vault locks meanwhile.
  const [switching, openSwitch, closeSwitch] = useDialog<{ alias: string; entryId: string }>(
    sectionButton,
  );
  const [toRemove, setToRemove] = useState<number[] | null>(null);
  const header = useRef<HTMLDivElement>(null);
  const set = <K extends keyof HostForm>(key: K, value: HostForm[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const readOnly = host.kind === 'match';
  const edit = editFromForm(form, host.id);
  const dirty = JSON.stringify(edit) !== JSON.stringify(editFromForm(initial, host.id));
  const errors = useHostErrors(form, edit, hosts);
  const invalid = Boolean(errors.alias || errors.port) || form.other.some((o) => optionProblem(o));
  const name = edit.patterns.join(' ') || hostLabel(host);
  const mono = hostMonogram(host);
  const vault = useHostVault(host);
  const saved = vault.vault === 'unlocked' ? vault.entry : undefined;
  const alias = vault.vault === 'unlocked' ? vault.alias : (host.patterns[0] ?? '');

  const save = useAppMutation(api.saveHost, {
    success: () => t('hosts.saved', { name }),
    onSuccess: (result) => navigate({ page: 'hosts', hostId: result.id }),
  });
  const remove = useAppMutation((id: number) => api.deleteHost(id), {
    success: () => t('hosts.deleted', { name }),
    onSuccess: () => {
      setConfirmDelete(false);
      navigate({ page: 'hosts' });
    },
  });
  // With a saved password the test signs in with it (and the 2FA code);
  // otherwise ssh runs in batch mode and only keys can get in.
  const connect = useAppMutation(
    async (withVault: boolean) => ({
      run: withVault ? await api.vaultTestConnection(alias) : await api.testConnection(alias),
      withVault,
    }),
    {
      onSuccess: setTest,
      onError: (error) => {
        if (AppError.from(error).code !== 'vault_locked') return false;
        toast.error(vaultErrorMessage(t, error));
        return true;
      },
    },
  );
  const removeKnown = useAppMutation((lines: number[]) => api.removeKnownHosts(lines), {
    success: (_, lines) => t('known.removed', { line: lines.join(', ') }),
    onSuccess: () => setToRemove(null),
  });

  const submit = (event: FormEvent) => {
    // Forms in dialogs opened from here bubble their submit up React's tree.
    if (event.target !== event.currentTarget) return;
    event.preventDefault();
    if (readOnly || invalid || save.isPending) return;
    save.mutate(edit);
  };
  const testable = host.kind === 'host' && !host.isWildcard && !dirty;
  const fixes: Partial<Record<MessageAction, () => void>> = {
    checkHostKey: () => openHostKey(true),
    ...(saved
      ? { editPassword: () => openPassword('edit'), addOtp: () => openPassword('otp') }
      : {}),
  };

  return (
    <form
      onSubmit={submit}
      aria-labelledby="host-title"
      // `clip`, not `hidden`: the glow sticks out on the right, and a hidden
      // overflow would let focus scroll the whole editor sideways.
      className="glass-raised relative flex min-w-0 flex-1 flex-col overflow-clip rounded-2xl"
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-[110px] -right-[60px] h-[220px] w-[320px] rounded-full bg-[#2563EB] opacity-35 blur-[60px]"
      />
      <div
        ref={header}
        className="relative flex flex-wrap items-center gap-2.5 px-5 pt-[18px] pb-3.5"
      >
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
          // Not disabled while it runs, so it keeps focus for the next try.
          <Button
            data-test-connection=""
            variant="soft"
            className="aria-disabled:opacity-60"
            icon={
              connect.isPending ? (
                <Spinner className="size-4" />
              ) : (
                <Terminal className="size-[15px]" strokeWidth={1.75} />
              )
            }
            aria-busy={connect.isPending || undefined}
            aria-disabled={connect.isPending || undefined}
            onClick={() => connect.isPending || connect.mutate(Boolean(saved))}
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

      {/* Mounted before any result, so screen readers announce each one. */}
      <div role="status" className="relative">
        {test ? (
          <LoginResult
            className="mx-5 mb-3"
            run={test.run}
            context={test.withVault ? 'vaultTest' : 'test'}
            alias={alias}
            vaultLocked={vault.vault === 'locked'}
            onAction={fixes}
            onClose={() => {
              setTest(null);
              header.current?.querySelector<HTMLElement>('[data-test-connection]')?.focus();
            }}
          />
        ) : null}
      </div>

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

            <HostPassword
              ref={passwordSection}
              vault={vault}
              dirty={dirty}
              onEdit={() => openPassword('edit')}
              onSwitch={() => saved && openSwitch({ alias, entryId: saved.id })}
            />

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

      {/* The switch to a key stays open under the password and host key dialogs it opens. */}
      <Dialog open={switching !== null} onOpenChange={(open) => open || closeSwitch()}>
        {switching ? (
          <SwitchToKeyDialog
            host={host}
            alias={switching.alias}
            entryId={switching.entryId}
            onAction={{
              checkHostKey: () => openHostKey(true),
              editPassword: () => openPassword('edit'),
              addOtp: () => openPassword('otp'),
            }}
            onDone={closeSwitch}
          />
        ) : null}
      </Dialog>
      <Dialog open={passwordOpen !== null} onOpenChange={(open) => open || closePassword()}>
        {passwordOpen && vault.vault === 'unlocked' ? (
          <HostPasswordDialog
            alias={alias}
            user={host.user}
            entry={saved}
            focusOtp={passwordOpen === 'otp'}
            onDone={closePassword}
          />
        ) : null}
      </Dialog>
      <Dialog open={hostKeyOpen !== null} onOpenChange={(open) => open || closeHostKey()}>
        {hostKeyOpen ? (
          <CheckHostKeyDialog
            initialHost={host.hostName ?? alias}
            onRemove={setToRemove}
            onDone={closeHostKey}
          />
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={toRemove !== null}
        onOpenChange={(open) => open || setToRemove(null)}
        title={t('known.removeTitle')}
        description={t('known.removeText')}
        confirmLabel={t('common.delete')}
        destructive
        busy={removeKnown.isPending}
        onConfirm={() => toRemove && removeKnown.mutate(toRemove)}
      />
    </form>
  );
}
