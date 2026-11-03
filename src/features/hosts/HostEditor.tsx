import {
  Copy,
  MoreHorizontal,
  PlugZap,
  ShieldCheck,
  SquareTerminal,
  Terminal,
  Trash2,
} from 'lucide-react';
import {
  type FormEvent,
  type ReactNode,
  useCallback,
  useId,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useEnvironment } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostEntry } from '@/bindings/HostEntry';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/components/ui/Menu';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { Tooltip } from '@/components/ui/Tooltip';
import { HostResolution } from '@/features/hostsFile/HostResolution';
import { CheckHostKeyDialog } from '@/features/known/CheckHostKeyDialog';
import { useConnect } from '@/features/terminal/connect';
import { copyText } from '@/lib/clipboard';
import { displayPath } from '@/lib/format';
import { AppError } from '@/lib/ipc';
import { ConfigPreview, ServerFields, useHostErrors } from './HostFields';
import { HostPasswordDialog } from './HostPasswordDialog';
import { LoginResult } from './LoginResult';
import type { MessageAction } from './login';
import {
  changedLines,
  chooseKey,
  configMethod,
  editFromForm,
  formFromHost,
  gitAccount,
  gitService,
  type HostForm,
  hostLabel,
  hostMonogram,
  isConcrete,
  METHOD_LABEL,
  optionProblem,
  previewLines,
  sameEdit,
  suppressedOption,
} from './model';
import { MoreSection } from './OtherOptions';
import { SignInSection } from './SignIn';
import { SwitchToKeyDialog } from './SwitchToKeyDialog';
import { useDialog } from './useDialog';
import {
  type EntryFollowUp,
  entryFollowUp,
  hostAliases,
  hostEntryInput,
  useHostVault,
  vaultErrorMessage,
} from './vault';

interface HostEditorProps {
  host: HostEntry;
  hosts: HostEntry[];
}

export function HostEditor({ host, hosts }: HostEditorProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const connectTo = useConnect();
  const environment = useEnvironment();
  const home = environment.data?.paths.home;
  const sshMissing = environment.data ? environment.data.opensshVersion === null : false;

  const vault = useHostVault(host);
  const found =
    vault.vault === 'unlocked' && vault.entry
      ? { alias: vault.alias, entry: vault.entry }
      : undefined;
  const saved = found?.entry;
  const alias = vault.vault === 'unlocked' ? vault.alias : (hostAliases(host)[0] ?? '');
  const passwordSaved = Boolean(saved);

  const initial = useMemo(() => formFromHost(host, { passwordSaved }), [host, passwordSaved]);
  const [form, setForm] = useState<HostForm>(initial);
  const [base, setBase] = useState(initial);
  // The switch to a key saved the block; once it closes, the form takes the
  // block as saved, which is what the switch was doing.
  const [adopt, setAdopt] = useState(false);
  if (adopt) {
    setAdopt(false);
    setBase(initial);
    setForm(initial);
  } else if (base !== initial) {
    setBase(initial);
    const untouched = sameEdit(form, base, host.id);
    if (untouched && !sameEdit(initial, base, host.id)) {
      // Changed on disk (in a terminal, say) and not edited here: take the
      // new version, keeping a Key / Key and password choice (it writes nothing).
      const keepMethod =
        form.method !== base.method &&
        form.method !== null &&
        initial.method !== null &&
        configMethod(form.method) === configMethod(initial.method);
      setForm(keepMethod ? { ...initial, method: form.method } : initial);
    } else if (
      form.method === base.method &&
      initial.method !== null &&
      base.method !== null &&
      initial.method !== base.method &&
      configMethod(initial.method) === configMethod(base.method)
    ) {
      // The vault now tells Key from Key and password (it was unlocked, or a
      // password was saved or recycled); follow it unless the user chose.
      const method = initial.method;
      setForm((f) => ({ ...f, method }));
    }
  }

  const [confirmDelete, setConfirmDelete] = useState(false);
  const [test, setTest] = useState<{ run: ConnectionTest; withVault: boolean } | null>(null);
  // Dialogs opened from the sign-in section give focus back to it when the
  // button that opened them is gone (the password was saved, the switch ended).
  const signIn = useRef<HTMLFieldSetElement>(null);
  const sectionButton = () =>
    signIn.current?.querySelector<HTMLElement>('[data-card=password] button') ??
    signIn.current?.querySelector<HTMLElement>('[role=radio][data-state=checked]');
  // `otp`: opened to add a 2FA secret, so that field takes focus.
  const [passwordOpen, openPassword, closePassword] = useDialog<'edit' | 'otp'>(sectionButton);
  const [hostKeyOpen, openHostKey, closeHostKey] = useDialog<true>();
  // Captured when it opens, so it stays put if the vault locks meanwhile.
  const [switching, openSwitch, closeSwitch] = useDialog<{
    alias: string;
    entryId: string;
    keyPath: string;
  }>(sectionButton);
  const switchSaved = useRef(false);
  const endSwitch = useCallback(() => {
    if (switchSaved.current) setAdopt(true);
    switchSaved.current = false;
    closeSwitch();
  }, [closeSwitch]);
  const [toRemove, setToRemove] = useState<number[] | null>(null);
  const header = useRef<HTMLDivElement>(null);
  const set = <K extends keyof HostForm>(key: K, value: HostForm[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  const readOnly = host.kind === 'match';
  const concrete = isConcrete(host) && alias !== '';
  const git = gitService(host);
  const edit = editFromForm(form, host.id);
  const followUp = entryFollowUp(form, host, found);
  const dirty = !sameEdit(form, initial, host.id) || followUp.kind === 'trash';
  // Installing a key saves the block; edits outside the sign-in section would be lost.
  const otherDirty = !sameEdit(
    {
      ...form,
      method: initial.method,
      identityFile: initial.identityFile,
      identitiesOnly: initial.identitiesOnly,
    },
    initial,
    host.id,
  );
  const errors = useHostErrors(form, edit, hosts);
  const invalid =
    Boolean(errors.alias || errors.port) ||
    form.other.some((o) => !suppressedOption(form, o) && optionProblem(o));
  const name = edit.patterns.join(' ') || hostLabel(host);
  const mono = hostMonogram(host);

  const save = useAppMutation(
    async (vars: { edit: HostEdit; followUp: EntryFollowUp }) => {
      const result = await api.saveHost(vars.edit);
      // The block is saved either way; the vault entry follows it if it can.
      let vaultError: unknown = null;
      try {
        await applyFollowUp(vars.followUp);
      } catch (error) {
        vaultError = error;
      }
      return { result, vaultError };
    },
    {
      onSuccess: ({ result, vaultError }, vars) => {
        toast.success(t('hosts.saved', { name }), {
          description:
            vars.followUp.kind === 'trash' && !vaultError
              ? t('hosts.editor.savedTrashed')
              : undefined,
        });
        if (vaultError) {
          toast.error(t('hosts.editor.vaultUpdateFailed'), {
            description: vaultErrorMessage(t, vaultError),
          });
        }
        navigate({ page: 'hosts', hostId: result.id });
      },
    },
  );
  const remove = useAppMutation((id: number) => api.deleteHost(id), {
    success: () => t('hosts.deleted', { name }),
    onSuccess: () => {
      setConfirmDelete(false);
      navigate({ page: 'hosts' });
    },
  });
  // With a saved password the check signs in with it (and the 2FA code);
  // otherwise ssh runs in batch mode and only keys can get in.
  const check = useAppMutation(
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
    if (readOnly || invalid || save.isPending || !dirty) return;
    save.mutate({ edit, followUp });
  };
  const runCheck = () => check.isPending || check.mutate(passwordSaved);
  const copyCommand = async () => {
    try {
      await copyText(`ssh ${alias}`);
      toast.success(t('hosts.editor.commandCopied', { alias }));
    } catch (error) {
      toastError(t, error);
    }
  };
  const openTerminal = async () => {
    try {
      await api.terminalOpenExternal(alias);
    } catch (error) {
      toastError(t, error);
    }
  };
  const fixes: Partial<Record<MessageAction, () => void>> = {
    checkHostKey: () => openHostKey(true),
    ...(saved
      ? { editPassword: () => openPassword('edit'), addOtp: () => openPassword('otp') }
      : {}),
  };
  // Connect and Check run the saved block, and need ssh.
  const runReason = sshMissing
    ? t('hosts.editor.noSsh')
    : dirty
      ? t('hosts.editor.saveFirst')
      : null;

  const via =
    host.proxyJump && host.proxyJump.toLowerCase() !== 'none'
      ? t('hosts.via', { jump: host.proxyJump })
      : null;
  const target = `${host.user ? `${host.user}@` : ''}${host.hostName ?? alias}${
    host.port && host.port !== 22 ? `:${host.port}` : ''
  }`;
  const subtitle = concrete
    ? [target, via, form.method ? t(METHOD_LABEL[form.method]) : null].filter(Boolean).join(' · ')
    : host.lineEnd > host.lineStart
      ? t('hosts.lines', { start: host.lineStart, end: host.lineEnd })
      : t('hosts.line', { start: host.lineStart });
  const okTitle =
    git && test?.run.ok
      ? (() => {
          const account = gitAccount(test.run.output);
          return account
            ? t('hosts.editor.gitOk', { service: git, account })
            : t('hosts.editor.gitOkNoAccount', { service: git });
        })()
      : undefined;
  const lines = readOnly
    ? [
        { key: 'Match', value: host.criteria ?? '', header: true },
        ...host.options.map((o) => ({ ...o, header: false })),
      ]
    : previewLines(edit);

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
        className="soft-glow absolute -top-[215px] -right-[165px] h-[430px] w-[530px] [--glow-color:rgb(37_99_235/0.32)]"
      />
      <div
        ref={header}
        className="relative flex flex-wrap items-center gap-3 px-5 pt-[18px] pb-3.5"
      >
        <Tile tone={mono.tone} size={44}>
          <span className="font-mono text-[14px] font-semibold">{mono.text}</span>
        </Tile>
        <div className="min-w-[200px] flex-1">
          <h2
            id="host-title"
            title={hostLabel(host)}
            className="truncate font-mono text-[17px] leading-6 font-medium"
          >
            {hostLabel(host)}
          </h2>
          <p className="truncate text-subtle">{subtitle}</p>
        </div>
        {!concrete || readOnly ? null : git ? (
          // Not disabled while it runs, so it keeps focus for the next try.
          <ActionButton
            data-check=""
            reason={runReason}
            busy={check.isPending}
            icon={<PlugZap className="size-4" strokeWidth={2} />}
            onClick={runCheck}
          >
            {t('hosts.editor.check')}
          </ActionButton>
        ) : (
          <ActionButton
            reason={runReason}
            icon={<Terminal className="size-4" strokeWidth={2.2} />}
            onClick={() => connectTo(alias)}
          >
            {t('hosts.editor.connect')}
          </ActionButton>
        )}
        <Menu>
          <MenuTrigger asChild>
            <IconButton
              data-more=""
              label={t('hosts.editor.moreActions')}
              variant="secondary"
              className="size-9 rounded-[10px]"
              icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
            />
          </MenuTrigger>
          <MenuContent>
            {concrete && !readOnly ? (
              <>
                {git ? null : (
                  <MenuItem
                    icon={<PlugZap className="size-[15px]" strokeWidth={1.9} />}
                    disabled={runReason !== null}
                    onSelect={runCheck}
                  >
                    {t('hosts.editor.checkConnection')}
                  </MenuItem>
                )}
                <MenuItem
                  icon={<Copy className="size-[15px]" strokeWidth={1.9} />}
                  onSelect={() => void copyCommand()}
                >
                  {t('hosts.editor.copyCommand')}
                </MenuItem>
                <MenuItem
                  icon={<SquareTerminal className="size-[15px]" strokeWidth={1.9} />}
                  disabled={runReason !== null}
                  onSelect={() => void openTerminal()}
                >
                  {t('hosts.editor.openTerminal')}
                </MenuItem>
                <MenuSeparator />
              </>
            ) : null}
            <MenuItem
              destructive
              icon={<Trash2 className="size-[15px]" strokeWidth={1.9} />}
              onSelect={() => setConfirmDelete(true)}
            >
              {t('hosts.deleteHost')}
            </MenuItem>
          </MenuContent>
        </Menu>
      </div>

      {/* Mounted before any result, so screen readers announce each one. */}
      <div role="status" className="relative">
        {test ? (
          <LoginResult
            className="mx-5 mb-3"
            run={test.run}
            context={test.withVault ? 'vaultTest' : 'test'}
            alias={alias}
            okTitle={okTitle}
            vaultLocked={vault.vault === 'locked'}
            onAction={fixes}
            onClose={() => {
              setTest(null);
              header.current
                ?.querySelector<HTMLElement>(git ? '[data-check]' : '[data-more]')
                ?.focus();
            }}
          />
        ) : null}
      </div>

      <div className="relative flex min-h-0 flex-1 flex-wrap content-start gap-[18px] overflow-y-auto px-5 pt-0.5 pb-[18px]">
        {readOnly ? (
          <div className="flex min-w-0 flex-[999_1_400px] flex-col gap-3">
            <p className="rounded-xl border border-info-solid/30 bg-info-solid/[0.09] px-3 py-2.5 text-[12.5px] text-info">
              {t('hosts.matchReadOnly')}
            </p>
          </div>
        ) : (
          <div className="flex min-w-0 flex-[999_1_400px] flex-col gap-[18px]">
            <Section legend={t('hosts.editor.server')}>
              <ServerFields
                form={form}
                set={set}
                errors={dirty ? errors : { port: errors.port }}
                // Patterns say how to write more of them.
                aliasHint={concrete ? t('hosts.editor.aliasHint') : t('hosts.aliasHint')}
              />
            </Section>

            <HostResolution form={form} />

            {concrete && form.method !== null ? (
              <SignInSection
                ref={signIn}
                form={{ ...form, method: form.method }}
                update={setForm}
                savedMethod={initial.method ?? 'key'}
                vault={vault}
                alias={alias}
                trashPending={followUp.kind === 'trash'}
                otherDirty={otherDirty}
                onEditPassword={openPassword}
                onInstallKey={() =>
                  saved &&
                  openSwitch({ alias, entryId: saved.id, keyPath: form.identityFile.trim() })
                }
                onCreateKey={() =>
                  dialogs.generateKeyFor((made) => {
                    const file = displayPath(made.privatePath ?? '', home);
                    if (file) setForm((f) => chooseKey(f, file));
                  })
                }
              />
            ) : null}

            <MoreSection form={form} set={set} hosts={hosts} hostId={host.id} />
          </div>
        )}

        <aside
          aria-labelledby="host-preview-title"
          className="flex min-w-[220px] flex-[1_1_220px] flex-col gap-2"
        >
          <h3
            id="host-preview-title"
            className="text-[12px] font-semibold tracking-[0.02em] text-subtle"
          >
            {t('hosts.editor.previewTitle')}
          </h3>
          <ConfigPreview lines={lines} changed={readOnly ? undefined : changedLines(lines, host)} />
          <p className="flex gap-2 text-[12px] leading-[18px] text-subtle">
            <ShieldCheck
              aria-hidden="true"
              className="mt-0.5 size-3.5 shrink-0"
              strokeWidth={1.75}
            />
            {t('hosts.backupNote')}
          </p>
        </aside>
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
      <Dialog open={switching !== null} onOpenChange={(open) => open || endSwitch()}>
        {switching ? (
          <SwitchToKeyDialog
            host={host}
            alias={switching.alias}
            entryId={switching.entryId}
            initialKeyPath={switching.keyPath || undefined}
            onAction={{
              checkHostKey: () => openHostKey(true),
              editPassword: () => openPassword('edit'),
              addOtp: () => openPassword('otp'),
            }}
            onConfigSaved={() => {
              switchSaved.current = true;
            }}
            onDone={endSwitch}
          />
        ) : null}
      </Dialog>
      <Dialog open={passwordOpen !== null} onOpenChange={(open) => open || closePassword()}>
        {passwordOpen && vault.vault === 'unlocked' ? (
          <HostPasswordDialog
            alias={alias}
            user={form.user.trim()}
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

/** What saving does to the vault entry (see `entryFollowUp`). */
async function applyFollowUp(followUp: EntryFollowUp): Promise<void> {
  if (followUp.kind === 'trash') {
    await api.vaultTrash(followUp.entryId);
  } else if (followUp.kind === 'update') {
    const current = await api.vaultEntry(followUp.entryId);
    await api.vaultUpdate(
      followUp.entryId,
      // `null` keeps the password and the 2FA secret.
      hostEntryInput(
        followUp.alias,
        { username: followUp.username, password: null, otp: null },
        current,
      ),
    );
  }
}

function Section({ legend, children }: { legend: string; children: ReactNode }) {
  return (
    <fieldset className="m-0 flex min-w-0 flex-col border-0 p-0">
      <legend className="mb-2 p-0 text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {legend}
      </legend>
      {children}
    </fieldset>
  );
}

interface ActionButtonProps {
  /** Why it can't run now; shown as a tooltip and read with the button. */
  reason: string | null;
  busy?: boolean;
  icon: ReactNode;
  onClick: () => void;
  children: ReactNode;
  'data-check'?: string;
}

/**
 * The header's primary action. It stays focusable while it can't run (or
 * while it runs), so the reason can be read and focus isn't lost.
 */
function ActionButton({ reason, busy, icon, onClick, children, ...rest }: ActionButtonProps) {
  const reasonId = useId();
  const blocked = reason !== null || busy;
  const button = (
    <Button
      variant="primary"
      className="h-9 rounded-[10px] px-4 text-[13.5px] aria-disabled:opacity-50 aria-disabled:hover:brightness-100"
      icon={busy ? <Spinner className="size-4" /> : icon}
      aria-disabled={blocked || undefined}
      aria-busy={busy || undefined}
      aria-describedby={reason ? reasonId : undefined}
      onClick={() => blocked || onClick()}
      {...rest}
    >
      {children}
    </Button>
  );
  if (!reason) return button;
  return (
    <>
      <Tooltip content={reason}>{button}</Tooltip>
      <span id={reasonId} className="sr-only">
        {reason}
      </span>
    </>
  );
}
