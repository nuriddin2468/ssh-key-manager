import { useMutation } from '@tanstack/react-query';
import {
  ArrowLeftRight,
  Copy,
  Eye,
  EyeOff,
  FileDown,
  FileUp,
  FolderInput,
  Link2,
  Lock,
  MonitorSmartphone,
  MoreHorizontal,
  Pencil,
  PencilLine,
  Plus,
  Send,
  Server,
  SquareTerminal,
  Trash2,
  TriangleAlert,
  Undo2,
  Variable,
} from 'lucide-react';
import { useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll } from '@/api/queries';
import { useRouter } from '@/app/router';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvKind } from '@/bindings/EnvKind';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { EnvVarInfo } from '@/bindings/EnvVarInfo';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import {
  Menu,
  MenuContent,
  MenuItem,
  MenuSeparator,
  MenuSub,
  MenuTrigger,
} from '@/components/ui/Menu';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { Tooltip } from '@/components/ui/Tooltip';
import { SendDialog } from '@/features/nearby/SendDialog';
import { MASK, REVEAL_MS } from '@/features/passwords/SavedSecret';
import { toastVaultError, useSecretCall, useVaultMutation } from '@/features/passwords/vault';
import { defaultShell, shellName, useShells } from '@/features/terminal/shells';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { cn } from '@/lib/cn';
import { formatRelative } from '@/lib/format';
import { useSettings } from '@/lib/settings';
import { CompareDialog } from './CompareDialog';
import { ExportEnvDialog } from './ExportEnvDialog';
import { FilesSection } from './files/FilesSection';
import { useMakeLocal } from './files/useMakeLocal';
import { MoveEnvDialog } from './MoveEnvDialog';
import {
  compareWith,
  type FirstPart,
  isProduction,
  secondPart,
  showsParts,
  whereLabel,
} from './model';
import { useEnv, useSharedValues } from './queries';
import { RenamePartDialog } from './RenamePartDialog';
import { RestoreEnvDialog } from './RestoreEnvDialog';
import { ShareVariableDialog } from './ShareVariableDialog';
import { useEnvLabel, useProjectNames } from './useProjectNames';
import { VariableDialog } from './VariableDialog';

type Open =
  | { kind: 'variable'; variable: EnvVarInfo | null }
  | { kind: 'share'; variable: EnvVarInfo }
  | { kind: 'export' }
  | { kind: 'compare' }
  | { kind: 'send' }
  | { kind: 'move' }
  | { kind: 'renamePart' }
  | { kind: 'restore'; first: FirstPart };

interface EnvPaneProps {
  summary: EnvSummary;
  /** Every environment, for comparing. */
  all: EnvSummary[];
  onEdit: (env: EnvDetail) => void;
  /** The environment left the list (deleted for good). */
  onGone: () => void;
  onImport: () => void;
}

/**
 * The selected environment: its actions and its variables, values hidden.
 * Mounted per environment (keyed by id), so a shown value never outlives a
 * switch to another one; locking unmounts it too.
 */
export function EnvPane({ summary, all, onEdit, onGone, onImport }: EnvPaneProps) {
  const { t, i18n } = useTranslation();
  const envLabelOf = useEnvLabel();
  const names = useProjectNames();
  const { navigate } = useRouter();
  const terminals = useTerminals();
  const shells = useShells().data ?? [];
  const opensByDefault = defaultShell(shells, useSettings().defaultShell);
  const detail = useEnv(summary.id);
  const [open, setOpen] = useState<Open | null>(null);
  const compareHintId = useId();
  const siblings = compareWith(all, summary);
  const [removing, setRemoving] = useState<EnvVarInfo | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const env = detail.data;
  const label = envLabelOf(summary);
  const production = isProduction(summary.name);
  const inTrash = summary.inTrash;

  const restore = useVaultMutation(() => api.envsRestore(summary.id), {
    success: () => t('envs.restored', { name: label }),
  });
  // Back in its part, it may give its project a second: the first is named
  // before, as when one is made there.
  const startRestore = () => {
    const first = secondPart(all, summary.project, [summary.part]);
    if (first) setOpen({ kind: 'restore', first });
    else restore.mutate(undefined);
  };
  const trash = useVaultMutation(() => api.envsTrash(summary.id), {
    onSuccess: () => {
      const { id } = summary;
      // The pane may be gone when Undo is clicked, so call the command
      // directly. It puts back the parts the project had a moment ago, so
      // nothing is asked, unlike a restore from the recycle bin.
      const undo = async () => {
        try {
          await api.envsRestore(id);
          await invalidateAll();
          navigate({ page: 'envs', envId: id });
          toast.success(t('envs.restored', { name: label }));
        } catch (error) {
          toastVaultError(t, error);
        }
      };
      toast.success(t('envs.movedToTrash', { name: label }), {
        duration: 8_000,
        action: { label: t('envs.undo'), onClick: () => void undo() },
        classNames: {
          actionButton:
            '!h-7 !rounded-lg !border !border-white/15 !bg-white/10 !px-2.5 !text-[12.5px] !font-medium !text-fg hover:!bg-white/15',
        },
      });
    },
  });
  const remove = useVaultMutation(() => api.envsDelete(summary.id), {
    success: () => t('envs.deleted', { name: label }),
    onSuccess: () => {
      setConfirmDelete(false);
      onGone();
    },
  });
  const setKind = useVaultMutation((kind: EnvKind) => api.envsSetKind(summary.id, kind), {
    success: (_, kind) =>
      t(kind === 'local' ? 'envs.kind.nowLocal' : 'envs.kind.nowRemote', { name: label }),
  });
  // Production asks first: its values would be on this disk.
  const makeLocal = useMakeLocal(summary);
  // A remote environment has files only while the vault is unlocked.
  const keptAlways = (env?.files.length ?? 0) - (env?.whileUnlocked.length ?? 0);
  const removeVar = useVaultMutation((name: string) => api.envsRemoveVar(summary.id, name), {
    success: (_, name) => t('envs.varRemoved', { name }),
    onSuccess: () => setRemoving(null),
  });

  /** In `shell`, or the default one. */
  const run = (shell?: string) => {
    terminals.openLocal({
      shell,
      env: { id: summary.id, label },
    });
    navigate({ page: 'terminal' });
  };

  return (
    <section
      aria-label={label}
      className="glass-raised relative flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl"
    >
      <header className="relative flex flex-col gap-3.5 border-b border-white/[0.07] px-5 pt-5 pb-4">
        <div className="flex items-start gap-3">
          <Tile tone="lime" size={44}>
            <Variable className="size-[22px]" strokeWidth={2} />
          </Tile>
          <div className="min-w-0 flex-1">
            <p className="truncate text-[12.5px] text-muted">
              {whereLabel(
                summary.project ? names.get(summary.project) : t('projects.personal'),
                showsParts(all, summary.project) ? summary.part : '',
              )}
            </p>
            <h2 className="selectable flex min-w-0 items-center gap-2 text-[17px] leading-6 font-semibold">
              <span className="truncate">{summary.name}</span>
              <Badge tone={summary.kind === 'local' ? 'accent' : 'neutral'}>
                <span title={t(`envs.kind.${summary.kind}Hint`)}>
                  {t(`envs.kind.${summary.kind}`)}
                  <span className="sr-only">: {t(`envs.kind.${summary.kind}Hint`)}</span>
                </span>
              </Badge>
              {production ? <Badge tone="warning">{t('envs.production')}</Badge> : null}
              {inTrash ? (
                <Badge tone="warning" pill>
                  {t('envs.inTrash')}
                </Badge>
              ) : null}
            </h2>
          </div>
          <Menu>
            <MenuTrigger asChild>
              <IconButton
                label={t('envs.moreActions')}
                variant="secondary"
                size="md"
                icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
              />
            </MenuTrigger>
            <MenuContent align="end">
              {inTrash ? (
                <>
                  <MenuItem icon={<Undo2 className="size-4" />} onSelect={startRestore}>
                    {t('envs.restore')}
                  </MenuItem>
                  <MenuItem
                    destructive
                    icon={<Trash2 className="size-4" />}
                    onSelect={() => setConfirmDelete(true)}
                  >
                    {t('envs.deleteForever')}
                  </MenuItem>
                </>
              ) : (
                <>
                  {shells.length > 1 ? (
                    <>
                      <MenuSub icon={<SquareTerminal className="size-4" />} label={t('envs.runIn')}>
                        {shells.map((shell) => (
                          <MenuItem key={shell.id} onSelect={() => run(shell.id)}>
                            <span className="flex-1">{shellName(t, shell)}</span>
                            {shell === opensByDefault ? (
                              <span className="text-[11.5px] text-subtle">
                                {t('terminal.picker.default')}
                              </span>
                            ) : null}
                          </MenuItem>
                        ))}
                      </MenuSub>
                      <MenuSeparator />
                    </>
                  ) : null}
                  <MenuItem
                    icon={<Pencil className="size-4" />}
                    disabled={!env}
                    onSelect={() => env && onEdit(env)}
                  >
                    {t('envs.editEnv')}
                  </MenuItem>
                  <MenuItem icon={<FileUp className="size-4" />} onSelect={onImport}>
                    {t('envs.importInto')}
                  </MenuItem>
                  {summary.kind === 'local' ? (
                    <MenuItem
                      icon={<Server className="size-4" />}
                      disabled={keptAlways > 0}
                      onSelect={() => setKind.mutate('remote')}
                    >
                      {keptAlways > 0 ? (
                        <span className="flex flex-col">
                          <span>{t('envs.kind.makeRemote')}</span>
                          <span className="text-[11.5px] text-subtle">
                            {t('envs.kind.stopFilesFirst')}
                          </span>
                        </span>
                      ) : (
                        t('envs.kind.makeRemote')
                      )}
                    </MenuItem>
                  ) : (
                    <MenuItem
                      icon={<MonitorSmartphone className="size-4" />}
                      onSelect={makeLocal.start}
                    >
                      {t('envs.kind.makeLocal')}
                    </MenuItem>
                  )}
                  <MenuItem
                    icon={<Send className="size-4" />}
                    onSelect={() => setOpen({ kind: 'send' })}
                  >
                    {t('envs.send')}
                  </MenuItem>
                  <MenuItem
                    icon={<FolderInput className="size-4" />}
                    disabled={!env}
                    onSelect={() => setOpen({ kind: 'move' })}
                  >
                    {t('envs.move.menu')}
                  </MenuItem>
                  {/* Where parts show: names from before projects can change at once. */}
                  {summary.part && showsParts(all, summary.project) ? (
                    <MenuItem
                      icon={<PencilLine className="size-4" />}
                      onSelect={() => setOpen({ kind: 'renamePart' })}
                    >
                      {t('envs.renamePart.menu')}
                    </MenuItem>
                  ) : null}
                  <MenuSeparator />
                  <MenuItem
                    destructive
                    icon={<Trash2 className="size-4" />}
                    onSelect={() => trash.mutate(undefined)}
                  >
                    {t('envs.moveToTrash')}
                  </MenuItem>
                </>
              )}
            </MenuContent>
          </Menu>
          {makeLocal.dialog}
        </div>
        {env?.notes ? (
          <p className="selectable text-[12.5px] leading-[19px] whitespace-pre-wrap text-fg-2">
            {env.notes}
          </p>
        ) : null}
        {inTrash ? (
          <div className="flex flex-wrap items-center gap-2 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.08] px-3 py-2">
            <span className="min-w-0 flex-1 text-[12.5px] text-fg-2">{t('envs.trashNote')}</span>
            <Button
              size="sm"
              variant="primary"
              icon={<Undo2 className="size-3.5" strokeWidth={2} />}
              loading={restore.isPending}
              onClick={startRestore}
            >
              {t('envs.restore')}
            </Button>
          </div>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <Button
              variant="primary"
              size="sm"
              icon={<SquareTerminal className="size-[15px]" strokeWidth={2} />}
              onClick={() => run()}
            >
              {t('envs.run')}
            </Button>
            <Button
              size="sm"
              icon={<FileDown className="size-[15px]" strokeWidth={1.9} />}
              onClick={() => setOpen({ kind: 'export' })}
            >
              {t('envs.exportEnv')}
            </Button>
            {/* Stages of one project and part are what compare. */}
            {siblings.length > 0 ? (
              <Button
                size="sm"
                icon={<ArrowLeftRight className="size-[15px]" strokeWidth={1.9} />}
                onClick={() => setOpen({ kind: 'compare' })}
              >
                {t('envs.compare')}
              </Button>
            ) : (
              // Focusable, so its reason reaches the keyboard and screen
              // readers; the reason is outside, read once as its description.
              <>
                <Tooltip content={t('envs.compareDisabled')}>
                  <Button
                    size="sm"
                    icon={<ArrowLeftRight className="size-[15px]" strokeWidth={1.9} />}
                    aria-disabled="true"
                    aria-describedby={compareHintId}
                    className="cursor-default opacity-50"
                  >
                    {t('envs.compare')}
                  </Button>
                </Tooltip>
                <span id={compareHintId} hidden>
                  {t('envs.compareDisabled')}
                </span>
              </>
            )}
            {summary.modified ? (
              <span className="ml-auto text-[12px] text-subtle">
                {t('envs.modified', {
                  when: formatRelative(new Date(summary.modified), i18n.language),
                })}
              </span>
            ) : null}
          </div>
        )}
      </header>

      <div className="relative flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto px-5 pt-4 pb-5">
        {env ? (
          <FilesSection env={summary} files={env.files} whileUnlocked={env.whileUnlocked} />
        ) : null}
        <div className="flex items-center gap-2">
          <h3 className="text-[13px] font-semibold">
            {t('envs.variables')}
            <span className="ml-1.5 font-normal text-subtle tabular-nums">
              {summary.variableCount}
            </span>
          </h3>
          {inTrash ? null : (
            <Button
              variant="soft"
              size="sm"
              className="ml-auto"
              icon={<Plus className="size-3.5" strokeWidth={2.5} />}
              onClick={() => setOpen({ kind: 'variable', variable: null })}
            >
              {t('envs.addVar')}
            </Button>
          )}
        </div>

        {detail.isPending ? (
          <div className="grid flex-1 place-items-center text-subtle">
            <Spinner className="size-5" />
          </div>
        ) : env && env.variables.length === 0 ? (
          <div className="flex flex-col items-center gap-2 rounded-2xl border border-dashed border-white/[0.14] px-4 py-8 text-center">
            <p className="font-semibold">{t('envs.noVarsTitle')}</p>
            <p className="max-w-[380px] text-[12.5px] text-muted">{t('envs.noVarsText')}</p>
            {inTrash ? null : (
              <div className="mt-1 flex flex-wrap justify-center gap-2">
                <Button
                  size="sm"
                  icon={<Plus className="size-3.5" strokeWidth={2.5} />}
                  onClick={() => setOpen({ kind: 'variable', variable: null })}
                >
                  {t('envs.addVar')}
                </Button>
                <Button
                  size="sm"
                  icon={<FileUp className="size-3.5" strokeWidth={2} />}
                  onClick={onImport}
                >
                  {t('envs.importInto')}
                </Button>
              </div>
            )}
          </div>
        ) : env ? (
          <table className="w-full table-fixed border-collapse text-left">
            <caption className="sr-only">{t('envs.variables')}</caption>
            <colgroup>
              <col className="w-[34%]" />
              <col className="w-[40%]" />
              <col />
              <col className="w-[76px]" />
            </colgroup>
            <thead>
              <tr className="h-8 border-b border-white/[0.07] text-[11.5px] font-medium tracking-[0.02em] text-subtle">
                <th scope="col" className="px-2.5 font-medium">
                  {t('envs.colName')}
                </th>
                <th scope="col" className="px-2.5 font-medium">
                  {t('envs.colValue')}
                </th>
                <th scope="col" className="px-2.5 font-medium">
                  {t('envs.colNote')}
                </th>
                <th scope="col" className="px-2.5 font-medium">
                  <span className="sr-only">{t('envs.colActions')}</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {env.variables.map((variable) => (
                <VariableRow
                  key={variable.name}
                  envId={summary.id}
                  modified={summary.modified}
                  variable={variable}
                  readOnly={inTrash}
                  onEdit={() => setOpen({ kind: 'variable', variable })}
                  onShare={() => setOpen({ kind: 'share', variable })}
                  onRemove={() => setRemoving(variable)}
                />
              ))}
            </tbody>
          </table>
        ) : null}
      </div>

      <Dialog open={open !== null} onOpenChange={(next) => (next ? undefined : setOpen(null))}>
        {open?.kind === 'variable' && env ? (
          <VariableDialog env={env} variable={open.variable} onDone={() => setOpen(null)} />
        ) : null}
        {open?.kind === 'share' && env ? (
          <ShareVariableDialog env={env} variable={open.variable} onDone={() => setOpen(null)} />
        ) : null}
        {open?.kind === 'export' ? (
          <ExportEnvDialog env={summary} onDone={() => setOpen(null)} />
        ) : null}
        {open?.kind === 'compare' ? (
          <CompareDialog env={summary} all={siblings} onDone={() => setOpen(null)} />
        ) : null}
        {open?.kind === 'renamePart' ? (
          <RenamePartDialog env={summary} all={all} onDone={() => setOpen(null)} />
        ) : null}
        {open?.kind === 'move' && env ? (
          <MoveEnvDialog env={env} all={all} onDone={() => setOpen(null)} />
        ) : null}
        {open?.kind === 'restore' ? (
          <RestoreEnvDialog env={summary} first={open.first} onDone={() => setOpen(null)} />
        ) : null}
        {open?.kind === 'send' ? (
          <SendDialog
            what={{ type: 'environment', envId: summary.id }}
            name={label}
            onStarted={() => setOpen(null)}
          />
        ) : null}
      </Dialog>

      <ConfirmDialog
        open={removing !== null}
        onOpenChange={(next) => (next ? undefined : setRemoving(null))}
        title={t('envs.removeVarTitle', { name: removing?.name ?? '' })}
        description={t('envs.removeVarText', { env: label })}
        confirmLabel={t('envs.removeVar')}
        destructive
        busy={removeVar.isPending}
        onConfirm={() => removing && removeVar.mutate(removing.name)}
      />
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={t('envs.deleteTitle', { name: label })}
        description={t('envs.deleteText')}
        confirmLabel={t('envs.deleteForever')}
        destructive
        busy={remove.isPending}
        onConfirm={() => remove.mutate(undefined)}
      />
    </section>
  );
}

interface VariableRowProps {
  envId: string;
  /** When the environment last changed: a shown value hides then. */
  modified: string | null;
  variable: EnvVarInfo;
  readOnly: boolean;
  onEdit: () => void;
  onShare: () => void;
  onRemove: () => void;
}

function VariableRow({
  envId,
  modified,
  variable,
  readOnly,
  onEdit,
  onShare,
  onRemove,
}: VariableRowProps) {
  const { t } = useTranslation();
  const shared = useSharedValues().data?.find((item) => item.id === variable.shared);
  const users = shared?.users.filter((use) => !use.inTrash).length ?? 1;
  const [revealed, setRevealed] = useState<string | null>(null);
  const reveal = useSecretCall(api.envsReveal);

  // A changed environment may have a new value; hide the old one.
  useEffect(() => {
    void modified;
    setRevealed(null);
  }, [modified]);

  useEffect(() => {
    if (revealed === null) return;
    const timer = window.setTimeout(() => setRevealed(null), REVEAL_MS);
    return () => window.clearTimeout(timer);
  }, [revealed]);

  const copy = useMutation({
    mutationFn: () => api.envsCopy(envId, variable.name),
    onSuccess: (result) => {
      toast.success(t('envs.copied', { name: variable.name }), {
        id: 'envs-copy',
        description:
          result.clearsInSecs !== null
            ? t('passwords.clearsIn', { seconds: result.clearsInSecs })
            : undefined,
      });
    },
    onError: (error) => toastVaultError(t, error),
  });

  const toggle = () => {
    if (revealed !== null) {
      setRevealed(null);
      return;
    }
    if (reveal.pending) return;
    reveal
      .call(envId, variable.name)
      .then(setRevealed)
      .catch((error: unknown) => toastVaultError(t, error));
  };

  return (
    <tr className="h-11 border-t border-white/[0.05] align-middle first:border-t-0 hover:bg-white/[0.03]">
      <td className="px-2.5 py-1">
        <span className="flex min-w-0 items-center gap-1.5">
          <span
            className="selectable truncate font-mono text-[12.5px] text-fg"
            title={variable.name}
          >
            {variable.name}
          </span>
          {variable.secret ? (
            <span title={t('envs.secretHint')} className="shrink-0 text-[var(--accent-text)]">
              <Lock aria-hidden="true" className="size-3.5" strokeWidth={2} />
              <span className="sr-only">{t('envs.secret')}</span>
            </span>
          ) : null}
          {variable.shared ? (
            <span
              title={t('envs.shared.badge', { count: users })}
              className="shrink-0 text-cyan-300"
            >
              <Link2 aria-hidden="true" className="size-3.5" strokeWidth={2} />
              <span className="sr-only">{t('envs.shared.badge', { count: users })}</span>
            </span>
          ) : null}
          {variable.unresolved ? (
            <span title={t('envs.shared.gone')} className="shrink-0 text-warning">
              <TriangleAlert aria-hidden="true" className="size-3.5" strokeWidth={2} />
              <span className="sr-only">{t('envs.shared.gone')}</span>
            </span>
          ) : null}
        </span>
      </td>
      <td className="px-2.5 py-1">
        <span className="flex min-w-0 items-center gap-0.5">
          {variable.empty ? (
            <span className="min-w-0 flex-1 text-[12.5px] text-subtle italic">
              {t('envs.emptyValue')}
            </span>
          ) : (
            <>
              <span
                className={cn(
                  'min-w-0 flex-1 font-mono',
                  revealed === null
                    ? 'truncate tracking-[0.1em] text-muted'
                    : 'selectable text-[12.5px] break-all whitespace-pre-wrap',
                )}
              >
                {revealed ?? (
                  <>
                    <span aria-hidden="true">{MASK}</span>
                    <span className="sr-only">{t('envs.hidden')}</span>
                  </>
                )}
              </span>
              <IconButton
                label={
                  revealed === null
                    ? t('envs.showValue', { name: variable.name })
                    : t('envs.hideValue', { name: variable.name })
                }
                icon={
                  revealed === null ? (
                    <Eye className="size-[15px]" strokeWidth={1.75} />
                  ) : (
                    <EyeOff className="size-[15px]" strokeWidth={1.75} />
                  )
                }
                onClick={toggle}
              />
              <IconButton
                label={t('envs.copyValue', { name: variable.name })}
                icon={<Copy className="size-[15px]" strokeWidth={1.75} />}
                onClick={() => {
                  if (!copy.isPending) copy.mutate();
                }}
              />
            </>
          )}
        </span>
      </td>
      <td
        className="truncate px-2.5 py-1 text-[12.5px] text-muted"
        title={variable.note || undefined}
      >
        {variable.note || <span className="text-subtle">{t('common.dash')}</span>}
      </td>
      <td className="px-1.5 py-1">
        <span className="flex justify-end gap-0.5">
          {readOnly ? null : (
            <>
              <IconButton
                label={t('envs.editVar', { name: variable.name })}
                icon={<Pencil className="size-[15px]" strokeWidth={1.75} />}
                onClick={onEdit}
              />
              <IconButton
                label={t('envs.shared.shareLabel', { name: variable.name })}
                icon={<Link2 className="size-[15px]" strokeWidth={1.75} />}
                onClick={onShare}
              />
              <IconButton
                label={t('envs.removeVarLabel', { name: variable.name })}
                icon={<Trash2 className="size-[15px]" strokeWidth={1.75} />}
                onClick={onRemove}
              />
            </>
          )}
        </span>
      </td>
    </tr>
  );
}
