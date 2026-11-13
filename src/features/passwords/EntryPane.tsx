import { useMutation } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import {
  Copy,
  ExternalLink,
  Eye,
  EyeOff,
  KeyRound,
  MoreHorizontal,
  Pencil,
  Send,
  Server,
  Trash2,
  Undo2,
} from 'lucide-react';
import { type ComponentProps, type ReactNode, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll, useConfig, useKeys } from '@/api/queries';
import { useRouter } from '@/app/router';
import type { CopyField } from '@/bindings/CopyField';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { ProjectMember } from '@/bindings/ProjectMember';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/components/ui/Menu';
import { Popover, PopoverTrigger } from '@/components/ui/Popover';
import { Tile, TONES } from '@/components/ui/Tile';
import { HostPreview } from '@/features/hosts/HostPreview';
import { KeyPreview } from '@/features/keys/KeyPreview';
import { SendDialog } from '@/features/nearby/SendDialog';
import { ProjectChips, useProjectMenu } from '@/features/projects/ProjectMenu';
import { cn } from '@/lib/cn';
import { formatDate, formatRelative, shortFingerprint } from '@/lib/format';
import { avatar, openableUrl } from './model';
import { OtpCode } from './OtpCode';
import { MASK, REVEAL_MS } from './SavedSecret';
import { toastVaultError, useSecretCall, useVaultEntry, useVaultMutation } from './vault';

const COPIED = {
  username: 'passwords.copiedUsername',
  password: 'passwords.copiedPassword',
  url: 'passwords.copiedUrl',
  otp: 'passwords.copiedOtp',
} as const;

const KIND_LABEL = {
  login: 'passwords.kindLogin',
  host: 'passwords.kindHost',
  key: 'passwords.kindKey',
} as const;

interface EntryPaneProps {
  entry: EntrySummary;
  onEdit: (detail: EntryDetail) => void;
  /** The entry left the current list (trashed, restored or deleted). */
  onGone: () => void;
}

/**
 * The selected entry. Mounted per entry (keyed by id), so a revealed password
 * never outlives a switch to another entry; locking unmounts it too.
 */
export function EntryPane({ entry, onEdit, onGone }: EntryPaneProps) {
  const { t, i18n } = useTranslation();
  const projectMember: ProjectMember | null = entry.inTrash
    ? null
    : { type: 'login', id: entry.id };
  const projectMenu = useProjectMenu(projectMember);
  const { navigate } = useRouter();
  const detail = useVaultEntry(entry.id);
  const config = useConfig();
  const keys = useKeys();
  const [revealed, setRevealed] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [sending, setSending] = useState(false);
  const mark = avatar(entry.title);
  const href = openableUrl(entry.url);
  const passwordLabel = entry.kind === 'key' ? t('passwords.passphrase') : t('passwords.password');

  // A changed entry may have a new password; hide the old one.
  useEffect(() => {
    void entry.modified;
    setRevealed(null);
  }, [entry.modified]);

  useEffect(() => {
    if (revealed === null) return;
    const timer = window.setTimeout(() => setRevealed(null), REVEAL_MS);
    return () => window.clearTimeout(timer);
  }, [revealed]);

  const copy = useMutation({
    mutationFn: (field: CopyField) => api.vaultCopy(entry.id, field),
    onSuccess: (result, field) => {
      toast.success(t(COPIED[field]), {
        id: 'vault-copy',
        description:
          result.clearsInSecs !== null
            ? t('passwords.clearsIn', { seconds: result.clearsInSecs })
            : undefined,
      });
    },
    onError: (error) => toastVaultError(t, error),
  });

  const reveal = useSecretCall(api.vaultReveal);
  const show = () => {
    if (reveal.pending) return;
    reveal
      .call(entry.id, 'password')
      .then(setRevealed)
      .catch((error: unknown) => toastVaultError(t, error));
  };

  const restore = useVaultMutation(() => api.vaultRestore(entry.id), {
    success: () => t('passwords.restored', { name: entry.title }),
    onSuccess: onGone,
  });
  const trash = useVaultMutation(() => api.vaultTrash(entry.id), {
    onSuccess: () => {
      onGone();
      const { id, title } = entry;
      // The pane is gone by the time Undo is clicked, so call the command directly.
      const undo = async () => {
        try {
          await api.vaultRestore(id);
          await invalidateAll();
          navigate({ page: 'passwords', entryId: id });
          toast.success(t('passwords.restored', { name: title }));
        } catch (error) {
          toastVaultError(t, error);
        }
      };
      toast.success(t('passwords.movedToTrash', { name: title }), {
        duration: 8_000,
        action: { label: t('passwords.restore'), onClick: () => void undo() },
        classNames: {
          actionButton:
            '!h-7 !rounded-lg !border !border-ink/15 !bg-ink/10 !px-2.5 !text-[12.5px] !font-medium !text-fg hover:!bg-ink/15',
        },
      });
    },
  });
  const remove = useVaultMutation(() => api.vaultDelete(entry.id), {
    success: () => t('passwords.deleted', { name: entry.title }),
    onSuccess: () => {
      setConfirmDelete(false);
      onGone();
    },
  });

  const open = async () => {
    if (!href) return;
    try {
      if (isTauri()) await openUrl(href);
      else window.open(href, '_blank', 'noopener,noreferrer');
    } catch (error) {
      toastVaultError(t, error);
    }
  };

  const linkedHost = entry.host
    ? (config.data?.view.hosts.find(
        (host) => host.kind === 'host' && host.patterns.includes(entry.host ?? ''),
      ) ?? null)
    : null;
  const linkedKey = entry.keyFingerprint
    ? (keys.data?.keys.find((key) => key.fingerprint === entry.keyFingerprint) ?? null)
    : null;
  const data = detail.data;
  // Buttons stay enabled while copying, so keyboard focus never drops to the page.
  const copyField = (field: CopyField) => {
    if (!copy.isPending) copy.mutate(field);
  };
  const copyButton = (field: CopyField, label: string) => (
    <IconButton
      label={label}
      icon={<Copy className="size-[15px]" strokeWidth={1.75} />}
      onClick={() => copyField(field)}
    />
  );

  return (
    <aside
      aria-label={t('passwords.detailLabel')}
      className="glass-raised relative flex w-[340px] shrink-0 flex-col overflow-hidden rounded-2xl xl:w-[380px]"
    >
      <div
        aria-hidden="true"
        className="pointer-events-none absolute -top-[90px] -left-10 h-[220px] w-[300px] rounded-full opacity-45 blur-[50px]"
        style={{ background: TONES[mark.tone][1] }}
      />
      <div className="relative flex flex-col gap-3.5 border-b border-ink/[0.07] px-5 pt-5 pb-4">
        <div className="flex items-start gap-3">
          <Tile tone={mark.tone} size={48}>
            <span className="text-[20px] font-semibold">{mark.letter}</span>
          </Tile>
          <div className="min-w-0 flex-1">
            <h2 className="selectable truncate text-[16px] leading-6 font-semibold">
              {entry.title}
            </h2>
            <p className="flex items-center gap-1.5 text-[12.5px] text-muted">
              <span>{t(KIND_LABEL[entry.kind])}</span>
              {entry.inTrash ? (
                <Badge tone="warning" pill>
                  {t('passwords.inTrash')}
                </Badge>
              ) : null}
            </p>
            <ProjectChips member={projectMember} className="mt-1.5" />
          </div>
          <Menu>
            <MenuTrigger asChild>
              <IconButton
                label={t('passwords.moreActions')}
                variant="secondary"
                size="md"
                icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
              />
            </MenuTrigger>
            <MenuContent>
              {!entry.inTrash && data ? (
                <MenuItem icon={<Pencil className="size-4" />} onSelect={() => onEdit(data)}>
                  {t('passwords.edit')}
                </MenuItem>
              ) : null}
              {entry.username ? (
                <MenuItem icon={<Copy className="size-4" />} onSelect={() => copyField('username')}>
                  {t('passwords.copyUsername')}
                </MenuItem>
              ) : null}
              {entry.url ? (
                <MenuItem icon={<Copy className="size-4" />} onSelect={() => copyField('url')}>
                  {t('passwords.copyUrl')}
                </MenuItem>
              ) : null}
              {projectMenu.sub}
              <MenuSeparator />
              {entry.inTrash ? (
                <>
                  <MenuItem
                    icon={<Undo2 className="size-4" />}
                    onSelect={() => restore.mutate(undefined)}
                  >
                    {t('passwords.restore')}
                  </MenuItem>
                  <MenuItem
                    destructive
                    icon={<Trash2 className="size-4" />}
                    onSelect={() => setConfirmDelete(true)}
                  >
                    {t('passwords.deleteForever')}
                  </MenuItem>
                </>
              ) : (
                <MenuItem
                  destructive
                  icon={<Trash2 className="size-4" />}
                  onSelect={() => trash.mutate(undefined)}
                >
                  {t('passwords.moveToTrash')}
                </MenuItem>
              )}
            </MenuContent>
          </Menu>
          {projectMenu.dialog}
        </div>
        <div className="flex flex-wrap gap-2">
          {entry.inTrash ? (
            <Button
              variant="primary"
              icon={<Undo2 className="size-[15px]" strokeWidth={2} />}
              loading={restore.isPending}
              onClick={() => restore.mutate(undefined)}
            >
              {t('passwords.restore')}
            </Button>
          ) : (
            <>
              {entry.hasPassword ? (
                <Button
                  variant="primary"
                  icon={<Copy className="size-[15px]" strokeWidth={2} />}
                  onClick={() => copyField('password')}
                >
                  {t('passwords.copyPassword')}
                </Button>
              ) : null}
              <Button
                icon={<Pencil className="size-[15px]" strokeWidth={1.9} />}
                disabled={!data}
                onClick={() => data && onEdit(data)}
              >
                {t('passwords.edit')}
              </Button>
              {entry.kind !== 'key' ? (
                <Button
                  icon={<Send className="size-[15px]" strokeWidth={1.9} />}
                  onClick={() => setSending(true)}
                >
                  {t('passwords.send')}
                </Button>
              ) : null}
            </>
          )}
        </div>
      </div>

      <div className="relative flex min-h-0 flex-1 flex-col gap-[18px] overflow-y-auto px-5 pt-4 pb-[18px]">
        <div className="glass flex flex-col divide-y divide-line-soft rounded-xl">
          {entry.username ? (
            <Field label={t('passwords.username')}>
              <span className="selectable min-w-0 flex-1 truncate">{entry.username}</span>
              {copyButton('username', t('passwords.copyUsername'))}
            </Field>
          ) : null}

          <Field label={passwordLabel}>
            {entry.hasPassword ? (
              <>
                <span
                  className={cn(
                    'min-w-0 flex-1 font-mono',
                    revealed === null
                      ? 'truncate tracking-[0.1em] text-muted'
                      : 'selectable text-[12.5px] break-all',
                  )}
                >
                  {revealed ?? (
                    <>
                      <span aria-hidden="true">{MASK}</span>
                      <span className="sr-only">{t('passwords.hidden')}</span>
                    </>
                  )}
                </span>
                <IconButton
                  label={
                    revealed === null ? t('passwords.showPassword') : t('passwords.hidePassword')
                  }
                  icon={
                    revealed === null ? (
                      <Eye className="size-[15px]" strokeWidth={1.75} />
                    ) : (
                      <EyeOff className="size-[15px]" strokeWidth={1.75} />
                    )
                  }
                  onClick={() => {
                    if (revealed !== null) setRevealed(null);
                    else show();
                  }}
                />
                {copyButton('password', t('passwords.copyPassword'))}
              </>
            ) : (
              <span className="text-subtle">{t('passwords.noPassword')}</span>
            )}
          </Field>

          {entry.url ? (
            <Field label={t('passwords.website')}>
              <span className="selectable min-w-0 flex-1 truncate">{entry.url}</span>
              {href ? (
                <IconButton
                  label={t('passwords.openWebsite')}
                  icon={<ExternalLink className="size-[15px]" strokeWidth={1.75} />}
                  onClick={() => void open()}
                />
              ) : null}
              {copyButton('url', t('passwords.copyUrl'))}
            </Field>
          ) : null}

          {entry.hasOtp ? (
            <Field label={t('passwords.otp')}>
              <span className="min-w-0 flex-1">
                <OtpCode entryId={entry.id} />
              </span>
              {copyButton('otp', t('passwords.copyOtp'))}
            </Field>
          ) : null}

          {entry.kind === 'host' && entry.host ? (
            <Field label={t('passwords.linkedHost')}>
              <span className="flex min-w-0 flex-1 items-center gap-2">
                {linkedHost ? (
                  <Popover>
                    <PopoverTrigger asChild>
                      <LinkChip tone="blue" icon={<Server className="size-3" strokeWidth={2.2} />}>
                        {entry.host}
                      </LinkChip>
                    </PopoverTrigger>
                    <HostPreview host={linkedHost} />
                  </Popover>
                ) : (
                  <>
                    <span className="truncate font-mono text-[12.5px]">{entry.host}</span>
                    <span className="truncate text-[12px] text-warning">
                      {t('passwords.hostNotFound')}
                    </span>
                  </>
                )}
              </span>
            </Field>
          ) : null}

          {entry.kind === 'key' && entry.keyFingerprint ? (
            <Field label={t('passwords.linkedKey')}>
              <span className="flex min-w-0 flex-1 flex-col items-start gap-1">
                {linkedKey ? (
                  <Popover>
                    <PopoverTrigger asChild>
                      <LinkChip
                        tone="teal"
                        icon={<KeyRound className="size-3" strokeWidth={2.2} />}
                      >
                        {linkedKey.name}
                      </LinkChip>
                    </PopoverTrigger>
                    <KeyPreview keyView={linkedKey} />
                  </Popover>
                ) : (
                  <span className="text-[12px] text-warning">{t('passwords.keyNotFound')}</span>
                )}
                <span className="selectable font-mono text-[11.5px] text-subtle">
                  {shortFingerprint(entry.keyFingerprint)}
                </span>
              </span>
            </Field>
          ) : null}
        </div>

        {data?.notes ? (
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[11.5px] leading-4 font-semibold tracking-[0.02em] text-subtle">
              {t('passwords.notes')}
            </h3>
            <p className="selectable rounded-[10px] border border-line-soft bg-shade/25 px-3 py-2.5 text-[12.5px] leading-[18px] whitespace-pre-wrap text-fg-2 [overflow-wrap:anywhere]">
              {data.notes}
            </p>
          </section>
        ) : null}

        <dl className="grid grid-cols-[minmax(96px,auto)_minmax(0,1fr)] gap-x-3 gap-y-2 text-[12.5px]">
          <dt className="text-subtle">{t('passwords.modified')}</dt>
          <dd>{formatDate(entry.modified, i18n.language)}</dd>
          {entry.hasPassword && data?.passwordChanged ? (
            <>
              <dt className="text-subtle">{t('passwords.passwordChanged')}</dt>
              <dd>{formatRelative(new Date(data.passwordChanged), i18n.language)}</dd>
            </>
          ) : null}
          {data ? (
            <>
              <dt className="text-subtle">{t('passwords.history')}</dt>
              <dd>{t('passwords.history', { count: data.historyLen })}</dd>
            </>
          ) : null}
          <dt className="text-subtle">{t('passwords.created')}</dt>
          <dd>{formatDate(entry.created, i18n.language)}</dd>
          {entry.group && !entry.inTrash ? (
            <>
              <dt className="text-subtle">{t('passwords.folder')}</dt>
              <dd className="selectable truncate">{entry.group}</dd>
            </>
          ) : null}
        </dl>
      </div>

      <div className="relative flex flex-wrap items-center gap-2 border-t border-ink/[0.07] px-3.5 py-2.5">
        {entry.inTrash ? (
          <Button
            variant="danger"
            size="sm"
            className="ml-auto"
            icon={<Trash2 className="size-[15px]" strokeWidth={1.75} />}
            onClick={() => setConfirmDelete(true)}
          >
            {t('passwords.deleteForever')}
          </Button>
        ) : (
          <Button
            variant="danger"
            size="sm"
            className="ml-auto"
            loading={trash.isPending}
            icon={<Trash2 className="size-[15px]" strokeWidth={1.75} />}
            onClick={() => trash.mutate(undefined)}
          >
            {t('passwords.moveToTrash')}
          </Button>
        )}
      </div>

      <Dialog open={sending} onOpenChange={setSending}>
        {sending ? (
          <SendDialog
            what={{ type: 'password', entryId: entry.id, hasOtp: entry.hasOtp }}
            name={entry.title}
            onStarted={() => setSending(false)}
          />
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={confirmDelete}
        onOpenChange={setConfirmDelete}
        title={t('passwords.deleteTitle', { name: entry.title })}
        description={t('passwords.deleteText')}
        confirmLabel={t('passwords.deleteForever')}
        destructive
        busy={remove.isPending}
        onConfirm={() => remove.mutate(undefined)}
      />
    </aside>
  );
}

/** A label, then the value and its buttons; read in that order. */
function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex min-h-[54px] flex-col justify-center gap-0.5 py-2 pr-1.5 pl-3">
      <span className="text-[11.5px] leading-4 font-medium text-subtle">{label}</span>
      <div className="flex min-h-[30px] items-center gap-1">{children}</div>
    </div>
  );
}

interface LinkChipProps extends ComponentProps<'button'> {
  tone: 'blue' | 'teal';
  icon: ReactNode;
}

/**
 * A linked host or key, styled like the "Used by" host chips on Keys; a
 * `PopoverTrigger` for its preview.
 */
function LinkChip({ tone, icon, children, className, ...rest }: LinkChipProps) {
  return (
    <button
      type="button"
      {...rest}
      // Hosts' colour or keys', from their sections.
      data-section={tone === 'blue' ? 'hosts' : 'keys'}
      className={cn(
        'pressable inline-flex h-[24px] max-w-full items-center gap-1.5 rounded-md border px-2 font-mono text-[12px]',
        'border-[rgb(var(--accent-rgb)/0.3)] bg-[rgb(var(--accent-rgb)/0.12)] text-[var(--accent-text)] hover:bg-[rgb(var(--accent-rgb)/0.2)] data-[state=open]:bg-[rgb(var(--accent-rgb)/0.2)]',
        className,
      )}
    >
      {icon}
      <span className="truncate">{children}</span>
    </button>
  );
}
