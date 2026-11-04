import { KeyRound, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAgent, useKeys } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import type { AuthorizedKey } from '@/bindings/AuthorizedKey';
import type { KeyView } from '@/bindings/KeyView';
import type { ServerKeys } from '@/bindings/ServerKeys';
import type { ServerKeysAction } from '@/bindings/ServerKeysAction';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/components/ui/Menu';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { algorithmBadge } from '@/features/keys/model';
import { cn } from '@/lib/cn';
import { shortFingerprint } from '@/lib/format';
import { ErrorBox, Live, OkBox } from './Feedback';
import { LoginResult } from './LoginResult';
import type { MessageAction, RunContext } from './login';
import {
  addableKeys,
  entryName,
  entryTone,
  expiry,
  type OwnKeys,
  ownKeyName,
  removalLocksOut,
} from './serverKeys';
import { useUnlockFix } from './useUnlockFix';
import { vaultErrorMessage } from './vault';

interface ServerKeysDialogProps {
  alias: string;
  /** `user@host` the keys let in, as the editor shows it. */
  account: string;
  /** Sign in with what the vault saved: the host's password and 2FA code, key passphrases. */
  withVault: boolean;
  /** The vault has the host's password, so a removed key cannot lock the user out. */
  passwordSaved: boolean;
  /** The vault has the host's password but is locked. */
  vaultLocked: boolean;
  /** Fixes a failed sign-in offers (checking the host key, editing the password). */
  onAction: Partial<Record<MessageAction, () => void>>;
}

/** A run of `server_keys`, and how its result is named in messages. */
interface Run {
  action: ServerKeysAction;
  /** The key added or removed. */
  name: string;
}

/** What the last run did: a sentence, a failed sign-in, or a failure after signing in. */
type Outcome =
  | { kind: 'ok'; text: string }
  | { kind: 'login'; run: ServerKeys; context: RunContext }
  | { kind: 'error'; text: string; output?: string };

/**
 * Who may sign in to the host with a key: the lines of its
 * `~/.ssh/authorized_keys`. Adds one of the user's keys, or removes a key
 * after asking; each change and the fresh list come from one sign-in, since
 * a server may take a 2FA code only once.
 */
export function ServerKeysDialog({
  alias,
  account,
  withVault,
  passwordSaved,
  vaultLocked,
  onAction,
}: ServerKeysDialogProps) {
  const { t, i18n } = useTranslation();
  const dialogs = useDialogs();
  const keys = useKeys();
  const agent = useAgent();
  const own: OwnKeys = { keys: keys.data?.keys ?? [], agent: agent.data?.identities ?? [] };
  const listId = useId();

  /** The file as last read. */
  const [file, setFile] = useState<ServerKeys | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [confirm, setConfirm] = useState<AuthorizedKey | null>(null);
  // Removing a key takes its row, and the focus, away; it goes to "Add key"
  // once the confirmation has closed and given focus back.
  const add = useRef<HTMLDivElement>(null);
  const focusAdd = () =>
    requestAnimationFrame(() =>
      setTimeout(() => add.current?.querySelector<HTMLElement>('button')?.focus(), 0),
    );

  const run = useAppMutation(
    ({ action }: Run) =>
      withVault ? api.vaultServerKeys(alias, action) : api.serverKeys(alias, action),
    {
      onSuccess: (result, { action, name }) => {
        if (result.read) setFile(result);
        setOutcome(describe(result, action, name));
        if (action.type === 'remove') {
          setConfirm(null);
          if (result.changed) focusAdd();
        }
      },
      onError: (error) => {
        setOutcome({ kind: 'error', text: vaultErrorMessage(t, error) });
        setConfirm(null);
        return true;
      },
    },
  );
  const pending = run.isPending ? run.variables.action.type : null;

  function describe(result: ServerKeys, action: ServerKeysAction, name: string): Outcome | null {
    const values = { key: name, alias };
    if (!result.read) {
      const context: RunContext =
        action.type === 'add' ? 'install' : passwordSaved ? 'vaultTest' : 'test';
      return { kind: 'login', run: result, context };
    }
    switch (action.type) {
      case 'list':
        return null;
      case 'add':
        if (!result.ok) {
          return {
            kind: 'error',
            text: t('hosts.serverKeys.addFailed', values),
            output: result.output,
          };
        }
        return {
          kind: 'ok',
          text: t(result.changed ? 'hosts.serverKeys.added' : 'hosts.serverKeys.present', values),
        };
      case 'remove':
        if (!result.ok) {
          return {
            kind: 'error',
            text: t('hosts.serverKeys.removeFailed', values),
            output: result.output,
          };
        }
        return {
          kind: 'ok',
          text: t(result.changed ? 'hosts.serverKeys.removed' : 'hosts.serverKeys.gone', values),
        };
    }
  }

  const list = () => run.mutate({ action: { type: 'list' }, name: '' });
  const addKey = (key: KeyView) =>
    run.mutate({ action: { type: 'add', keyId: key.id }, name: key.name });
  const removeKey = (entry: AuthorizedKey) =>
    run.mutate({ action: { type: 'remove', publicKey: entry.publicKey }, name: entryName(entry) });

  // Once the key ssh could not open is unlocked, sign in again to read the file.
  const unlockFix = useUnlockFix(() => list());

  // Read the file once, when the dialog opens (Strict Mode runs effects twice).
  const listOnce = useRef(list);
  const started = useRef(false);
  useEffect(() => {
    if (started.current) return;
    started.current = true;
    listOnce.current();
  }, []);

  const entries = file?.file.keys ?? [];
  const addable = addableKeys(own.keys, entries);
  const confirmMine = confirm ? ownKeyName(confirm, own) : null;
  const day = (date: Date) =>
    new Intl.DateTimeFormat(i18n.language, {
      day: 'numeric',
      month: 'short',
      year: date.getFullYear() === new Date().getFullYear() ? undefined : 'numeric',
    }).format(date);

  return (
    <DialogContent section="hosts" className="max-w-[580px]">
      <DialogHeader
        icon={
          <Tile tone="blue" size={44} glow>
            <KeyRound className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('hosts.serverKeys.title', { alias })}
        description={t('hosts.serverKeys.description', { account })}
      />
      <DialogBody>
        <Live>
          {file === null && pending === 'list' ? (
            <p className="flex items-center justify-center gap-2.5 py-8 text-[13px] text-subtle">
              <Spinner className="size-4" />
              {t('hosts.serverKeys.loading', { alias })}
            </p>
          ) : null}
          {outcome?.kind === 'ok' ? <OkBox>{outcome.text}</OkBox> : null}
          {outcome?.kind === 'login' ? (
            <LoginResult
              run={outcome.run}
              context={outcome.context}
              alias={alias}
              vaultLocked={vaultLocked}
              onAction={{ ...onAction, ...unlockFix(outcome.run) }}
            />
          ) : null}
          {outcome?.kind === 'error' ? (
            <ErrorBox>
              <span className="flex min-w-0 flex-col gap-1">
                {outcome.text}
                {outcome.output ? (
                  <span className="selectable font-mono text-[11.5px] leading-[17px] whitespace-pre-wrap text-fg-2">
                    {outcome.output}
                  </span>
                ) : null}
              </span>
            </ErrorBox>
          ) : null}
        </Live>

        {file === null ? null : entries.length === 0 ? (
          <EmptyState
            icon={
              <Tile tone="slate" size={36}>
                <KeyRound className="size-[17px]" strokeWidth={2} />
              </Tile>
            }
            title={t('hosts.serverKeys.emptyTitle')}
            description={t('hosts.serverKeys.emptyText', { account })}
          />
        ) : (
          <ul
            aria-label={t('hosts.serverKeys.listLabel', { alias })}
            className="glass flex max-h-[320px] flex-col gap-0.5 overflow-y-auto rounded-[14px] p-1.5"
          >
            {entries.map((entry) => {
              const mine = ownKeyName(entry, own);
              const until = expiry(entry);
              const name = entryName(entry);
              const locksOut = removalLocksOut(entry, entries, own, passwordSaved);
              return (
                <li key={entry.line} className="flex items-start gap-[11px] px-2.5 py-2">
                  <Tile tone={entryTone(entry)} size={30} className="mt-0.5">
                    <KeyRound className="size-[15px]" strokeWidth={2.25} />
                  </Tile>
                  <div className="flex min-w-0 flex-1 flex-col gap-1">
                    <span
                      title={entry.comment || undefined}
                      className={cn(
                        'truncate text-[13px] font-medium',
                        entry.comment ? 'font-mono' : 'text-subtle italic',
                      )}
                    >
                      {entry.comment || t('hosts.serverKeys.noComment')}
                    </span>
                    <span className="flex flex-wrap items-center gap-1.5">
                      <Badge mono>{algorithmBadge(entry)}</Badge>
                      {mine ? (
                        <Badge tone="accent">{t('hosts.serverKeys.thisComputer')}</Badge>
                      ) : null}
                      {until ? (
                        <Badge tone={until.expired ? 'critical' : 'warning'}>
                          {t(
                            until.expired ? 'hosts.serverKeys.expired' : 'hosts.serverKeys.expires',
                            {
                              date: day(until.date),
                            },
                          )}
                        </Badge>
                      ) : null}
                      {entry.certAuthority ? (
                        <Badge tone="info">{t('hosts.serverKeys.certAuthority')}</Badge>
                      ) : null}
                      {entry.options.length > 0 ? (
                        <Badge>{t('hosts.serverKeys.restricted')}</Badge>
                      ) : null}
                    </span>
                    <span
                      title={entry.fingerprint}
                      className="truncate font-mono text-[11.5px] text-subtle"
                    >
                      {mine ? `${mine} · ` : ''}
                      {shortFingerprint(entry.fingerprint)}
                    </span>
                    {entry.options.length > 0 ? (
                      <span
                        title={entry.options.join(', ')}
                        className="truncate font-mono text-[11.5px] text-subtle"
                      >
                        {entry.options.join(', ')}
                      </span>
                    ) : null}
                  </div>
                  <IconButton
                    label={t('hosts.serverKeys.remove', { key: name })}
                    tooltip={locksOut ? t('hosts.serverKeys.removeBlocked', { alias }) : undefined}
                    icon={<Trash2 className="size-[15px]" strokeWidth={1.9} />}
                    className="aria-disabled:opacity-40"
                    aria-disabled={locksOut || pending !== null || undefined}
                    aria-describedby={locksOut ? `${listId}-${entry.line}` : undefined}
                    onClick={() => locksOut || pending !== null || setConfirm(entry)}
                  />
                  {locksOut ? (
                    <span id={`${listId}-${entry.line}`} className="sr-only">
                      {t('hosts.serverKeys.removeBlocked', { alias })}
                    </span>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
        {file && file.file.invalid.length > 0 ? (
          <p className="-mt-2 text-[12px] leading-[18px] text-subtle">
            {t('hosts.serverKeys.invalid', { count: file.file.invalid.length })}
          </p>
        ) : null}
      </DialogBody>
      <DialogFooter>
        <Button
          variant="ghost"
          size="lg"
          className="mr-auto"
          icon={
            pending === 'list' ? (
              <Spinner className="size-4" />
            ) : (
              <RefreshCw aria-hidden="true" className="size-4" strokeWidth={2} />
            )
          }
          disabled={pending !== null}
          onClick={list}
        >
          {t('common.refresh')}
        </Button>
        <Menu>
          <div ref={add} className="contents">
            <MenuTrigger asChild disabled={file === null || pending !== null}>
              <Button
                variant="primary"
                size="lg"
                loading={pending === 'add'}
                icon={<Plus aria-hidden="true" className="size-4" strokeWidth={2.25} />}
              >
                {t('hosts.serverKeys.add')}
              </Button>
            </MenuTrigger>
          </div>
          <MenuContent>
            {addable.map((key) => (
              <MenuItem
                key={key.id}
                icon={<KeyRound className="size-[15px]" strokeWidth={1.9} />}
                onSelect={() => addKey(key)}
              >
                <span className="font-mono">{key.name}</span>
              </MenuItem>
            ))}
            {addable.length > 0 ? <MenuSeparator /> : null}
            <MenuItem
              icon={<Plus className="size-[15px]" strokeWidth={1.9} />}
              onSelect={() => dialogs.generateKeyFor(addKey)}
            >
              {t('hosts.serverKeys.newKey')}
            </MenuItem>
          </MenuContent>
        </Menu>
      </DialogFooter>

      <ConfirmDialog
        open={confirm !== null}
        onOpenChange={(open) => open || run.isPending || setConfirm(null)}
        title={t('hosts.serverKeys.removeTitle', {
          key: confirm ? entryName(confirm) : '',
          alias,
        })}
        description={
          confirmMine
            ? t('hosts.serverKeys.removeOwnText', { key: confirmMine, account })
            : t('hosts.serverKeys.removeText', { account })
        }
        confirmLabel={t('hosts.serverKeys.removeConfirm')}
        destructive
        alert={confirmMine !== null}
        busy={pending === 'remove'}
        onConfirm={() => confirm && removeKey(confirm)}
      />
    </DialogContent>
  );
}
