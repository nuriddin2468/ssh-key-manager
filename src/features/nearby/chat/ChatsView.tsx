import { Laptop, Lock, MessagesSquare, MoreHorizontal, Trash2 } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { ChatSummary } from '@/bindings/ChatSummary';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/components/ui/Menu';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { formatRelative } from '@/lib/format';
import { AddVariablesDialog } from './AddVariablesDialog';
import { Bubble } from './Bubble';
import { Composer, type ComposerDialog } from './Composer';
import { ItemPickerDialog } from './ItemPickerDialog';
import { byDay, useChatAction } from './model';
import { useChatHistory, useChatList } from './queries';
import { SecretDialog } from './SecretDialog';
import { VariablesDialog } from './VariablesDialog';

/** The id of the Chats tab's panel. */
export const CHATS_PANEL = 'nearby-panel-chats';

/** Chats: the list of computers on the left, the conversation on the right. */
export function ChatsView({ chat }: { chat: string | undefined }) {
  const { t } = useTranslation();
  const dialogs = useDialogs();
  const vault = useVaultStatus().data?.state;
  const list = useChatList();
  const { navigate } = useRouter();
  if (vault !== undefined && vault !== 'unlocked') {
    return (
      <EmptyState
        className="my-auto"
        icon={<Lock className="size-6" strokeWidth={2} />}
        title={t('nearby.chat.vaultLocked')}
        action={
          vault === 'locked' ? (
            <Button
              variant="primary"
              onClick={() => dialogs.unlockVault({ description: t('nearby.chat.vaultLocked') })}
            >
              {t('passwords.unlock')}
            </Button>
          ) : null
        }
      />
    );
  }
  if (!list.data) {
    return (
      <div className="grid flex-1 place-items-center text-subtle">
        <Spinner className="size-6" />
      </div>
    );
  }
  const chats = list.data.chats;
  if (chats.length === 0) {
    return (
      <EmptyState
        className="my-auto"
        icon={<MessagesSquare className="size-6" strokeWidth={2} />}
        title={t('nearby.chat.noOne')}
      />
    );
  }
  const open = chats.find((item) => item.key === chat);
  return (
    <div className="flex min-h-0 flex-1 gap-4">
      <ChatList
        chats={chats}
        open={open?.key}
        onOpen={(key) => navigate({ page: 'nearby', tab: 'chats', chat: key })}
      />
      <section
        aria-label={open ? t('nearby.chat.menu', { name: open.name }) : undefined}
        className="glass-raised relative flex min-w-0 flex-1 flex-col overflow-hidden rounded-2xl"
      >
        {open ? (
          <Conversation key={open.key} peer={open} />
        ) : (
          <EmptyState
            className="my-auto"
            icon={<MessagesSquare className="size-6" strokeWidth={2} />}
            title={t('nearby.chat.noneOpen')}
          />
        )}
      </section>
    </div>
  );
}

function ChatList({
  chats,
  open,
  onOpen,
}: {
  chats: ChatSummary[];
  open: string | undefined;
  onOpen: (key: string) => void;
}) {
  const { t } = useTranslation();
  const sections = [
    { title: t('nearby.chat.myDevices'), items: chats.filter((item) => item.own) },
    { title: t('nearby.chat.paired'), items: chats.filter((item) => !item.own) },
  ].filter((section) => section.items.length > 0);
  return (
    <nav
      aria-label={t('nearby.chat.list')}
      className="glass flex w-[280px] shrink-0 flex-col overflow-hidden rounded-2xl xl:w-[300px]"
    >
      <div className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-2">
        {sections.map((section) => (
          <div key={section.title} className="flex flex-col gap-0.5">
            <h2 className="flex min-h-7 items-center gap-2 px-2.5 pt-1 pb-1 text-[12.5px] font-semibold">
              {section.title}
              <span aria-hidden="true" className="text-[12px] font-normal text-subtle tabular-nums">
                {section.items.length}
              </span>
            </h2>
            <ul className="flex flex-col gap-0.5">
              {section.items.map((item) => (
                <li key={item.key}>
                  <ChatRow item={item} open={item.key === open} onOpen={() => onOpen(item.key)} />
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </nav>
  );
}

/** What the list says for the last entry, when it isn't a text. */
const LAST = {
  secret: 'nearby.chat.lastSecret',
  variables: 'nearby.chat.lastVariables',
  card: 'nearby.chat.lastCard',
  line: 'nearby.chat.lastLine',
} as const;

function ChatRow({ item, open, onOpen }: { item: ChatSummary; open: boolean; onOpen: () => void }) {
  const { t, i18n } = useTranslation();
  const last = item.last;
  const preview = last
    ? last.kind === 'text'
      ? last.mine
        ? t('nearby.chat.you', { text: last.text ?? '' })
        : (last.text ?? '')
      : t(LAST[last.kind as keyof typeof LAST] ?? LAST.card)
    : '';
  const presence = item.online ? t('nearby.chat.online') : t('nearby.chat.offline');
  return (
    <button
      type="button"
      aria-current={open ? 'true' : undefined}
      onClick={onOpen}
      className={cn(
        'pressable-soft flex min-h-[52px] w-full items-center gap-2.5 rounded-xl px-2.5 py-1.5 text-left',
        open ? 'selected-row' : 'hover:bg-ink/[0.04]',
      )}
    >
      <span className="relative shrink-0">
        <Tile tone={item.own ? 'orange' : 'slate'} size={30}>
          <Laptop className="size-[15px]" strokeWidth={2} />
        </Tile>
        {item.online ? (
          <span
            aria-hidden="true"
            className="absolute -right-0.5 -bottom-0.5 size-2.5 rounded-full border-2 border-surface bg-online"
          />
        ) : null}
      </span>
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="flex items-center gap-2">
          <span
            className={cn(
              'min-w-0 flex-1 truncate text-[13px]',
              item.unread > 0 ? 'font-semibold' : 'font-medium',
            )}
          >
            {item.name}
          </span>
          {last ? (
            <time dateTime={last.at} className="shrink-0 text-[11px] text-subtle">
              {formatRelative(new Date(last.at), i18n.language)}
            </time>
          ) : null}
        </span>
        <span className="flex items-center gap-2">
          <span className="min-w-0 flex-1 truncate text-[12.5px] text-muted">
            <span className={item.online ? 'text-online' : 'text-subtle'}>{presence}</span>
            {preview ? ` · ${preview}` : ''}
          </span>
          {item.unread > 0 ? (
            <>
              <span
                aria-hidden="true"
                className="grid h-4 min-w-4 place-items-center rounded-full bg-[rgb(var(--accent-rgb)/0.2)] px-1 text-[10.5px] font-semibold text-[var(--accent-text)] tabular-nums"
              >
                {item.unread}
              </span>
              <span className="sr-only">{t('nearby.chat.unread', { count: item.unread })}</span>
            </>
          ) : null}
        </span>
      </span>
    </button>
  );
}

type Open = ComposerDialog | { add: string } | null;

function Conversation({ peer }: { peer: ChatSummary }) {
  const { t, i18n } = useTranslation();
  const history = useChatHistory(peer.key);
  const [dialog, setDialog] = useState<Open>(null);
  const [deleting, setDeleting] = useState(false);
  const remove = useChatAction(
    () => api.chatDelete(peer.key),
    () => {
      setDeleting(false);
      toast.success(t('nearby.chat.deleted'));
    },
  );
  const entries = history.data ?? [];

  // What is shown is read; the newest stays in view.
  const count = entries.length;
  // biome-ignore lint/correctness/useExhaustiveDependencies: on new entries only
  useEffect(() => {
    if (peer.unread > 0) void api.chatMarkRead(peer.key).catch(() => undefined);
    const stream = document.getElementById(`chat-stream-${peer.key}`);
    stream?.scrollTo({ top: stream.scrollHeight });
  }, [count, peer.key]);

  const close = () => setDialog(null);
  return (
    <>
      <header className="flex items-center gap-3 border-b border-line-soft px-4 py-3">
        <Tile tone={peer.own ? 'orange' : 'slate'} size={32}>
          <Laptop className="size-4" strokeWidth={2} />
        </Tile>
        <div className="flex min-w-0 flex-1 flex-col">
          <h2 className="truncate text-[14px] leading-5 font-semibold">{peer.name}</h2>
          <span
            title={t('nearby.chat.onlineHint')}
            className={cn('text-[12px]', peer.online ? 'text-online' : 'text-subtle')}
          >
            {peer.online ? t('nearby.chat.online') : t('nearby.chat.offline')}
          </span>
        </div>
        <Menu>
          <MenuTrigger asChild>
            <IconButton
              variant="ghost"
              label={t('nearby.chat.menu', { name: peer.name })}
              icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
            />
          </MenuTrigger>
          <MenuContent align="end">
            <MenuItem
              destructive
              icon={<Trash2 className="size-4" strokeWidth={2} />}
              onSelect={() => setDeleting(true)}
            >
              {t('nearby.chat.delete')}
            </MenuItem>
          </MenuContent>
        </Menu>
      </header>

      <div
        id={`chat-stream-${peer.key}`}
        role="log"
        aria-live="polite"
        aria-label={t('nearby.chat.menu', { name: peer.name })}
        className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto px-4 py-4"
      >
        {entries.length === 0 ? (
          <p className="my-auto max-w-[360px] self-center text-center text-[12.5px] leading-[18px] text-subtle">
            {t('nearby.chat.empty', { name: peer.name })}
          </p>
        ) : (
          byDay(entries).map((day) => (
            <div key={day.day} className="flex flex-col gap-1.5">
              <p className="self-center py-1 text-[12px] text-subtle">
                {new Date(`${day.day}T12:00:00Z`).toLocaleDateString(i18n.language, {
                  day: 'numeric',
                  month: 'long',
                })}
              </p>
              {day.entries.map((entry) => (
                <Bubble
                  key={entry.id}
                  peer={peer}
                  entry={entry}
                  onAddVariables={(id) => setDialog({ add: id })}
                />
              ))}
            </div>
          ))
        )}
      </div>

      <Composer peer={peer} onOpen={setDialog} />

      <Dialog open={dialog !== null} onOpenChange={(next) => (next ? undefined : close())}>
        {dialog === 'secret' ? (
          <SecretDialog peer={peer} onDone={close} />
        ) : dialog === 'variables' ? (
          <VariablesDialog peer={peer} onDone={close} />
        ) : dialog && typeof dialog === 'object' ? (
          <AddVariablesDialog peer={peer} id={dialog.add} onDone={close} />
        ) : dialog ? (
          <ItemPickerDialog peer={peer} kind={dialog} onDone={close} />
        ) : null}
      </Dialog>

      <ConfirmDialog
        open={deleting}
        onOpenChange={setDeleting}
        title={t('nearby.chat.deleteTitle', { name: peer.name })}
        description={t('nearby.chat.deleteText', { name: peer.name })}
        confirmLabel={t('nearby.chat.deleteConfirm')}
        destructive
        busy={remove.isPending}
        onConfirm={() => remove.mutate(undefined)}
      />
    </>
  );
}
