import {
  FileKey,
  FolderTree,
  KeyRound,
  Plus,
  RectangleEllipsis,
  SendHorizontal,
  Server,
  Variable,
} from 'lucide-react';
import { type KeyboardEvent, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import {
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuSeparator,
  MenuTrigger,
} from '@/components/ui/Menu';
import type { PickKind } from './ItemPickerDialog';
import { useChatAction } from './model';

export type ComposerDialog = 'secret' | 'variables' | PickKind;

interface ComposerProps {
  peer: { key: string; name: string; online: boolean };
  /** The user just opened this conversation: the field takes the focus. */
  focus?: boolean;
  /** Opens one of the dialogs that send something other than text. */
  onOpen: (dialog: ComposerDialog) => void;
}

/** Where the user writes: Enter sends, Shift+Enter breaks the line. */
export function Composer({ peer, focus = false, onOpen }: ComposerProps) {
  const { t } = useTranslation();
  const [text, setText] = useState('');
  const field = useRef<HTMLTextAreaElement>(null);
  const hint = useId();
  const send = useChatAction(
    (words: string) => api.chatSendText(peer.key, words),
    () => setText(''),
  );
  const offline = !peer.online;

  // Focus moves here when the user opens a conversation, not when the tab does.
  useEffect(() => {
    if (focus) field.current?.focus();
  }, [focus]);

  // The field grows with its text, up to six lines.
  useEffect(() => {
    const node = field.current;
    if (!node) return;
    // Empty, it is one line high, whatever its placeholder.
    node.style.height = '';
    if (!text) return;
    node.style.height = `${Math.min(node.scrollHeight, 6 * 20 + 16)}px`;
  }, [text]);

  const submit = () => {
    if (offline || send.isPending || !text.trim()) return;
    send.mutate(text);
  };
  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === 'Enter' && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      submit();
    }
  };

  return (
    <div className="flex flex-col gap-1.5 border-t border-line-soft p-3">
      <div className="flex items-end gap-2">
        <Menu>
          <MenuTrigger asChild>
            <IconButton
              variant="secondary"
              label={t('nearby.chat.more')}
              icon={<Plus className="size-4" strokeWidth={2} />}
              disabled={offline}
            />
          </MenuTrigger>
          <MenuContent align="start">
            <MenuLabel>{t('nearby.chat.groupHidden')}</MenuLabel>
            <MenuItem
              icon={<KeyRound className="size-4" strokeWidth={2} />}
              onSelect={() => onOpen('secret')}
            >
              {t('nearby.chat.secretItem')}
            </MenuItem>
            <MenuItem
              icon={<Variable className="size-4" strokeWidth={2} />}
              onSelect={() => onOpen('variables')}
            >
              {t('nearby.chat.variablesItem')}
            </MenuItem>
            <MenuSeparator />
            <MenuLabel>{t('nearby.chat.groupSaved')}</MenuLabel>
            <MenuItem
              icon={<RectangleEllipsis className="size-4" strokeWidth={2} />}
              onSelect={() => onOpen('password')}
            >
              {t('nearby.chat.passwordItem')}
            </MenuItem>
            <MenuItem
              icon={<Server className="size-4" strokeWidth={2} />}
              onSelect={() => onOpen('host')}
            >
              {t('nearby.chat.hostItem')}
            </MenuItem>
            <MenuItem
              icon={<FolderTree className="size-4" strokeWidth={2} />}
              onSelect={() => onOpen('hostsGroup')}
            >
              {t('nearby.chat.groupItem')}
            </MenuItem>
            <MenuItem
              icon={<FileKey className="size-4" strokeWidth={2} />}
              onSelect={() => onOpen('publicKey')}
            >
              {t('nearby.chat.keyItem')}
            </MenuItem>
            <MenuItem
              icon={<Variable className="size-4" strokeWidth={2} />}
              onSelect={() => onOpen('environment')}
            >
              {t('nearby.chat.envItem')}
            </MenuItem>
          </MenuContent>
        </Menu>
        <textarea
          ref={field}
          rows={1}
          value={text}
          dir="auto"
          disabled={offline}
          aria-label={t('nearby.chat.composer', { name: peer.name })}
          aria-describedby={hint}
          placeholder={t('nearby.chat.composer', { name: peer.name })}
          onChange={(event) => setText(event.target.value)}
          onKeyDown={onKeyDown}
          className="field min-h-[34px] flex-1 resize-none rounded-[9px] border border-line-field px-3 py-[7px] text-[13px] leading-5 outline-none placeholder:text-faint focus-visible:ring-2 focus-visible:ring-[rgb(var(--accent-rgb)/0.5)] disabled:opacity-60"
        />
        <Button
          variant="primary"
          disabled={offline || !text.trim()}
          loading={send.isPending}
          icon={<SendHorizontal aria-hidden="true" className="size-4" strokeWidth={2} />}
          onClick={submit}
        >
          {t('nearby.chat.send')}
        </Button>
      </div>
      <p id={hint} className="px-1 text-[11.5px] leading-4 text-subtle">
        {offline
          ? t('nearby.chat.offlineHint', { name: peer.name })
          : t('nearby.chat.composerHint')}
      </p>
    </div>
  );
}
