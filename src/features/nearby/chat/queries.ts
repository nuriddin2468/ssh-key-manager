// Chats: the list and each conversation, kept current by the backend's
// events, and telling the backend while Nearby is open.

import { useQuery } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { useEffect } from 'react';
import { api } from '@/api/commands';
import { queryClient, useVaultStatus } from '@/api/queries';
import type { ChatsChanged } from '@/bindings/ChatsChanged';
import { CHATS_EVENT, MOCK_CHATS_EVENT } from './events';

export const chatKeys = {
  list: ['chats', 'list'] as const,
  history: (key: string) => ['chats', 'history', key] as const,
};

/** The conversations, while the vault is unlocked. */
export function useChatList() {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({ queryKey: chatKeys.list, queryFn: api.chatList, enabled: unlocked });
}

/** One conversation, while the vault is unlocked. */
export function useChatHistory(key: string | undefined) {
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  return useQuery({
    queryKey: chatKeys.history(key ?? ''),
    queryFn: () => api.chatHistory(key ?? ''),
    enabled: unlocked && Boolean(key),
  });
}

function refresh(key: string | null) {
  void queryClient.invalidateQueries({ queryKey: chatKeys.list });
  void queryClient.invalidateQueries({
    queryKey: key ? chatKeys.history(key) : ['chats', 'history'],
  });
}

/** App-wide: follows the backend's chat events. Mounted once in the shell. */
export function useChatEvents(): void {
  useEffect(() => {
    if (isTauri()) {
      const unlisten = listen<ChatsChanged>(CHATS_EVENT, (event) => refresh(event.payload.key));
      return () => void unlisten.then((stop) => stop());
    }
    if (!import.meta.env.DEV) return undefined;
    const changed = (event: Event) =>
      refresh((event as CustomEvent<ChatsChanged>).detail?.key ?? null);
    window.addEventListener(MOCK_CHATS_EVENT, changed);
    return () => window.removeEventListener(MOCK_CHATS_EVENT, changed);
  }, []);
}

/** How often an open Nearby says so again. */
const OPEN_EVERY_MS = 20_000;
/** How long after Nearby closes the backend hears it: a page that opens again meanwhile keeps it open. */
const CLOSE_AFTER_MS = 500;
let closing: number | undefined;

/**
 * Tells the backend Nearby is open while the component is mounted: with the
 * vault unlocked and the window visible, this computer is online for chats.
 * It says so again every 20 seconds, and says it closed only once no page
 * opened again within half a second: commands may arrive out of order, and
 * a late "closed" must not take a page that is open offline.
 */
export function useChatsOnline(): void {
  useEffect(() => {
    window.clearTimeout(closing);
    const open = () => void api.chatSetOpen(true).catch(() => undefined);
    open();
    const timer = window.setInterval(open, OPEN_EVERY_MS);
    return () => {
      window.clearInterval(timer);
      closing = window.setTimeout(
        () => void api.chatSetOpen(false).catch(() => undefined),
        CLOSE_AFTER_MS,
      );
    };
  }, []);
}
