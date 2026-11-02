import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { type RefObject, useEffect } from 'react';
import { invalidateAll } from '@/api/queries';
import { platform } from '@/lib/platform';
import { useDialogs } from './dialogs';
import { type Page, type Route, useRouter } from './router';

const FIND_EVENT = 'sshkm:find';
const PAGES: Page[] = ['overview', 'keys', 'hosts', 'agent', 'known', 'audit'];

/**
 * Wires the native menu (macOS), keyboard shortcuts (Windows/Linux, where
 * there is no menu bar) and file-change notifications from the backend.
 */
export function useAppEvents(): void {
  const { navigate } = useRouter();
  const dialogs = useDialogs();

  useEffect(() => {
    const command = (id: string) => {
      if (id.startsWith('nav-')) navigate({ page: id.slice(4) } as Route);
      else if (id === 'settings') navigate({ page: 'settings' });
      else if (id === 'new-key') dialogs.generateKey();
      else if (id === 'import-key') void dialogs.importKey();
      else if (id === 'add-host') dialogs.addHost();
      else if (id === 'check') void invalidateAll();
      else if (id === 'find') window.dispatchEvent(new Event(FIND_EVENT));
    };

    const unlisten: Promise<() => void>[] = [];
    if (isTauri()) {
      unlisten.push(listen('ssh-files-changed', () => void invalidateAll()));
      unlisten.push(listen<string>('menu', (event) => command(event.payload)));
    }

    // On macOS the menu bar owns these shortcuts; elsewhere the page does.
    const onKey = (event: KeyboardEvent) => {
      const mod = platform === 'macos' ? event.metaKey : event.ctrlKey;
      if (!mod || event.altKey) return;
      if (platform === 'macos' && isTauri()) return;
      const digit = Number(event.key);
      let id: string | undefined;
      if (digit >= 1 && digit <= PAGES.length) id = `nav-${PAGES[digit - 1]}`;
      else if (event.key === ',') id = 'settings';
      else if (event.key.toLowerCase() === 'n') id = event.shiftKey ? 'add-host' : 'new-key';
      else if (event.key.toLowerCase() === 'o') id = 'import-key';
      else if (event.key.toLowerCase() === 'r') id = 'check';
      else if (event.key.toLowerCase() === 'f' || event.key.toLowerCase() === 'k') id = 'find';
      if (!id) return;
      event.preventDefault();
      command(id);
    };
    window.addEventListener('keydown', onKey);

    return () => {
      window.removeEventListener('keydown', onKey);
      for (const promise of unlisten) void promise.then((stop) => stop());
    };
  }, [navigate, dialogs]);
}

/** Focuses the page's search field on ⌘F / ⌘K. */
export function useFindShortcut(input: RefObject<HTMLInputElement | null>): void {
  useEffect(() => {
    const focus = () => {
      input.current?.focus();
      input.current?.select();
    };
    window.addEventListener(FIND_EVENT, focus);
    return () => window.removeEventListener(FIND_EVENT, focus);
  }, [input]);
}
