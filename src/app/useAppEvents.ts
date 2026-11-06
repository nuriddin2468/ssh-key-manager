import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { type RefObject, useEffect } from 'react';
import { invalidateAll } from '@/api/queries';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { platform } from '@/lib/platform';
import { checkForUpdates } from '@/lib/updater';
import { useDialogs } from './dialogs';
import { type Page, type Route, useRouter } from './router';

/** ⌘F: the page's search, or the terminal's find bar. */
export const FIND_EVENT = 'sshkm:find';
/** ⌘K: opens or closes the command palette (src/features/palette). */
export const PALETTE_EVENT = 'sshkm:palette';
// ⌘1–⌘9, in the order they were added so existing shortcuts never move.
export const NAV_PAGES: Page[] = [
  'overview',
  'keys',
  'hosts',
  'agent',
  'known',
  'audit',
  'hostsFile',
  'passwords',
  'terminal',
];

/**
 * Wires the native menu (macOS) and the tray menu, keyboard shortcuts
 * (Windows/Linux, where there is no menu bar) and file-change notifications
 * from the backend.
 */
export function useAppEvents(): void {
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const { setPickerOpen } = useTerminals();

  useEffect(() => {
    const command = (id: string) => {
      if (id.startsWith('nav-')) navigate({ page: id.slice(4) } as Route);
      else if (id === 'settings') navigate({ page: 'settings' });
      else if (id === 'new-session') {
        navigate({ page: 'terminal' });
        setPickerOpen(true);
      } else if (id === 'new-key') dialogs.generateKey();
      else if (id === 'import-key') void dialogs.importKey();
      else if (id === 'add-host') dialogs.addHost();
      else if (id === 'check') void invalidateAll();
      else if (id === 'check-updates') void checkForUpdates();
      else if (id === 'find') window.dispatchEvent(new Event(FIND_EVENT));
      else if (id === 'palette') window.dispatchEvent(new Event(PALETTE_EVENT));
      // From the tray menu: a session to that host.
      else if (id.startsWith('connect:'))
        navigate({ page: 'terminal', connect: id.slice('connect:'.length), nonce: Date.now() });
      // From the tray menu: one of the Tools page's tools.
      else if (id.startsWith('tool:')) navigate({ page: 'tools', tool: id.slice('tool:'.length) });
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
      if (digit >= 1 && digit <= NAV_PAGES.length) id = `nav-${NAV_PAGES[digit - 1]}`;
      else if (event.key === ',') id = 'settings';
      else if (event.key.toLowerCase() === 'n') id = event.shiftKey ? 'add-host' : 'new-key';
      else if (event.key.toLowerCase() === 'o') id = 'import-key';
      // ⌘T on macOS; Ctrl+Shift+T elsewhere, as Ctrl+T belongs to the shell.
      else if (event.key.toLowerCase() === 't' && (platform === 'macos' || event.shiftKey))
        id = 'new-session';
      else if (event.key.toLowerCase() === 'r') id = 'check';
      else if (event.key.toLowerCase() === 'f') id = 'find';
      // Ctrl+K belongs to the shell in the terminal, which passes on Ctrl+Shift+K.
      else if (event.key.toLowerCase() === 'k') id = 'palette';
      if (!id) return;
      event.preventDefault();
      command(id);
    };
    window.addEventListener('keydown', onKey);

    return () => {
      window.removeEventListener('keydown', onKey);
      for (const promise of unlisten) void promise.then((stop) => stop());
    };
  }, [navigate, dialogs, setPickerOpen]);
}

/** Focuses the page's search field on ⌘F. */
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
