// The light and dark themes. `public/theme-boot.js` picks one before the first
// paint; this keeps it current: when the setting changes (here or in another
// window) and, while the setting is System, when the system's appearance does.
// The tokens themselves are in `src/styles/app.css`.

import { useSyncExternalStore } from 'react';
import { call } from '@/lib/ipc';
import { currentSettings, type Settings, subscribeSettings } from '@/lib/settings';

export type Appearance = Settings['appearance'];
export type Theme = 'light' | 'dark';

export const APPEARANCES: readonly Appearance[] = ['system', 'light', 'dark'];

/** The theme an appearance shows when the system is light (`systemLight`) or not. */
export function resolveTheme(appearance: Appearance, systemLight: boolean): Theme {
  if (appearance === 'light' || appearance === 'dark') return appearance;
  return systemLight ? 'light' : 'dark';
}

function systemQuery(): MediaQueryList | null {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function'
    ? window.matchMedia('(prefers-color-scheme: light)')
    : null;
}

function documentTheme(): Theme {
  return document.documentElement.dataset.theme === 'light' ? 'light' : 'dark';
}

let theme: Theme = typeof document === 'undefined' ? 'dark' : documentTheme();
const listeners = new Set<() => void>();

/** The theme on screen now. */
export function currentTheme(): Theme {
  return theme;
}

/** Calls `listener` whenever the theme on screen changes. Returns the unsubscribe. */
export function subscribeTheme(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribeTheme, currentTheme);
}

/** Shows `next` and tells whoever draws with plain colours (xterm, toasts). */
function show(next: Theme): void {
  const root = document.documentElement;
  root.dataset.theme = next;
  root.style.colorScheme = next;
  // The boot script painted the window before the styles loaded; they do it now.
  root.style.removeProperty('background-color');
  if (next === theme) return;
  theme = next;
  for (const listener of listeners) listener();
}

/**
 * Follows the setting and the system from now on. `native` (the main window
 * only) also sets the windows' own appearance: title bars, the window
 * background before a page paints, native dialogs. Returns the stop.
 */
export function startTheme({ native = false }: { native?: boolean } = {}): () => void {
  const query = systemQuery();
  let sent = '';
  const update = () => {
    const { appearance } = currentSettings();
    const next = resolveTheme(appearance, query?.matches ?? false);
    show(next);
    const message = `${appearance}:${next}`;
    if (native && message !== sent) {
      sent = message;
      call('set_appearance', { appearance, dark: next === 'dark' }).catch(() => {
        // The windows keep their look; the page is right either way.
        sent = '';
      });
    }
  };
  update();
  const unsubscribe = subscribeSettings(update);
  query?.addEventListener('change', update);
  return () => {
    unsubscribe();
    query?.removeEventListener('change', update);
  };
}
