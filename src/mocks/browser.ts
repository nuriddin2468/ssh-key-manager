// Browser autofill for `pnpm dev` (see backend.ts): the settings section's
// status, turning it on and off, and revoking paired browsers. The pairing
// dialog has its own preview: `?open=pairing`.

import type { BrowserStatus } from '@/bindings/BrowserStatus';
import type { PairedBrowser } from '@/bindings/PairedBrowser';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { vaultHandlers } from './vault';

type Handler = (args: Record<string, unknown>) => unknown;

let enabled = true;
let paired: PairedBrowser[] = [
  {
    id: 'mock-chrome-0123456789',
    browser: 'Google Chrome',
    computer: 'MacBook-Pro',
    paired: '2026-10-28T09:12:00Z',
  },
  {
    id: 'mock-firefox-0123456789',
    browser: 'Firefox',
    computer: 'MacBook-Pro',
    paired: '2026-09-14T17:40:00Z',
  },
];

async function unlocked(): Promise<boolean> {
  const status = (await vaultHandlers.vault_status?.({})) as VaultStatus | undefined;
  return status?.state === 'unlocked';
}

async function status(): Promise<BrowserStatus> {
  return {
    enabled,
    listening: enabled,
    problem: null,
    browsers: [
      { name: 'Google Chrome', registered: true },
      { name: 'Firefox', registered: true },
      { name: 'Microsoft Edge', registered: false },
    ],
    paired: (await unlocked()) ? paired : null,
    pairing: null,
  };
}

export const browserHandlers: Record<string, Handler> = {
  browser_status: () => status(),
  browser_set_enabled: (args) => {
    enabled = Boolean(args.enabled);
    return status();
  },
  browser_answer_pairing: () => undefined,
  browser_revoke: (args) => {
    paired = paired.filter((browser) => browser.id !== args.id);
  },
};
