// Hosts from the shell history, for `pnpm dev` (see backend.ts). The app
// reads the history in Rust; this answers with made-up targets, and like the
// app leaves out those a `Host` block covers and those dismissed.

import type { HistoryScan } from '@/bindings/HistoryScan';
import type { HistoryStatus } from '@/bindings/HistoryStatus';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostSuggestion } from '@/bindings/HostSuggestion';

type Handler = (args: Record<string, unknown>) => unknown;

const DAY = 24 * 3600 * 1000;
const ago = (days: number) => new Date(Date.now() - days * DAY).toISOString();

function suggestion(
  partial: Partial<HostSuggestion> & Pick<HostSuggestion, 'id' | 'alias' | 'host'>,
) {
  return {
    user: null,
    port: null,
    identityFile: null,
    proxyJump: null,
    forwardAgent: false,
    options: [],
    uses: 1,
    lastUsed: null,
    shells: ['zsh'],
    ...partial,
  } satisfies HostSuggestion;
}

const SUGGESTIONS: HostSuggestion[] = [
  suggestion({
    id: '5f0c6a1e9b2d4c7a8e3f1b0d2c4a6e8f',
    alias: 'root-10-0-0-5',
    host: '10.0.0.5',
    user: 'root',
    port: 2222,
    identityFile: '~/.ssh/id_ed25519',
    uses: 14,
    lastUsed: ago(2),
  }),
  suggestion({
    id: '1a2b3c4d5e6f708192a3b4c5d6e7f809',
    alias: 'web1',
    host: 'web1.staging.example.com',
    user: 'deploy',
    proxyJump: 'bastion',
    options: [{ key: 'ServerAliveInterval', value: '30' }],
    uses: 9,
    lastUsed: ago(6),
    shells: ['zsh', 'bash'],
  }),
  suggestion({
    id: '9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b',
    alias: 'pi-192-168-1-40',
    host: '192.168.1.40',
    user: 'pi',
    uses: 4,
    lastUsed: ago(41),
    shells: ['fish'],
  }),
  suggestion({
    id: '0f1e2d3c4b5a69788796a5b4c3d2e1f0',
    alias: 'nas',
    host: 'nas.home.arpa',
    user: 'backup',
    port: 2200,
    forwardAgent: true,
    uses: 3,
    shells: ['bash'],
  }),
  suggestion({
    id: 'a0b1c2d3e4f5061728394a5b6c7d8e9f',
    alias: 'admin-2001-db8-10',
    host: '2001:db8::10',
    user: 'admin',
    uses: 1,
    shells: ['powerShell'],
  }),
];

let status: HistoryStatus = { consent: 'unasked', dismissed: 0 };
let dismissed = new Set<string>();

/** Like `configured` in `shell_history.rs`: by name, or by HostName, User and Port. */
function covered(s: HostSuggestion, hosts: HostEntry[]): boolean {
  return hosts.some(
    (h) =>
      h.patterns.some((p) => p.toLowerCase() === s.alias || p.toLowerCase() === s.host) ||
      (h.hostName?.toLowerCase() === s.host &&
        (h.port ?? 22) === (s.port ?? 22) &&
        (s.user === null || h.user === s.user)),
  );
}

export function shellHistoryHandlers(hosts: () => HostEntry[]): Record<string, Handler> {
  return {
    shell_history_status: () => status,
    shell_history_set_enabled: (args) => {
      status = { ...status, consent: args.enabled ? 'on' : 'off' };
      return status;
    },
    shell_history_scan: (): HistoryScan => {
      if (status.consent !== 'on') {
        throw { code: 'invalid_input', message: 'shell history suggestions are off' };
      }
      const all = SUGGESTIONS.filter((s) => !covered(s, hosts()));
      return {
        suggestions: all.filter((s) => !dismissed.has(s.id)),
        files: [
          { shell: 'zsh', path: '/Users/dev/.zsh_history', secrets: 2 },
          { shell: 'bash', path: '/Users/dev/.bash_history', secrets: 0 },
          { shell: 'fish', path: '/Users/dev/.local/share/fish/fish_history', secrets: 0 },
        ],
        dismissed: all.filter((s) => dismissed.has(s.id)).length,
      };
    },
    shell_history_dismiss: (args) => {
      dismissed.add(String(args.id));
      status = { ...status, dismissed: dismissed.size };
      return status;
    },
    shell_history_forget_dismissed: () => {
      dismissed = new Set();
      status = { ...status, dismissed: 0 };
      return status;
    },
  };
}
