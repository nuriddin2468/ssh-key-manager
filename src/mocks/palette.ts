// Quick search, for `pnpm dev` (see backend.ts): its shortcut, and what the
// quick window lists, from the other mocks.

import type { EntrySummary } from '@/bindings/EntrySummary';
import type { HostEntry } from '@/bindings/HostEntry';
import type { QuickItems } from '@/bindings/QuickItems';
import type { QuickStatus } from '@/bindings/QuickStatus';
import { isConnectable } from '@/features/terminal/model';

type Handler = (args: Record<string, unknown>) => unknown;

const DEFAULT = 'Shift+Super+Space';
/** Spotlight's: the mock says another app has it, to show that message. */
const TAKEN = 'Super+Space';

let status: QuickStatus = {
  enabled: true,
  shortcut: DEFAULT,
  defaultShortcut: DEFAULT,
  registered: true,
};

export function paletteHandlers(sources: {
  hosts: () => HostEntry[];
  /** The vault's entries; fails while it is locked. */
  entries: () => unknown;
}): Record<string, Handler> {
  return {
    quick_status: () => status,
    quick_set_shortcut: ({ enabled, shortcut }) => {
      const text = typeof shortcut === 'string' ? shortcut : DEFAULT;
      if (!/(^|\+)(Ctrl|Alt|Super)\+/.test(text)) {
        return Promise.reject({
          code: 'invalid_input',
          message: 'a shortcut needs Ctrl, Alt or the Command key',
        });
      }
      status = {
        ...status,
        enabled: Boolean(enabled),
        shortcut: text,
        registered: Boolean(enabled) && text !== TAKEN,
      };
      return status;
    },
    quick_items: async (): Promise<QuickItems> => {
      const seen = new Set<string>();
      const hosts = sources
        .hosts()
        .filter((block) => block.kind === 'host' && !block.isWildcard)
        .flatMap((block) =>
          block.patterns
            .filter((alias) => isConnectable(alias) && !seen.has(alias) && seen.add(alias))
            .map((alias) => ({ alias, user: block.user, hostName: block.hostName })),
        );
      const entries = await Promise.resolve(sources.entries()).then(
        (list) =>
          (list as EntrySummary[])
            .filter((entry) => !entry.inTrash)
            .map(({ id, title, username, url, kind, hasPassword, hasOtp }) => ({
              id,
              title,
              username,
              url,
              kind,
              hasPassword,
              hasOtp,
            })),
        () => null,
      );
      return { hosts, entries };
    },
    quick_connect: () => undefined,
    quick_close: () => undefined,
  };
}
