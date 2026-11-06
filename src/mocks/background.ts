// Running on with the window closed, for `pnpm dev` (see backend.ts).

import type { BackgroundStatus } from '@/bindings/BackgroundStatus';

type Handler = (args: Record<string, unknown>) => unknown;

let status: BackgroundStatus = { enabled: true, available: true };

export const backgroundHandlers: Record<string, Handler> = {
  background_status: () => status,
  background_set_enabled: (args) => {
    status = { ...status, enabled: Boolean(args.enabled) };
    return status;
  },
};
