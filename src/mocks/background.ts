// Running on with the window closed, and opening at login, for `pnpm dev`
// (see backend.ts).

import type { AutostartStatus } from '@/bindings/AutostartStatus';
import type { BackgroundStatus } from '@/bindings/BackgroundStatus';

type Handler = (args: Record<string, unknown>) => unknown;

let status: BackgroundStatus = { enabled: true, available: true };
let autostart: AutostartStatus = { enabled: false, turnedOffInSettings: false, blocker: null };

export const backgroundHandlers: Record<string, Handler> = {
  background_status: () => status,
  background_set_enabled: (args) => {
    status = { ...status, enabled: Boolean(args.enabled) };
    return status;
  },
  autostart_status: () => autostart,
  // As the app does: turning it on keeps the app running in the background.
  autostart_set_enabled: (args) => {
    const enabled = Boolean(args.enabled);
    autostart = { ...autostart, enabled };
    if (enabled && status.available) status = { ...status, enabled: true };
    return autostart;
  },
};
