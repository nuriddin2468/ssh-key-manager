// Running on with the window closed, and opening at login, for `pnpm dev`
// (see backend.ts).

import type { AutostartStatus } from '@/bindings/AutostartStatus';
import type { BackgroundStatus } from '@/bindings/BackgroundStatus';

type Handler = (args: Record<string, unknown>) => unknown;

// One virtual file to begin with: shop-api dev's (envs.ts).
let status: BackgroundStatus = { enabled: true, available: true, virtualFiles: 1 };
let autostart: AutostartStatus = { enabled: false, turnedOffInSettings: false, blocker: null };

/** As the app does: binding a virtual file keeps it running in the background. */
export function keepRunningForVirtualFiles() {
  if (status.available) status = { ...status, enabled: true };
}

/** How many virtual files the app serves, for the Settings page. */
export function setVirtualFiles(count: number) {
  status = { ...status, virtualFiles: count };
}

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
