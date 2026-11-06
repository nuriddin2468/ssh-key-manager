import { Channel, isTauri } from '@tauri-apps/api/core';
import { createElement, useEffect, useSyncExternalStore } from 'react';
import { toast } from 'sonner';
import type { Release } from '@/bindings/Release';
import type { UpdateOffer } from '@/bindings/UpdateOffer';
import { UpdateToast } from '@/components/UpdateToast';
import i18n from '@/i18n';
import { call } from '@/lib/ipc';
import { showReleaseNotes } from '@/lib/releaseNotes';

/**
 * The updater runs in Rust (`src-tauri/src/commands/updates.rs`), with the
 * release server and key from `tauri.conf.json`; the page can only ask.
 */
const updates = {
  /** The newer version the release server offers, with its notes, or `null`. */
  check: () => call<UpdateOffer | null>('update_check'),
  /**
   * Backs up the SSH and vault files, installs the version the last check
   * found and restarts into it.
   */
  install: (onProgress: (percent: number) => void) =>
    call<void>('update_install', { progress: new Channel<number>(onProgress) }),
};

/** Where the app is in finding, downloading and installing a newer release. */
export type UpdateState =
  | { status: 'idle' }
  | { status: 'checking' }
  | { status: 'upToDate' }
  /** `releases` are the notes of each version since this one, newest first. */
  | { status: 'available'; version: string; releases: Release[] }
  | { status: 'downloading'; version: string; percent: number | null }
  | { status: 'error' };

const TOAST_ID = 'update';
/**
 * The offer is a custom toast, and sonner keeps a toast's custom content when
 * another toast reuses its id, so progress and results use `TOAST_ID` instead.
 */
const OFFER_ID = 'update-offer';
const CHECK_INTERVAL = 6 * 60 * 60 * 1000;

let state: UpdateState = { status: 'idle' };
/** The version the automatic check last told the user about, so it asks only once. */
let announced: string | null = null;
const listeners = new Set<() => void>();

function set(next: UpdateState): void {
  state = next;
  for (const listener of listeners) listener();
}

export function useUpdateState(): UpdateState {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => state,
  );
}

/**
 * Asks the release server for a newer version. A `quiet` check (the automatic
 * one) stays silent unless it finds a version it has not offered yet.
 */
export async function checkForUpdates({ quiet = false } = {}): Promise<void> {
  if (state.status === 'checking' || state.status === 'downloading') return;
  set({ status: 'checking' });
  try {
    // `pnpm dev` in a browser has nothing to update.
    const found = isTauri() ? await updates.check() : null;
    if (!found) {
      set({ status: 'upToDate' });
      if (!quiet) toast.success(i18n.t('updates.upToDate'), { id: TOAST_ID });
      return;
    }
    set({ status: 'available', version: found.version, releases: found.releases });
    if (!quiet || announced !== found.version) offer(found);
  } catch (error) {
    set({ status: 'error' });
    if (!quiet) toast.error(i18n.t('updates.error'), { id: TOAST_ID, description: reason(error) });
  }
}

/** Downloads and installs the update found by the last check, then restarts into it. */
export async function installUpdate(): Promise<void> {
  if (state.status !== 'available') return;
  const { version, releases } = state;
  const progress = (percent: number | null) => {
    set({ status: 'downloading', version, percent });
    toast.loading(i18n.t('updates.downloading', { version }), {
      id: TOAST_ID,
      description: percent === null ? undefined : `${percent}%`,
    });
  };

  progress(null);
  try {
    // Windows quits into the installer; macOS and Linux restart once it is installed.
    await updates.install((percent) => {
      if (state.status === 'downloading' && state.percent !== percent) progress(percent);
    });
  } catch (error) {
    set({ status: 'available', version, releases });
    toast.error(i18n.t('updates.installFailed'), { id: TOAST_ID, description: reason(error) });
  }
}

/** Checks at startup and every few hours while automatic checks are on. */
export function useAutomaticUpdates(enabled: boolean): void {
  useEffect(() => {
    if (!enabled || !isTauri()) return;
    void checkForUpdates({ quiet: true });
    const timer = window.setInterval(() => void checkForUpdates({ quiet: true }), CHECK_INTERVAL);
    return () => window.clearInterval(timer);
  }, [enabled]);
}

/** Opens the notes of the version the last check found, to install it from there. */
export function showUpdateNotes(): void {
  if (state.status !== 'available') return;
  showReleaseNotes({ kind: 'offer', version: state.version, releases: state.releases });
}

/**
 * Offers the update. Its button opens the release notes, where the update
 * is installed, so what changes is read before it does.
 */
function offer({ version, releases }: UpdateOffer): void {
  announced = version;
  toast.custom(
    () =>
      createElement(UpdateToast, {
        version,
        releases,
        onLater: () => toast.dismiss(OFFER_ID),
        onShowNotes: () => {
          toast.dismiss(OFFER_ID);
          showUpdateNotes();
        },
      }),
    { id: OFFER_ID, duration: Number.POSITIVE_INFINITY },
  );
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
