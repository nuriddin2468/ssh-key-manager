import { useSyncExternalStore } from 'react';
import { toast } from 'sonner';
import type { Change } from '@/bindings/Change';
import type { Release } from '@/bindings/Release';
import i18n from '@/i18n';
import history from '../../changelog/releases.json';

/**
 * The notes of this version and every one before it, newest first, as this
 * build was made (`changelog/releases.json`). Newer versions' notes come
 * from the release server with the update offer.
 */
export const RELEASES = history as Release[];

/** What the release notes dialog shows, if it is open. */
export type NotesView =
  /** Before installing `version`: the notes of each version since this one. */
  | { kind: 'offer'; version: string; releases: Release[] }
  /** After updating to `version`: the notes of the versions this one skipped to. */
  | { kind: 'updated'; version: string; releases: Release[] }
  /** Every version this build knows of. */
  | { kind: 'history' };

let view: NotesView | null = null;
const listeners = new Set<() => void>();

export function showReleaseNotes(next: NotesView | null): void {
  view = next;
  for (const listener of listeners) listener();
}

export function useReleaseNotes(): NotesView | null {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => view,
  );
}

/** A note in the app's language, or in English if it wasn't written in it. */
export function noteText(change: Change, language: string): string {
  const base = language.split('-')[0];
  if (base === 'ru' && change.ru) return change.ru;
  if (base === 'uz' && change.uz) return change.uz;
  return change.en;
}

/** Orders plain `1.2.3` versions; anything else counts as 0.0.0. */
export function compareVersions(a: string, b: string): number {
  const parts = (version: string) => {
    const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
    return match ? match.slice(1).map(Number) : [0, 0, 0];
  };
  const [x, y] = [parts(a), parts(b)];
  for (let i = 0; i < 3; i++) {
    const diff = (x[i] ?? 0) - (y[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

const SEEN_KEY = 'sshkm.seenVersion';
const TOAST_ID = 'updated';

/**
 * Once the app runs a version newer than the one it last ran, says so and
 * offers the notes of the versions in between.
 */
export function announceUpdate(appVersion: string): void {
  let seen: string | null;
  let usedBefore: boolean;
  try {
    seen = localStorage.getItem(SEEN_KEY);
    localStorage.setItem(SEEN_KEY, appVersion);
    // 0.7.0 and earlier didn't keep `SEEN_KEY`. Any other key of the app
    // means it ran before, so this version is the one it was updated to.
    usedBefore = Object.keys(localStorage).some(
      (key) => key.startsWith('sshkm.') && key !== SEEN_KEY,
    );
  } catch {
    return;
  }
  if (seen === null && !usedBefore) return;
  if (seen !== null && compareVersions(appVersion, seen) <= 0) return;

  const releases = RELEASES.filter(
    (release) =>
      compareVersions(release.version, appVersion) <= 0 &&
      (seen === null ? release.version === appVersion : compareVersions(release.version, seen) > 0),
  );
  if (releases.length === 0) return;
  toast.success(i18n.t('updates.updated', { version: appVersion }), {
    id: TOAST_ID,
    duration: 15_000,
    action: {
      label: i18n.t('updates.whatsNew'),
      onClick: () => showReleaseNotes({ kind: 'updated', version: appVersion, releases }),
    },
  });
}
