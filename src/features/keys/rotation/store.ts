// Rotations in progress, kept in this computer's local storage so the user
// can retry failed hosts or come back later. Only names, fingerprints, public
// keys and how far each host has come: nothing secret.

import { useCallback, useSyncExternalStore } from 'react';
import { type HostProgress, newProgress, type StepState } from './plan';

export interface Rotation {
  /** The key being replaced (`KeyView.id`). */
  oldKeyId: string;
  oldName: string;
  oldFingerprint: string | null;
  /** The old key's private file, as the config names it. */
  oldPath: string | null;
  /** The old public key line: what is taken off the servers. */
  oldPublicKey: string | null;
  /** The new key, once it is made. */
  newKeyId: string | null;
  /** The hosts moving, in the order they move. */
  hosts: HostProgress[];
  /** RFC 3339. */
  updated: string;
}

const STORAGE_KEY = 'sshkm.rotations';
const STATES: readonly StepState[] = ['pending', 'done', 'failed', 'skipped'];

const isState = (value: unknown): value is StepState => STATES.includes(value as StepState);
const isText = (value: unknown): value is string => typeof value === 'string';
const isTextOrNull = (value: unknown): value is string | null => value === null || isText(value);

function readProgress(value: unknown): HostProgress | null {
  if (!value || typeof value !== 'object') return null;
  const host = value as Record<string, unknown>;
  if (!isText(host.alias) || !host.alias) return null;
  const state = (field: string) => {
    const raw = host[field];
    return isState(raw) ? raw : 'pending';
  };
  const oldOnServer = typeof host.oldOnServer === 'boolean' ? host.oldOnServer : null;
  return {
    ...newProgress(host.alias),
    install: state('install'),
    verify: state('verify'),
    config: state('config'),
    removeOld: state('removeOld'),
    oldOnServer,
  };
}

/** A stored rotation, or `null` if it is not one (an older or damaged entry). */
export function readRotation(value: unknown): Rotation | null {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  if (
    !isText(raw.oldKeyId) ||
    !isText(raw.oldName) ||
    !isTextOrNull(raw.oldFingerprint) ||
    !isTextOrNull(raw.oldPath) ||
    !isTextOrNull(raw.oldPublicKey) ||
    !isTextOrNull(raw.newKeyId) ||
    !Array.isArray(raw.hosts)
  ) {
    return null;
  }
  const hosts = raw.hosts.map(readProgress).filter((host) => host !== null);
  return {
    oldKeyId: raw.oldKeyId,
    oldName: raw.oldName,
    oldFingerprint: raw.oldFingerprint,
    oldPath: raw.oldPath,
    oldPublicKey: raw.oldPublicKey,
    newKeyId: raw.newKeyId,
    hosts,
    updated: isText(raw.updated) ? raw.updated : new Date(0).toISOString(),
  };
}

function load(): Record<string, Rotation> {
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? '{}');
    if (!raw || typeof raw !== 'object') return {};
    const result: Record<string, Rotation> = {};
    for (const value of Object.values(raw)) {
      const rotation = readRotation(value);
      if (rotation) result[rotation.oldKeyId] = rotation;
    }
    return result;
  } catch {
    return {};
  }
}

let rotations: Record<string, Rotation> | null = null;
const listeners = new Set<() => void>();

function current(): Record<string, Rotation> {
  rotations ??= load();
  return rotations;
}

function write(next: Record<string, Rotation>) {
  rotations = next;
  try {
    if (Object.keys(next).length) localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Without storage it is remembered until the app quits.
  }
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Saves `rotation`, stamped with the time. */
export function saveRotation(rotation: Rotation) {
  write({ ...current(), [rotation.oldKeyId]: { ...rotation, updated: new Date().toISOString() } });
}

/** Forgets the rotation of the key `oldKeyId`. */
export function forgetRotation(oldKeyId: string) {
  if (!(oldKeyId in current())) return;
  const { [oldKeyId]: _gone, ...rest } = current();
  write(rest);
}

/** The rotation of `oldKeyId` as stored now, for code that runs between renders. */
export function rotationOf(oldKeyId: string): Rotation | null {
  return current()[oldKeyId] ?? null;
}

/** Changes the stored rotation of `oldKeyId`, if there is one. */
export function updateRotation(oldKeyId: string, change: (rotation: Rotation) => Rotation) {
  const now = current()[oldKeyId];
  if (now) saveRotation(change(now));
}

/** Every rotation in progress, by the old key's id. */
export function useRotations(): Record<string, Rotation> {
  return useSyncExternalStore(subscribe, current, current);
}

/** The rotation of `oldKeyId`, if one is in progress, and a function that changes it. */
export function useRotation(oldKeyId: string) {
  const rotation = useRotations()[oldKeyId] ?? null;
  const update = useCallback(
    (change: (rotation: Rotation) => Rotation) => updateRotation(oldKeyId, change),
    [oldKeyId],
  );
  return { rotation, update };
}

/** Changes one host's progress, by alias. */
export function withHost(
  rotation: Rotation,
  alias: string,
  change: Partial<HostProgress>,
): Rotation {
  return {
    ...rotation,
    hosts: rotation.hosts.map((host) => (host.alias === alias ? { ...host, ...change } : host)),
  };
}
