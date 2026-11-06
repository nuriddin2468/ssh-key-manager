// The browser's own password manager and form suggestions, which show under
// login fields next to the extension's menu. The popup turns them off and
// on again with the `privacy` permission, which the extension asks for only
// then (`optional_permissions`).
//
// Off sets the browser's "Offer to save passwords" (and, in Chromium, its
// address and earlier-entry suggestions) to off; on hands them back to the
// user's own settings. Passwords already saved in a Chromium browser are
// still suggested until the user deletes them there.
//
// The permission prompt may close the popup (Firefox), so what the user
// chose waits in `storage.session` and the background applies it once the
// permission comes (`applyWanted`).

import { ext } from './ext';

const PERMISSION = { permissions: ['privacy'] };
/** Where the popup leaves the user's choice for the background. */
const WANTED = 'browserSuggestions';

export interface Suggestions {
  /** Without the permission the extension can't tell: the browser's default, on. */
  on: boolean;
  /** False when the user's organization or another extension set it. */
  controllable: boolean;
}

function settings(): WebExt.BrowserSetting[] {
  const services = ext.privacy?.services;
  if (!services) return [];
  return [services.passwordSavingEnabled, services.autofillAddressEnabled].filter(
    (setting): setting is WebExt.BrowserSetting => setting !== undefined,
  );
}

/** Whether the browser offers to save passwords, and whether this extension may change that. */
export async function readSuggestions(): Promise<Suggestions> {
  if (!(await ext.permissions.contains(PERMISSION))) return { on: true, controllable: true };
  const [passwords] = settings();
  if (!passwords) return { on: true, controllable: true };
  const { value, levelOfControl } = await passwords.get({});
  return {
    on: value !== false,
    controllable:
      levelOfControl === 'controllable_by_this_extension' ||
      levelOfControl === 'controlled_by_this_extension',
  };
}

/**
 * Turns the browser's own suggestions on or off. Call it from the click
 * itself: the permission prompt needs the user's gesture. False if the
 * browser didn't allow it.
 */
export async function setSuggestions(on: boolean): Promise<boolean> {
  if (on) {
    // Nothing was changed without the permission, so there's nothing to give back.
    if (await ext.permissions.contains(PERMISSION)) await apply(true);
    return true;
  }
  const granted = ext.permissions.request(PERMISSION);
  await ext.storage.session.set({ [WANTED]: false });
  if (!(await granted)) return false;
  await apply(false);
  return true;
}

async function apply(on: boolean): Promise<void> {
  for (const setting of settings()) {
    if (on) await setting.clear({});
    else await setting.set({ value: false });
  }
  await ext.storage.session.remove(WANTED);
}

/** In the background, when the permission comes: what the popup asked for, if it closed first. */
export async function applyWanted(): Promise<void> {
  const stored = await ext.storage.session.get(WANTED);
  if (stored[WANTED] === false) await apply(false);
}

/** Whether passwords saved in the browser stay suggested after turning it off: Chromium. */
export function keepsSavedPasswords(): boolean {
  return !navigator.userAgent.includes('Firefox/');
}

/** Opens the browser's page of saved passwords (Chromium). */
export function openBrowserPasswords(): void {
  void ext.tabs.create({ url: 'chrome://settings/passwords' });
}
