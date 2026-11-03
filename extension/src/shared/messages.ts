// Messages from the content scripts to the background script, and back.
// The background takes the page's origin from the browser (the sender),
// never from the message.

import type { SaveOffer } from '../content/surfaces';
import type { LoginOffer, Problem } from './client';

export type ToBackground =
  /** The logins for the sending frame's page. */
  | { kind: 'logins' }
  /** The username and password of a login the user picked. */
  | { kind: 'fill'; entryId: string }
  /** Bring the app forward to unlock the vault. */
  | { kind: 'unlock' }
  /** A login form was sent with these values. */
  | { kind: 'capture'; username: string; password: string }
  /** The save offer waiting for this tab, if any. */
  | { kind: 'pendingSave' }
  | { kind: 'save'; id: string }
  | { kind: 'dismissSave'; id: string };

/** From the background to a tab's top frame. */
export type ToContent = { kind: 'offerSave' };

export type LoginsReply =
  | { state: 'ready'; logins: LoginOffer[] }
  | { state: 'locked' }
  /** Not paired, app not reachable, or anything else: show nothing. */
  | { state: 'off' };

export type FillReply =
  | { ok: true; username: string; password: string }
  | { ok: false; problem: Problem };

export type SaveReply = { ok: true; mode: 'save' | 'update' } | { ok: false; problem: Problem };

export type PendingSaveReply = SaveOffer | null;
