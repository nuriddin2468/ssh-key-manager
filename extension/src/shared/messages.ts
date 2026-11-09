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
  /**
   * A login form was sent with these values. `change`: a password-change
   * form, whose `password` is the new one.
   */
  | { kind: 'capture'; username: string; password: string; change?: boolean }
  /** The login the user picked was filled into the page's password field. */
  | { kind: 'filled'; entryId: string }
  /** The user sent the form with the password filled from the vault. */
  | { kind: 'signInSent' }
  /** Did a sign-in with a filled login just fail on this page? */
  | { kind: 'signInCheck' }
  /** The "couldn't sign in?" banner is shown for this login: not again in this tab. */
  | { kind: 'signInWarned'; entryId: string }
  /** Move the login the banner names to the vault's recycle bin. */
  | { kind: 'removeLogin'; entryId: string }
  /** The first step of a two-step login was sent with this username. */
  | { kind: 'username'; username: string }
  /** The save offer waiting for this tab, if any. */
  | { kind: 'pendingSave' }
  /** Save it, with the username in the banner's field if it has one. */
  | { kind: 'save'; id: string; username?: string }
  | { kind: 'dismissSave'; id: string };

/** From the extension's own pages (the popup): the logins of `origin` changed. */
export type FromPage = { kind: 'loginsChanged'; origin: string };

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

/** A sign-in with a login filled from the vault that seems to have failed. */
export interface FailedSignIn {
  entryId: string;
  title: string;
  username: string;
}

export type SignInCheckReply = FailedSignIn | null;

export type RemoveReply = { ok: true } | { ok: false; problem: Problem };
