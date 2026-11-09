// Talks to SSH Key Manager through its native messaging host
// (src-tauri/src/browser/host.rs). Everything but `hello`, `show`,
// `unlock`, `sameSite`, `launch` and pairing is sealed with the keys from
// pairing.
//
// The keys change once a day (`Action::Rekey` in protocol.rs). The app
// keeps the old ones, retired, and takes a request sealed with one after
// that for a copy of them: it forgets the pairing. So no request may be
// on its way with the old keys once the new ones are in use. A Web Lock,
// which the background and the extension's pages share, keeps every
// request out while the keys change.

import {
  deriveKeyBytes,
  fromBase64,
  importKeys,
  newClientId,
  newKeyPair,
  openResponse,
  pairingCode,
  randomBytes,
  sealRequest,
  toBase64,
} from './channel';
import { browserName, ext } from './ext';
import { forgetPairing, loadPairing, type Pairing, savePairing } from './keystore';

export const HOST = 'dev.sshkeymanager.autofill';

/** The Web Lock held while the keys are used (shared) or change (exclusive). */
const KEYS_LOCK = 'sshkm-autofill-keys';
/** How old the keys get before they change. */
const KEYS_LAST = 24 * 60 * 60_000;
/** After a change failed (an older app, a locked vault), the next try waits this long. */
const REKEY_RETRY = 60 * 60_000;
let rekeyTried = 0;
/** While requests are on their way, a change waits for them this many times, this long. */
const RENEW_TRIES = 5;
const RENEW_PAUSE = 2000;

/** Why a request failed. The first ones come from the app (protocol.rs). */
export type Problem =
  | 'locked'
  | 'noVault'
  | 'unknownClient'
  | 'denied'
  | 'expired'
  | 'busy'
  | 'notFound'
  | 'invalid'
  | 'failed'
  /** The app saw a copy of this browser's old keys in use, and forgot the pairing. */
  | 'revoked'
  /** Too many logins checked, fills asked about or unlocks asked for, in the last minute. */
  | 'tooMany'
  /** From the host: the app isn't running. */
  | 'notRunning'
  | 'launchFailed'
  /** The browser can't start the host: autofill is off in the app, or no app. */
  | 'noHost'
  /** This browser isn't paired. */
  | 'unpaired'
  /** The app is too old for the request: it doesn't know the action. */
  | 'outdatedApp';

export type Result<T> = { ok: true; value: T } | { ok: false; problem: Problem };

export type VaultLock = 'missing' | 'locked' | 'unlocked';

export interface LoginOffer {
  id: string;
  title: string;
  username: string;
  /** Saved for this very host, not just the same site. */
  exact: boolean;
}

export type CheckResult =
  | { status: 'new' }
  | { status: 'update'; entryId: string; title: string }
  | { status: 'saved' };

/** What a sealed request can ask; see `Action` in protocol.rs. */
export type Action =
  | 'status'
  | 'disconnect'
  | { logins: { origin: string } }
  | { fill: { origin: string; entryId: string } }
  | { check: { origin: string; username: string; password: string } }
  | { save: { origin: string; username: string; password: string } }
  | { update: { origin: string; entryId: string; password: string } }
  | { edit: { origin: string; entryId: string; username?: string; password?: string } }
  | { remove: { origin: string; entryId: string } }
  | { rekey: { publicKey: string } };

type Reply = { type: string; code?: Problem; [key: string]: unknown };

async function native(message: object): Promise<Reply> {
  try {
    const reply = await ext.runtime.sendNativeMessage(HOST, message);
    if (typeof reply === 'object' && reply !== null && 'type' in reply) return reply as Reply;
    return { type: 'error', code: 'failed' };
  } catch (error) {
    const text = String((error as Error)?.message ?? error);
    const missing = /not found|forbidden|No such native application|not allowed/i.test(text);
    return { type: 'error', code: missing ? 'noHost' : 'failed' };
  }
}

function failure(reply: Reply): { ok: false; problem: Problem } {
  return { ok: false, problem: reply.code ?? 'failed' };
}

/** Is the app there, and is its vault locked? Needs no pairing. */
export async function hello(): Promise<Result<VaultLock>> {
  const reply = await native({ type: 'hello' });
  if (reply.type !== 'hello') return failure(reply);
  return { ok: true, value: reply.vault as VaultLock };
}

/** Brings the app forward on the vault so the user can unlock it. */
export async function showApp(): Promise<void> {
  await native({ type: 'show' });
}

/**
 * Asks the app to unlock the vault without its main window: with Touch ID or
 * Windows Hello, or in a small window of the app's own. The master password
 * is typed there and never comes here. An app from before that, which doesn't
 * know the message, comes forward instead. Answers at once.
 */
export async function unlockVault(): Promise<void> {
  const reply = await native({ type: 'unlock' });
  if (reply.type === 'error' && reply.code === 'invalid') await showApp();
}

/**
 * Whether a login typed on `origin` belongs on `page` too: the same site, by
 * the rules the app offers logins by. Needs no pairing. False if the app
 * can't be asked.
 */
export async function sameSite(origin: string, page: string): Promise<boolean> {
  const reply = await native({ type: 'sameSite', origin, page });
  return reply.type === 'sameSite' && reply.same === true;
}

/** Starts the app when it isn't running. */
export async function launchApp(): Promise<Result<void>> {
  const reply = await native({ type: 'launch' });
  return reply.type === 'launched' ? { ok: true, value: undefined } : failure(reply);
}

export async function isPaired(): Promise<boolean> {
  return (await loadPairing()) !== null;
}

/** The Web Locks of the extension's origin; none in tests. */
function locks(): LockManager | undefined {
  return (globalThis.navigator as Navigator | undefined)?.locks;
}

/**
 * Sends a sealed request and opens the answer. Changes the keys afterwards
 * once they are a day old.
 */
export async function request<T>(action: Action): Promise<Result<T>> {
  const sendNow = async () => {
    const pairing = await loadPairing();
    const result: Result<T> = pairing
      ? await send<T>(pairing, action)
      : { ok: false, problem: 'unpaired' };
    return { pairing, result };
  };
  const manager = locks();
  const { pairing, result } = manager
    ? await manager.request(KEYS_LOCK, { mode: 'shared' }, sendNow)
    : await sendNow();
  if (!result.ok && result.problem === 'revoked') await forgetPairing();
  if (result.ok && pairing && keysDue(pairing) && action !== 'disconnect') {
    void renewKeys().catch(() => undefined);
  }
  return result;
}

function keysDue(pairing: Pairing, now = Date.now()): boolean {
  return now - (pairing.keysAt ?? pairing.pairedAt) >= KEYS_LAST && now - rekeyTried >= REKEY_RETRY;
}

/** While this page is changing the keys, or waiting to. */
let renewing = false;

/**
 * Changes the keys, if they are due, once no request uses them: it tries
 * again a few times rather than hold up requests while one waits for the
 * user. Without Web Locks it doesn't: another page could have a request on
 * its way.
 */
async function renewKeys(): Promise<void> {
  const manager = locks();
  if (!manager || renewing) return;
  renewing = true;
  try {
    for (let attempt = 0; attempt < RENEW_TRIES; attempt += 1) {
      if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, RENEW_PAUSE));
      const done = await manager.request(
        KEYS_LOCK,
        { mode: 'exclusive', ifAvailable: true },
        async (held) => {
          if (held) await renewHeld();
          return held !== null;
        },
      );
      if (done) return;
    }
  } finally {
    renewing = false;
  }
}

/** Changes the keys, if they are still due; the exclusive lock is held. */
async function renewHeld(): Promise<void> {
  const pairing = await loadPairing();
  if (!pairing || !keysDue(pairing)) return;
  rekeyTried = Date.now();
  const { privateKey, publicKey } = await newKeyPair();
  const reply = await send<{ publicKey: string }>(pairing, {
    rekey: { publicKey: toBase64(publicKey) },
  });
  if (!reply.ok) return;
  const keys = await importKeys(
    await deriveKeyBytes(
      privateKey,
      pairing.clientId,
      publicKey,
      fromBase64(reply.value.publicKey),
    ),
  );
  const renewed: Pairing = { ...pairing, ...keys, keysAt: Date.now() };
  await savePairing(renewed);
  // The first request with the new keys makes them the app's current ones.
  await send(renewed, 'status');
}

/** Seals `action` with `pairing`'s keys, sends it and opens the answer. */
async function send<T>(pairing: Pairing, action: Action): Promise<Result<T>> {
  const plain = new TextEncoder().encode(JSON.stringify({ sentAt: Date.now(), action }));
  const { nonce, sealed } = await sealRequest(pairing, pairing.clientId, plain);
  plain.fill(0);
  const reply = await native({
    type: 'request',
    clientId: pairing.clientId,
    nonce: toBase64(nonce),
    payload: toBase64(sealed),
  });
  if (reply.type !== 'response') return failure(reply);
  try {
    const opened = await openResponse(
      pairing,
      pairing.clientId,
      nonce,
      fromBase64(String(reply.nonce)),
      fromBase64(String(reply.payload)),
    );
    const value = JSON.parse(new TextDecoder().decode(opened)) as T;
    opened.fill(0);
    return { ok: true, value };
  } catch {
    return { ok: false, problem: 'invalid' };
  }
}

/**
 * Pairs with the app: shows `onCode`'s code, then waits until the user
 * decides in the app (up to two minutes).
 */
export async function pair(onCode: (code: string) => void): Promise<Result<void>> {
  const clientId = newClientId();
  const { privateKey, publicKey } = await newKeyPair();
  onCode(await pairingCode(clientId, publicKey));
  const nonce = randomBytes(12);
  const reply = await native({
    type: 'pair',
    clientId,
    publicKey: toBase64(publicKey),
    nonce: toBase64(nonce),
    browser: browserName(),
  });
  if (reply.type !== 'paired') return failure(reply);
  try {
    const appPublic = fromBase64(String(reply.publicKey));
    const keys = await importKeys(await deriveKeyBytes(privateKey, clientId, publicKey, appPublic));
    const info = await openResponse(
      keys,
      clientId,
      nonce,
      fromBase64(String(reply.nonce)),
      fromBase64(String(reply.payload)),
    );
    if (!(JSON.parse(new TextDecoder().decode(info)) as { paired?: boolean }).paired) {
      return { ok: false, problem: 'invalid' };
    }
    await savePairing({ ...keys, clientId, pairedAt: Date.now() });
    return { ok: true, value: undefined };
  } catch {
    return { ok: false, problem: 'invalid' };
  }
}

/** A change to a saved login of `origin`'s site. */
export type LoginChange =
  | { edit: { entryId: string; username?: string; password?: string } }
  | { remove: { entryId: string } };

/**
 * Edits or removes (to the vault's recycle bin) a login of `origin`'s site.
 * The app checks that the login belongs there. An app from before these
 * actions can't read the request and answers `invalid`: that is
 * `outdatedApp`, to say the app needs an update.
 */
export async function changeLogin(origin: string, change: LoginChange): Promise<Result<void>> {
  const action: Action =
    'edit' in change
      ? { edit: { origin, ...change.edit } }
      : { remove: { origin, entryId: change.remove.entryId } };
  const result = await request<{ entryId: string }>(action);
  if (result.ok) return { ok: true, value: undefined };
  return { ok: false, problem: result.problem === 'invalid' ? 'outdatedApp' : result.problem };
}

/** Forgets the pairing here, and in the app if it can be reached. */
export async function disconnect(): Promise<void> {
  await request('disconnect');
  await forgetPairing();
}
