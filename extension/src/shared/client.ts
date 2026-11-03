// Talks to SSH Key Manager through its native messaging host
// (src-tauri/src/browser/host.rs). Everything but `hello`, `show`, `launch`
// and pairing is sealed with the keys from pairing.

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
import { forgetPairing, loadPairing, savePairing } from './keystore';

export const HOST = 'dev.sshkeymanager.autofill';

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
  /** From the host: the app isn't running. */
  | 'notRunning'
  | 'launchFailed'
  /** The browser can't start the host: autofill is off in the app, or no app. */
  | 'noHost'
  /** This browser isn't paired. */
  | 'unpaired';

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
  | { update: { origin: string; entryId: string; password: string } };

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

/** Starts the app when it isn't running. */
export async function launchApp(): Promise<Result<void>> {
  const reply = await native({ type: 'launch' });
  return reply.type === 'launched' ? { ok: true, value: undefined } : failure(reply);
}

export async function isPaired(): Promise<boolean> {
  return (await loadPairing()) !== null;
}

/** Sends a sealed request and opens the answer. */
export async function request<T>(action: Action): Promise<Result<T>> {
  const pairing = await loadPairing();
  if (!pairing) return { ok: false, problem: 'unpaired' };
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

/** Forgets the pairing here, and in the app if it can be reached. */
export async function disconnect(): Promise<void> {
  await request('disconnect');
  await forgetPairing();
}
