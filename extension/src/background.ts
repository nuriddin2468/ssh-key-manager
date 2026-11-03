// The background script: the only part of the extension that talks to the
// app for pages. It answers the content scripts, naming each page by the
// origin the browser gives for the sending frame, never by what the page or
// the content script says.
//
// A login typed into a form waits here (in `storage.session`, memory only)
// until the user answers the banner, for at most three minutes; its
// password never goes back to a page.

import { type CheckResult, type LoginOffer, type Result, request, showApp } from './shared/client';
import { ext } from './shared/ext';
import type {
  FillReply,
  LoginsReply,
  PendingSaveReply,
  SaveReply,
  ToBackground,
  ToContent,
} from './shared/messages';

const LOGINS_TTL = 10_000;
const PENDING_TTL = 3 * 60_000;
const MAX_FIELD = 4096;

interface Pending {
  id: string;
  tabId: number;
  origin: string;
  username: string;
  password: string;
  mode: 'save' | 'update';
  entryId?: string;
  title?: string;
  at: number;
}

const logins = new Map<string, { at: number; reply: LoginsReply }>();

/** The sending frame's web origin, or `null` for anything else. */
function originOf(sender: WebExt.MessageSender): string | null {
  let origin = sender.origin;
  if (!origin || origin === 'null') {
    try {
      origin = sender.url ? new URL(sender.url).origin : undefined;
    } catch {
      return null;
    }
  }
  return origin && /^https?:\/\/[^/]+$/.test(origin) ? origin : null;
}

function isString(value: unknown, max = MAX_FIELD): value is string {
  return typeof value === 'string' && value.length <= max;
}

async function loginsFor(origin: string): Promise<LoginsReply> {
  const cached = logins.get(origin);
  if (cached && Date.now() - cached.at < LOGINS_TTL) return cached.reply;
  const result = await request<{ logins: LoginOffer[] }>({ logins: { origin } });
  let reply: LoginsReply;
  if (result.ok) reply = { state: 'ready', logins: result.value.logins };
  else if (result.problem === 'locked') reply = { state: 'locked' };
  else reply = { state: 'off' };
  if (reply.state === 'ready') logins.set(origin, { at: Date.now(), reply });
  else logins.delete(origin);
  return reply;
}

async function loadPending(): Promise<Record<string, Pending>> {
  const stored = await ext.storage.session.get('pending');
  const all = (stored.pending ?? {}) as Record<string, Pending>;
  const now = Date.now();
  for (const [tab, pending] of Object.entries(all)) {
    if (now - pending.at > PENDING_TTL) delete all[tab];
  }
  return all;
}

async function storePending(all: Record<string, Pending>): Promise<void> {
  await ext.storage.session.set({ pending: all });
}

async function dropPending(tabId: number, id?: string): Promise<void> {
  const all = await loadPending();
  const pending = all[tabId];
  if (pending && (id === undefined || pending.id === id)) {
    delete all[tabId];
    await storePending(all);
  }
}

/** Keeps a typed login for the banner, if the vault doesn't have it as typed. */
async function capture(tabId: number, origin: string, username: string, password: string) {
  if (!password) return;
  const check = await request<CheckResult>({ check: { origin, username, password } });
  if (!check.ok && check.problem !== 'locked') return;
  if (check.ok && check.value.status === 'saved') {
    await dropPending(tabId);
    return;
  }
  const update = check.ok && check.value.status === 'update' ? check.value : null;
  const all = await loadPending();
  all[tabId] = {
    id: crypto.randomUUID(),
    tabId,
    origin,
    username,
    password,
    mode: update ? 'update' : 'save',
    entryId: update?.entryId,
    title: update?.title,
    at: Date.now(),
  };
  await storePending(all);
  const offer: ToContent = { kind: 'offerSave' };
  await ext.tabs.sendMessage(tabId, offer, { frameId: 0 }).catch(() => undefined);
}

async function pendingFor(tabId: number): Promise<PendingSaveReply> {
  const pending = (await loadPending())[tabId];
  if (!pending) return null;
  return {
    id: pending.id,
    site: new URL(pending.origin).host,
    username: pending.username,
    mode: pending.mode,
    title: pending.title,
  };
}

/** Saves or updates the waiting login, checking again first: the vault may have changed. */
async function save(tabId: number, id: string): Promise<SaveReply> {
  const pending = (await loadPending())[tabId];
  if (!pending || pending.id !== id) return { ok: false, problem: 'expired' };
  const { origin, username, password } = pending;
  const check = await request<CheckResult>({ check: { origin, username, password } });
  if (!check.ok) return { ok: false, problem: check.problem };
  let done: Result<unknown> = { ok: true, value: null };
  let mode: 'save' | 'update' = 'save';
  if (check.value.status === 'new') {
    done = await request({ save: { origin, username, password } });
  } else if (check.value.status === 'update') {
    mode = 'update';
    done = await request({ update: { origin, entryId: check.value.entryId, password } });
  }
  if (!done.ok) return { ok: false, problem: done.problem };
  await dropPending(tabId, id);
  logins.delete(origin);
  return { ok: true, mode };
}

async function handle(
  message: ToBackground,
  origin: string,
  tabId: number,
  frameId: number,
): Promise<unknown> {
  switch (message.kind) {
    case 'logins':
      return loginsFor(origin);
    case 'fill': {
      if (!isString(message.entryId, 64)) return { ok: false, problem: 'invalid' };
      const result = await request<{ username: string; password: string }>({
        fill: { origin, entryId: message.entryId },
      });
      const reply: FillReply = result.ok
        ? { ok: true, username: result.value.username, password: result.value.password }
        : { ok: false, problem: result.problem };
      return reply;
    }
    case 'unlock':
      logins.delete(origin);
      await showApp();
      return null;
    case 'capture':
      if (isString(message.username) && isString(message.password)) {
        await capture(tabId, origin, message.username.trim(), message.password);
      }
      return null;
    case 'pendingSave':
      return frameId === 0 ? pendingFor(tabId) : null;
    case 'save':
      return isString(message.id, 64) ? save(tabId, message.id) : null;
    case 'dismissSave':
      if (isString(message.id, 64)) await dropPending(tabId, message.id);
      return null;
    default:
      return null;
  }
}

ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const origin = originOf(sender);
  const tabId = sender.tab?.id;
  if (sender.id !== ext.runtime.id || origin === null || tabId === undefined) return false;
  if (typeof message !== 'object' || message === null || !('kind' in message)) return false;
  handle(message as ToBackground, origin, tabId, sender.frameId ?? 0).then(sendResponse, () =>
    sendResponse(null),
  );
  return true;
});

ext.tabs.onRemoved.addListener((tabId) => {
  void dropPending(tabId);
});
