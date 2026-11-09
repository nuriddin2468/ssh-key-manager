// The background script: the only part of the extension that talks to the
// app for pages. It answers the content scripts, naming each page by the
// origin the browser gives for the sending frame, never by what the page or
// the content script says.
//
// A login typed into a form waits here (in `storage.session`, memory only)
// until the user answers the banner or closes the tab. It is offered for at
// most three minutes, only on pages of the site it was typed on, and dropped
// at the next look after that or once the tab shows another site; its
// password never goes back to a page.
//
// The username sent with the first step of a two-step login waits here too,
// for five minutes, to name a password sent next in the same tab on the same
// site without one.
//
// The login last filled in a tab waits here as well (no password), for ten
// minutes. A password-change form without a username field names its login
// by it, or by the site's only saved login. And if the user sent it and the
// tab shows the same site's sign-in form again within moments, the page asks
// whether to say the saved password may be out of date: once per login per
// tab.

import {
  type CheckResult,
  changeLogin,
  type LoginOffer,
  type Result,
  request,
  sameSite,
  unlockVault,
} from './shared/client';
import { ext } from './shared/ext';
import type {
  FillReply,
  FromPage,
  LoginsReply,
  PendingSaveReply,
  RemoveReply,
  SaveReply,
  SignInCheckReply,
  ToBackground,
  ToContent,
} from './shared/messages';
import { applyWanted } from './shared/suggestions';

const LOGINS_TTL = 10_000;
const PENDING_TTL = 3 * 60_000;
const USERNAME_TTL = 5 * 60_000;
/** How long the login filled in a tab names a password-change form's login. */
const FILLED_TTL = 10 * 60_000;
/** How soon after a sign-in was sent the sign-in form showing again counts as it failing. */
const SIGN_IN_FAILED_WITHIN = 20_000;
const MAX_FIELD = 4096;
/** Longest username taken from the banner or a two-step login's first step. */
const MAX_USERNAME = 256;

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

/** The username of a two-step login's first step, per tab. */
interface Step {
  origin: string;
  username: string;
  at: number;
}

/** The login last filled in a tab, per tab. */
interface Filled {
  origin: string;
  entryId: string;
  title: string;
  username: string;
  at: number;
  /** When the user sent the form with it. */
  sentAt?: number;
  /** Logins the "couldn't sign in?" banner was shown for in this tab. */
  warned: string[];
}

const logins = new Map<string, { at: number; reply: LoginsReply }>();

/**
 * The sending frame's web origin, or `null` for anything else. An opaque
 * origin (`null`: a sandboxed frame, a `data:` page) gets nothing, even when
 * the frame's URL is a site's. Only for a browser that doesn't report
 * origins (older Firefox) is the frame named by its URL; the content script
 * doesn't start in an opaque frame, so none asks that way.
 */
function originOf(sender: WebExt.MessageSender): string | null {
  let origin = sender.origin;
  if (origin === undefined) {
    if (!sender.url) return null;
    try {
      const url = new URL(sender.url);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
      origin = url.origin;
    } catch {
      return null;
    }
  }
  return /^https?:\/\/[^/]+$/.test(origin) ? origin : null;
}

/**
 * At most `burst` at once, then one per `interval` milliseconds, per tab.
 * The content script sends only logins the user put in and sent themselves
 * (content/typing.ts); this holds back anything else in the tab that sends
 * logins over and over, to learn from the banner whether a password is the
 * saved one.
 */
class RateLimit {
  private readonly tabs = new Map<number, { tokens: number; at: number }>();

  constructor(
    private readonly burst: number,
    private readonly interval: number,
  ) {}

  take(tabId: number, now = Date.now()): boolean {
    const last = this.tabs.get(tabId);
    const tokens = last
      ? Math.min(this.burst, last.tokens + (now - last.at) / this.interval)
      : this.burst;
    const allowed = tokens >= 1;
    this.tabs.set(tabId, { tokens: allowed ? tokens - 1 : tokens, at: now });
    return allowed;
  }

  forget(tabId: number): void {
    this.tabs.delete(tabId);
  }
}

const captures = new RateLimit(3, 1000);

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
  let expired = false;
  for (const [tab, pending] of Object.entries(all)) {
    if (now - pending.at > PENDING_TTL) {
      delete all[tab];
      expired = true;
    }
  }
  if (expired) await storePending(all);
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

async function loadSteps(): Promise<Record<string, Step>> {
  const stored = await ext.storage.session.get('steps');
  return (stored.steps ?? {}) as Record<string, Step>;
}

async function rememberUsername(tabId: number, origin: string, username: string): Promise<void> {
  const all = await loadSteps();
  all[tabId] = { origin, username, at: Date.now() };
  await ext.storage.session.set({ steps: all });
}

async function forgetUsername(tabId: number): Promise<void> {
  const all = await loadSteps();
  if (!(tabId in all)) return;
  delete all[tabId];
  await ext.storage.session.set({ steps: all });
}

async function loadFilled(): Promise<Record<string, Filled>> {
  const stored = await ext.storage.session.get('filled');
  return (stored.filled ?? {}) as Record<string, Filled>;
}

async function storeFilled(all: Record<string, Filled>): Promise<void> {
  await ext.storage.session.set({ filled: all });
}

/** Remembers the login filled in a tab, named by the vault's list for the page. */
async function rememberFilled(tabId: number, origin: string, entryId: string): Promise<void> {
  const list = await loginsFor(origin);
  const login = list.state === 'ready' ? list.logins.find((l) => l.id === entryId) : undefined;
  if (!login) return;
  const all = await loadFilled();
  const warned = all[tabId]?.warned ?? [];
  all[tabId] = {
    origin,
    entryId,
    title: login.title,
    username: login.username,
    at: Date.now(),
    warned,
  };
  await storeFilled(all);
}

async function signInSent(tabId: number, origin: string): Promise<void> {
  const all = await loadFilled();
  const filled = all[tabId];
  if (!filled || filled.origin !== origin || Date.now() - filled.at > FILLED_TTL) return;
  filled.sentAt = Date.now();
  await storeFilled(all);
}

/**
 * The login whose sign-in on this very origin was sent moments ago, unless
 * the banner was shown for it in this tab. The page then looks whether its
 * sign-in form is back.
 */
async function signInCheck(tabId: number, origin: string): Promise<SignInCheckReply> {
  const filled = (await loadFilled())[tabId];
  if (!filled?.sentAt || filled.origin !== origin) return null;
  if (Date.now() - filled.sentAt > SIGN_IN_FAILED_WITHIN) return null;
  if (filled.warned.includes(filled.entryId)) return null;
  return { entryId: filled.entryId, title: filled.title, username: filled.username };
}

async function signInWarned(tabId: number, entryId: string): Promise<void> {
  const all = await loadFilled();
  const filled = all[tabId];
  if (!filled || filled.entryId !== entryId) return;
  filled.sentAt = undefined;
  if (!filled.warned.includes(entryId)) filled.warned.push(entryId);
  await storeFilled(all);
}

/** Moves the login the "couldn't sign in?" banner named in this tab to the recycle bin. */
async function removeWarned(tabId: number, origin: string, entryId: string): Promise<RemoveReply> {
  const filled = (await loadFilled())[tabId];
  // Only the login the banner was shown for, on its own page.
  if (!filled || filled.origin !== origin || !filled.warned.includes(entryId)) {
    return { ok: false, problem: 'expired' };
  }
  const result = await changeLogin(origin, { remove: { entryId } });
  logins.delete(origin);
  return result.ok ? { ok: true } : { ok: false, problem: result.problem };
}

/**
 * The username of a password-change form that names none: that of the login
 * filled in this tab lately on this origin, else that of the site's only
 * saved login. Empty if neither.
 */
async function changedUsername(tabId: number, origin: string): Promise<string> {
  const filled = (await loadFilled())[tabId];
  if (filled && filled.origin === origin && Date.now() - filled.at <= FILLED_TTL) {
    return filled.username;
  }
  const list = await loginsFor(origin);
  if (list.state === 'ready' && list.logins.length === 1) return list.logins[0]?.username ?? '';
  return '';
}

/** The username sent just before in this tab, on the same site as `origin`; empty if none. */
async function usernameBefore(tabId: number, origin: string): Promise<string> {
  const step = (await loadSteps())[tabId];
  if (!step || Date.now() - step.at > USERNAME_TTL) return '';
  const same = step.origin === origin || (await sameSite(step.origin, origin).catch(() => false));
  return same ? step.username : '';
}

/**
 * Keeps a typed login for the banner, if the vault doesn't have it as typed.
 * One sent without a username takes the one the tab sent just before on the
 * same site, if any: the first step of a two-step login.
 */
async function capture(
  tabId: number,
  origin: string,
  typed: string,
  password: string,
  change = false,
) {
  if (!password) return;
  let username = typed || (await usernameBefore(tabId, origin));
  if (!username && change) username = await changedUsername(tabId, origin);
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

/**
 * The save offer for the tab's top page at `origin`. One typed on another
 * site (a sign-in that sent the tab on, or a sign-in frame) names only that
 * site: its username and the saved login's title are not this page's
 * business. Unless the app says the sites are the same, they count as
 * different.
 */
async function pendingFor(tabId: number, origin: string): Promise<PendingSaveReply> {
  const pending = (await loadPending())[tabId];
  if (!pending) return null;
  const site = new URL(pending.origin).host;
  // The app knows the Public Suffix List, so it tells what a site is.
  const same =
    pending.origin === origin || (await sameSite(pending.origin, origin).catch(() => false));
  if (!same) {
    return { id: pending.id, site, username: '', mode: pending.mode, elsewhere: true };
  }
  return {
    id: pending.id,
    site,
    username: pending.username,
    mode: pending.mode,
    title: pending.title,
  };
}

/**
 * Saves or updates the waiting login, checking again first: the vault may
 * have changed, and the user may have changed the username in the banner
 * (`typed`; none for a banner without the field).
 */
async function save(tabId: number, id: string, typed?: string): Promise<SaveReply> {
  const pending = (await loadPending())[tabId];
  if (!pending || pending.id !== id) return { ok: false, problem: 'expired' };
  const { origin, password } = pending;
  const username = typed ?? pending.username;
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
  await forgetUsername(tabId);
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
      await unlockVault();
      return null;
    case 'capture':
      if (isString(message.username) && isString(message.password) && captures.take(tabId)) {
        const change = message.change === true;
        await capture(tabId, origin, message.username.trim(), message.password, change);
      }
      return null;
    case 'filled':
      if (isString(message.entryId, 64)) await rememberFilled(tabId, origin, message.entryId);
      return null;
    case 'signInSent':
      await signInSent(tabId, origin);
      return null;
    case 'signInCheck':
      return frameId === 0 ? signInCheck(tabId, origin) : null;
    case 'signInWarned':
      if (isString(message.entryId, 64)) await signInWarned(tabId, message.entryId);
      return null;
    case 'removeLogin':
      if (!isString(message.entryId, 64) || frameId !== 0) return { ok: false, problem: 'invalid' };
      return removeWarned(tabId, origin, message.entryId);
    case 'username':
      if (isString(message.username, MAX_USERNAME) && message.username.trim()) {
        await rememberUsername(tabId, origin, message.username.trim());
      }
      return null;
    case 'pendingSave':
      return frameId === 0 ? pendingFor(tabId, origin) : null;
    case 'save': {
      if (!isString(message.id, 64)) return null;
      const typed = isString(message.username, MAX_USERNAME) ? message.username.trim() : undefined;
      return save(tabId, message.id, typed);
    }
    case 'dismissSave':
      if (isString(message.id, 64)) await dropPending(tabId, message.id);
      return null;
    default:
      return null;
  }
}

/** Whether `sender` is one of the extension's own pages, such as the popup. */
function fromOwnPage(sender: WebExt.MessageSender): boolean {
  return (
    sender.id === ext.runtime.id &&
    sender.tab === undefined &&
    typeof sender.url === 'string' &&
    sender.url.startsWith(ext.runtime.getURL(''))
  );
}

ext.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (fromOwnPage(sender)) {
    const page = message as Partial<FromPage> | null;
    if (page?.kind === 'loginsChanged' && typeof page.origin === 'string') {
      logins.delete(page.origin);
    }
    return false;
  }
  const origin = originOf(sender);
  const tabId = sender.tab?.id;
  if (sender.id !== ext.runtime.id || origin === null || tabId === undefined) return false;
  if (typeof message !== 'object' || message === null || !('kind' in message)) return false;
  handle(message as ToBackground, origin, tabId, sender.frameId ?? 0).then(sendResponse, () =>
    sendResponse(null),
  );
  return true;
});

// The popup may have closed while the browser asked for the permission.
ext.permissions.onAdded.addListener((added) => {
  if (added.permissions?.includes('privacy')) void applyWanted();
});

ext.tabs.onRemoved.addListener((tabId) => {
  captures.forget(tabId);
  void dropPending(tabId);
  void forgetUsername(tabId);
  void loadFilled().then((all) => {
    if (!(tabId in all)) return;
    delete all[tabId];
    return storeFilled(all);
  });
});
