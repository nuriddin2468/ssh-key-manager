import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import './background';

type Listener = (
  message: unknown,
  sender: WebExt.MessageSender,
  respond: (response?: unknown) => void,
) => boolean | undefined;

// The browser, as far as the background uses it; set up before it loads.
const world = vi.hoisted(() => {
  const state = { listener: null as Listener | null, session: {} as Record<string, unknown> };
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: {
      id: 'ext',
      onMessage: {
        addListener: (listener: Listener) => {
          state.listener = listener;
        },
      },
    },
    storage: {
      session: {
        get: async (key: string) => ({ [key]: structuredClone(state.session[key]) }),
        set: async (items: Record<string, unknown>) => {
          Object.assign(state.session, structuredClone(items));
        },
      },
    },
    tabs: { sendMessage: async () => undefined, onRemoved: { addListener: () => undefined } },
    permissions: { onAdded: { addListener: () => undefined } },
  };
  return state;
});

const client = vi.hoisted(() => ({
  request: vi.fn(),
  sameSite: vi.fn(),
  showApp: vi.fn(),
  unlockVault: vi.fn(),
  changeLogin: vi.fn(),
}));
vi.mock('./shared/client', () => client);

/** Sends a message from a content script; resolves with its answer, or `'refused'`. */
function send(message: unknown, sender: WebExt.MessageSender): Promise<unknown> {
  return new Promise((resolve) => {
    const full = { id: 'ext', tab: { id: 1 }, frameId: 0, ...sender };
    if (!world.listener?.(message, full, resolve)) resolve('refused');
  });
}

function checks(): number {
  return client.request.mock.calls.filter(([action]) => 'check' in action).length;
}

beforeEach(() => {
  world.session = {};
  client.request.mockReset();
  client.request.mockResolvedValue({ ok: true, value: { status: 'saved', logins: [] } });
  client.sameSite.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
});

describe('which page is asking', () => {
  it('names a frame by the origin the browser reports', async () => {
    const reply = await send(
      { kind: 'logins' },
      { origin: 'https://bank.example', url: 'https://bank.example/login' },
    );
    expect(reply).toEqual({ state: 'ready', logins: [] });
    expect(client.request).toHaveBeenCalledWith({ logins: { origin: 'https://bank.example' } });
  });

  it('gives an opaque frame nothing, whatever its URL', async () => {
    for (const sender of [
      { origin: 'null', url: 'https://bank.example/sandboxed' },
      { origin: '', url: 'https://bank.example/' },
      { origin: 'chrome-extension://abc', url: 'chrome-extension://abc/page.html' },
    ]) {
      expect(await send({ kind: 'logins' }, sender), JSON.stringify(sender)).toBe('refused');
    }
    expect(client.request).not.toHaveBeenCalled();
  });

  it('falls back to the URL only where the browser reports no origin', async () => {
    await send({ kind: 'logins' }, { url: 'https://shop.example/cart' });
    expect(client.request).toHaveBeenCalledWith({ logins: { origin: 'https://shop.example' } });
    for (const url of ['blob:https://shop.example/0b1c', 'data:text/html,hi', 'about:blank']) {
      expect(await send({ kind: 'logins' }, { url }), url).toBe('refused');
    }
    expect(await send({ kind: 'logins' }, {})).toBe('refused');
  });
});

describe('unlocking', () => {
  it('asks the app to unlock without its main window', async () => {
    client.unlockVault.mockReset();
    client.showApp.mockReset();
    const bank = { origin: 'https://bank.example', url: 'https://bank.example/login' };
    expect(await send({ kind: 'unlock' }, bank)).toBeNull();
    expect(client.unlockVault).toHaveBeenCalledTimes(1);
    expect(client.showApp).not.toHaveBeenCalled();
  });
});

describe('typed logins', () => {
  const typed = { kind: 'capture', username: 'alice', password: 'hunter2' };
  const bank = { origin: 'https://bank.example', url: 'https://bank.example/login' };

  it('are checked a few at a time per tab, then once a second', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(1_000_000);
    for (let i = 0; i < 5; i += 1) await send(typed, { ...bank, tab: { id: 7 } });
    expect(checks()).toBe(3);
    await send(typed, { ...bank, tab: { id: 8 } });
    expect(checks()).toBe(4);
    vi.setSystemTime(1_001_000);
    await send(typed, { ...bank, tab: { id: 7 } });
    await send(typed, { ...bank, tab: { id: 7 } });
    expect(checks()).toBe(5);
  });

  it('without a username take the one sent just before on the same site', async () => {
    client.request.mockResolvedValue({ ok: true, value: { status: 'new' } });
    client.sameSite.mockImplementation(async (_origin: string, page: string) =>
      page.endsWith('.bank.example'),
    );
    const login = { origin: 'https://login.bank.example', tab: { id: 3 } };
    await send({ kind: 'username', username: ' alice ' }, login);
    await send(
      { kind: 'capture', username: '', password: 'hunter2' },
      {
        origin: 'https://www.bank.example',
        tab: { id: 3 },
      },
    );
    expect(client.request).toHaveBeenLastCalledWith({
      check: { origin: 'https://www.bank.example', username: 'alice', password: 'hunter2' },
    });
    // Not on another site, and not in another tab.
    await send(
      { kind: 'capture', username: '', password: 'hunter3' },
      {
        origin: 'https://evil.example',
        tab: { id: 3 },
      },
    );
    expect(client.request).toHaveBeenLastCalledWith({
      check: { origin: 'https://evil.example', username: '', password: 'hunter3' },
    });
    await send(
      { kind: 'capture', username: '', password: 'hunter4' },
      {
        origin: 'https://www.bank.example',
        tab: { id: 4 },
      },
    );
    expect(client.request).toHaveBeenLastCalledWith({
      check: { origin: 'https://www.bank.example', username: '', password: 'hunter4' },
    });
  });

  it('are saved with the username the user put in the banner', async () => {
    world.session.pending = {
      1: {
        id: 'p1',
        tabId: 1,
        origin: 'https://bank.example',
        username: '',
        password: 'hunter2',
        mode: 'save',
        at: Date.now(),
      },
    };
    client.request.mockResolvedValue({ ok: true, value: { status: 'new' } });
    const reply = await send({ kind: 'save', id: 'p1', username: ' alice ' }, bank);
    expect(reply).toEqual({ ok: true, mode: 'save' });
    expect(client.request).toHaveBeenLastCalledWith({
      save: { origin: 'https://bank.example', username: 'alice', password: 'hunter2' },
    });
  });

  it('are saved as typed where they were typed, whichever page answers the banner', async () => {
    const bankFrame = { origin: 'https://bank.example', frameId: 5, tab: { id: 31 } };
    const newsTop = { origin: 'https://news.example', frameId: 0, tab: { id: 31 } };
    client.sameSite.mockResolvedValue(false);
    client.request.mockImplementation(async (action: Record<string, unknown>) => {
      const check = action.check as { username: string } | undefined;
      if (check?.username === 'admin') {
        return { ok: true, value: { status: 'update', entryId: 'bank-admin', title: 'Admin' } };
      }
      if (check) return { ok: true, value: { status: 'new' } };
      return { ok: true, value: { entryId: 'x' } };
    });
    // Typed in the bank's sign-in frame, on a page of another site.
    await send({ kind: 'capture', username: 'alice', password: 'typed' }, bankFrame);
    const offer = (await send({ kind: 'pendingSave' }, newsTop)) as { id: string };
    expect(offer).toMatchObject({ site: 'bank.example', username: '', elsewhere: true });

    // Only the top frame answers the banner.
    expect(await send({ kind: 'save', id: offer.id }, { ...newsTop, frameId: 2 })).toBeNull();
    await send({ kind: 'dismissSave', id: offer.id }, { ...newsTop, frameId: 2 });
    expect(client.request).not.toHaveBeenCalledWith(
      expect.objectContaining({ save: expect.anything() }),
    );

    // That page has no username field: a username from it counts for nothing.
    const reply = await send({ kind: 'save', id: offer.id, username: 'admin' }, newsTop);
    expect(reply).toEqual({ ok: true, mode: 'save' });
    expect(client.request).not.toHaveBeenCalledWith(
      expect.objectContaining({ update: expect.anything() }),
    );
    expect(client.request).toHaveBeenLastCalledWith({
      save: { origin: 'https://bank.example', username: 'alice', password: 'typed' },
    });
  });

  it('keep a username the vault supplied off the page, and use it unless one is typed', async () => {
    const site = { origin: 'https://store.example', tab: { id: 32 } };
    client.request.mockImplementation(async (action: Record<string, unknown>) => {
      if ('logins' in action) {
        return {
          ok: true,
          value: { logins: [{ id: 'e1', title: 'Shop', username: 'bob', exact: true }] },
        };
      }
      if ('check' in action)
        return { ok: true, value: { status: 'update', entryId: 'e1', title: 'Shop' } };
      return { ok: true, value: { entryId: 'e1' } };
    });
    // A password-change form with no username field.
    await send({ kind: 'capture', username: '', password: 'new1', change: true }, site);
    const offer = (await send({ kind: 'pendingSave' }, site)) as { id: string };
    expect(offer).toEqual({
      id: offer.id,
      site: 'store.example',
      username: '',
      mode: 'update',
      title: 'Shop',
      fromVault: true,
    });
    // The banner's field left empty: the vault's login is updated.
    await send({ kind: 'save', id: offer.id, username: '' }, site);
    expect(client.request).toHaveBeenCalledWith({
      check: { origin: 'https://store.example', username: 'bob', password: 'new1' },
    });
    expect(client.request).toHaveBeenLastCalledWith({
      update: { origin: 'https://store.example', entryId: 'e1', password: 'new1' },
    });
  });

  it('are offered in full only on pages of the site they were typed on', async () => {
    world.session.pending = {
      1: {
        id: 'p1',
        tabId: 1,
        origin: 'https://accounts.bank.example',
        username: 'alice',
        password: 'hunter2',
        mode: 'save',
        at: Date.now(),
      },
    };
    client.sameSite.mockImplementation(async (_origin: string, page: string) =>
      page.endsWith('.bank.example'),
    );
    const offer = { id: 'p1', site: 'accounts.bank.example', username: 'alice', mode: 'save' };

    const pending = { kind: 'pendingSave' };
    expect(await send(pending, { origin: 'https://accounts.bank.example' })).toEqual(offer);
    expect(client.sameSite).not.toHaveBeenCalled();
    expect(await send(pending, { origin: 'https://www.bank.example' })).toEqual(offer);
    expect(client.sameSite).toHaveBeenCalledWith(
      'https://accounts.bank.example',
      'https://www.bank.example',
    );
    expect(await send(pending, { origin: 'https://www.bank.example', frameId: 3 })).toBeNull();

    // The tab went to another site (a sign-in that sends you on): that page
    // learns the site's name only, and the offer stays for the site itself.
    expect(await send(pending, { origin: 'https://evil.example' })).toEqual({
      id: 'p1',
      site: 'accounts.bank.example',
      username: '',
      mode: 'save',
      elsewhere: true,
    });
    expect(await send(pending, { origin: 'https://accounts.bank.example' })).toEqual(offer);

    // When the app can't say (an older app, or not running), the sites differ.
    client.sameSite.mockRejectedValue(new Error('unknown message'));
    expect(await send(pending, { origin: 'https://www.bank.example' })).toMatchObject({
      username: '',
      elsewhere: true,
    });
  });
});

describe('a sign-in with a filled login', () => {
  const bank = { origin: 'https://bank.example', url: 'https://bank.example/login' };
  const offer = { id: 'e1', title: 'Bank', username: 'alice', exact: true };

  beforeEach(() => {
    client.request.mockImplementation(async (action: object) =>
      'logins' in action
        ? { ok: true, value: { logins: [offer] } }
        : { ok: true, value: { status: 'new' } },
    );
    client.changeLogin.mockReset();
    client.changeLogin.mockResolvedValue({ ok: true, value: undefined });
  });

  it('that comes back is said once per login and tab', async () => {
    await send({ kind: 'filled', entryId: 'e1' }, { ...bank, tab: { id: 11 } });
    // Not sent yet: nothing to say.
    expect(await send({ kind: 'signInCheck' }, { ...bank, tab: { id: 11 } })).toBeNull();
    await send({ kind: 'signInSent' }, { ...bank, tab: { id: 11 } });
    const failed = { entryId: 'e1', title: 'Bank', username: 'alice' };
    expect(await send({ kind: 'signInCheck' }, { ...bank, tab: { id: 11 } })).toEqual(failed);
    // Only for this very origin, in this tab, in the top frame.
    expect(
      await send({ kind: 'signInCheck' }, { origin: 'https://www.bank.example', tab: { id: 11 } }),
    ).toBeNull();
    expect(await send({ kind: 'signInCheck' }, { ...bank, tab: { id: 12 } })).toBeNull();
    expect(
      await send({ kind: 'signInCheck' }, { ...bank, tab: { id: 11 }, frameId: 2 }),
    ).toBeNull();

    await send({ kind: 'signInWarned', entryId: 'e1' }, { ...bank, tab: { id: 11 } });
    expect(await send({ kind: 'signInCheck' }, { ...bank, tab: { id: 11 } })).toBeNull();
    // Filled and sent again: still not said twice.
    await send({ kind: 'filled', entryId: 'e1' }, { ...bank, tab: { id: 11 } });
    await send({ kind: 'signInSent' }, { ...bank, tab: { id: 11 } });
    expect(await send({ kind: 'signInCheck' }, { ...bank, tab: { id: 11 } })).toBeNull();
  });

  it('is forgotten moments after it was sent', async () => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(5_000_000);
    await send({ kind: 'filled', entryId: 'e1' }, { ...bank, tab: { id: 13 } });
    await send({ kind: 'signInSent' }, { ...bank, tab: { id: 13 } });
    vi.setSystemTime(5_000_000 + 21_000);
    expect(await send({ kind: 'signInCheck' }, { ...bank, tab: { id: 13 } })).toBeNull();
  });

  it('removes only the login the banner named, on its page', async () => {
    const tab = { ...bank, tab: { id: 14 } };
    const remove = { kind: 'removeLogin', entryId: 'e1' };
    expect(await send(remove, tab)).toEqual({ ok: false, problem: 'expired' });
    await send({ kind: 'filled', entryId: 'e1' }, tab);
    await send({ kind: 'signInSent' }, tab);
    await send({ kind: 'signInWarned', entryId: 'e1' }, tab);
    expect(await send({ kind: 'removeLogin', entryId: 'other' }, tab)).toEqual({
      ok: false,
      problem: 'expired',
    });
    expect(await send(remove, { origin: 'https://evil.example', tab: { id: 14 } })).toEqual({
      ok: false,
      problem: 'expired',
    });
    expect(client.changeLogin).not.toHaveBeenCalled();
    expect(await send(remove, tab)).toEqual({ ok: true });
    expect(client.changeLogin).toHaveBeenCalledWith('https://bank.example', {
      remove: { entryId: 'e1' },
    });
    client.changeLogin.mockResolvedValue({ ok: false, problem: 'outdatedApp' });
    expect(await send(remove, tab)).toEqual({ ok: false, problem: 'outdatedApp' });
  });
});

describe('a password-change form', () => {
  const site = { origin: 'https://store.example', url: 'https://store.example/account' };
  const offers = [{ id: 'e1', title: 'Shop', username: 'bob', exact: true }];

  beforeEach(() => {
    client.request.mockImplementation(async (action: object) =>
      'logins' in action
        ? { ok: true, value: { logins: offers } }
        : { ok: true, value: { status: 'update', entryId: 'e1', title: 'Shop' } },
    );
  });

  it('without a username names the site\u2019s only login', async () => {
    await send(
      { kind: 'capture', username: '', password: 'new1', change: true },
      { ...site, tab: { id: 21 } },
    );
    expect(client.request).toHaveBeenLastCalledWith({
      check: { origin: 'https://store.example', username: 'bob', password: 'new1' },
    });
  });

  it('names no login for a form that changes no password', async () => {
    await send({ kind: 'capture', username: '', password: 'pw' }, { ...site, tab: { id: 22 } });
    expect(client.request).toHaveBeenLastCalledWith({
      check: { origin: 'https://store.example', username: '', password: 'pw' },
    });
  });
});

describe('the popup', () => {
  it('drops the logins it changed from the cache', async () => {
    const { runtime } = (globalThis as unknown as { chrome: { runtime: Record<string, unknown> } })
      .chrome;
    runtime.getURL = (path: string) => `chrome-extension://ext/${path}`;
    const bank = { origin: 'https://cache.example', url: 'https://cache.example/login' };
    await send({ kind: 'logins' }, bank);
    await send({ kind: 'logins' }, bank);
    const lookups = () => client.request.mock.calls.filter(([action]) => 'logins' in action).length;
    expect(lookups()).toBe(1);
    // A page may not ask for it.
    await send({ kind: 'loginsChanged', origin: 'https://cache.example' }, bank);
    await send({ kind: 'logins' }, bank);
    expect(lookups()).toBe(1);
    const popup = { id: 'ext', tab: undefined, url: 'chrome-extension://ext/popup.html' };
    await new Promise<void>((resolve) => {
      world.listener?.({ kind: 'loginsChanged', origin: 'https://cache.example' }, popup, () =>
        resolve(),
      );
      resolve();
    });
    await send({ kind: 'logins' }, bank);
    expect(lookups()).toBe(2);
  });
});
