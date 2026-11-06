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
  };
  return state;
});

const client = vi.hoisted(() => ({
  request: vi.fn(),
  sameSite: vi.fn(),
  showApp: vi.fn(),
  unlockVault: vi.fn(),
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
