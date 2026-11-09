import { beforeEach, describe, expect, it, vi } from 'vitest';

const native = vi.hoisted(() => vi.fn());
vi.mock('./ext', () => ({
  ext: { runtime: { sendNativeMessage: native } },
  browserName: () => 'Test',
}));
const keystore = vi.hoisted(() => ({ loadPairing: vi.fn(), forgetPairing: vi.fn() }));
vi.mock('./keystore', () => keystore);
// Sealing is tested in channel.test.ts; here a request goes out as is.
vi.mock('./channel', () => ({
  sealRequest: async (_keys: unknown, _id: string, plain: Uint8Array) => ({
    nonce: new Uint8Array(12),
    sealed: plain.slice(),
  }),
  toBase64: () => 'AA',
  fromBase64: () => new Uint8Array(),
  openResponse: async () => new TextEncoder().encode('{"entryId":"e"}'),
}));

import { changeLogin, unlockVault } from './client';

beforeEach(() => native.mockReset());

describe('unlockVault', () => {
  it('asks the app to unlock, and nothing more', async () => {
    native.mockResolvedValue({ type: 'shown' });
    await unlockVault();
    expect(native.mock.calls.map(([, message]) => message)).toEqual([{ type: 'unlock' }]);
  });

  it('brings an app that predates it forward instead', async () => {
    native.mockResolvedValueOnce({ type: 'error', code: 'invalid' });
    native.mockResolvedValueOnce({ type: 'shown' });
    await unlockVault();
    expect(native.mock.calls.map(([, message]) => message)).toEqual([
      { type: 'unlock' },
      { type: 'show' },
    ]);
  });

  it('opens nothing more when asked too often', async () => {
    native.mockResolvedValue({ type: 'error', code: 'tooMany' });
    await unlockVault();
    expect(native).toHaveBeenCalledTimes(1);
  });
});

describe('changeLogin', () => {
  beforeEach(() => {
    keystore.loadPairing.mockResolvedValue({ clientId: 'c', pairedAt: Date.now() });
  });

  it('edits and removes logins of the page', async () => {
    native.mockResolvedValue({ type: 'response', nonce: 'AA', payload: 'AA' });
    expect(await changeLogin('https://a.com', { edit: { entryId: 'e', password: 'n' } })).toEqual({
      ok: true,
      value: undefined,
    });
    expect(await changeLogin('https://a.com', { remove: { entryId: 'e' } })).toEqual({
      ok: true,
      value: undefined,
    });
  });

  it('tells an app that predates the actions apart', async () => {
    native.mockResolvedValue({ type: 'error', code: 'invalid' });
    expect(await changeLogin('https://a.com', { remove: { entryId: 'e' } })).toEqual({
      ok: false,
      problem: 'outdatedApp',
    });
    native.mockResolvedValue({ type: 'error', code: 'notFound' });
    expect(await changeLogin('https://a.com', { remove: { entryId: 'e' } })).toEqual({
      ok: false,
      problem: 'notFound',
    });
  });
});
