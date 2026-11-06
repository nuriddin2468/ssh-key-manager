import { beforeEach, describe, expect, it, vi } from 'vitest';

const native = vi.hoisted(() => vi.fn());
vi.mock('./ext', () => ({
  ext: { runtime: { sendNativeMessage: native } },
  browserName: () => 'Test',
}));
vi.mock('./keystore', () => ({}));

import { unlockVault } from './client';

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
