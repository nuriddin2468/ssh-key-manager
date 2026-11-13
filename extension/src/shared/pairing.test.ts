import { beforeEach, describe, expect, it, vi } from 'vitest';
import vectors from '../../../crates/sshkm-core/src/browser/channel-vectors.json';

const native = vi.hoisted(() => vi.fn());
vi.mock('./ext', () => ({
  ext: { runtime: { sendNativeMessage: native } },
  browserName: () => 'Test',
}));
const keystore = vi.hoisted(() => ({ savePairing: vi.fn() }));
vi.mock('./keystore', () => keystore);
// The real channel, but for opening the app's confirmation: the crypto is
// checked against the shared vectors in channel.test.ts.
vi.mock('./channel', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./channel')>();
  return {
    ...actual,
    deriveKeyBytes: vi.fn(actual.deriveKeyBytes),
    openResponse: vi.fn(async () => new TextEncoder().encode('{"paired":true}')),
  };
});

import { deriveKeyBytes, fromBase64, pairingCode, pairingCommitment, toBase64 } from './channel';
import { pair } from './client';

type Sent = Record<string, string>;

const sent = () => native.mock.calls.map(([, message]) => message as Sent);

beforeEach(() => {
  native.mockReset();
  keystore.savePairing.mockReset();
  vi.mocked(deriveKeyBytes).mockClear();
});

describe('pairing', () => {
  it('sends its key only once it has the app’s, and shows a code over both', async () => {
    native.mockResolvedValueOnce({ type: 'pairStarted', publicKey: vectors.appPublic });
    // Whatever key the last reply names, the one the code covered counts.
    native.mockResolvedValueOnce({
      type: 'paired',
      publicKey: vectors.clientPublic,
      nonce: 'AAAAAAAAAAAAAAAA',
      payload: 'AA==',
    });
    let shown = '';
    const result = await pair((code) => {
      shown = code;
    });
    expect(result).toEqual({ ok: true, value: undefined });

    const [start, finish] = sent();
    expect(start?.type).toBe('pairStart');
    expect(start).not.toHaveProperty('publicKey');
    expect(finish?.type).toBe('pairFinish');
    expect(finish?.clientId).toBe(start?.clientId);
    const clientId = String(start?.clientId);
    const clientPublic = fromBase64(String(finish?.publicKey));
    expect(start?.commitment).toBe(toBase64(await pairingCommitment(clientId, clientPublic)));
    const appPublic = fromBase64(vectors.appPublic);
    expect(shown).toBe(await pairingCode(clientId, clientPublic, appPublic));
    expect(vi.mocked(deriveKeyBytes).mock.calls[0]?.[3]).toEqual(appPublic);
    expect(keystore.savePairing).toHaveBeenCalledTimes(1);
  });

  it('says the app needs an update when it doesn’t know the first message', async () => {
    native.mockResolvedValueOnce({ type: 'error', code: 'invalid' });
    const onCode = vi.fn();
    expect(await pair(onCode)).toEqual({ ok: false, problem: 'outdatedApp' });
    expect(onCode).not.toHaveBeenCalled();
    expect(sent()).toHaveLength(1);
  });

  it('passes on why the app refused, and shows no code', async () => {
    native.mockResolvedValueOnce({ type: 'error', code: 'busy' });
    const onCode = vi.fn();
    expect(await pair(onCode)).toEqual({ ok: false, problem: 'busy' });
    native.mockResolvedValueOnce({ type: 'pairStarted', publicKey: 'AAAA' });
    expect(await pair(onCode)).toEqual({ ok: false, problem: 'invalid' });
    expect(onCode).not.toHaveBeenCalled();
  });
});
