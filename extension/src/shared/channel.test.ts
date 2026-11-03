import { describe, expect, it } from 'vitest';
import vectors from '../../../crates/sshkm-core/src/browser/channel-vectors.json';
import {
  concat,
  deriveKeyBytes,
  fromBase64,
  importKeys,
  newClientId,
  newKeyPair,
  openResponse,
  pairingCode,
  sealRequest,
  toBase64,
} from './channel';

const decoder = new TextDecoder();

function base64url(bytes: Uint8Array): string {
  return toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function hex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

/** The vectors' client key, imported the way WebCrypto allows: as a JWK. */
async function clientKey(): Promise<CryptoKey> {
  const pub = fromBase64(vectors.clientPublic);
  return crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      d: base64url(hex(vectors.clientSecret)),
      x: base64url(pub.slice(1, 33)),
      y: base64url(pub.slice(33, 65)),
    },
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
}

describe('the channel', () => {
  it('computes what the app computes', async () => {
    const clientPublic = fromBase64(vectors.clientPublic);
    const appPublic = fromBase64(vectors.appPublic);
    expect(await pairingCode(vectors.clientId, clientPublic)).toBe(vectors.code);

    const material = await deriveKeyBytes(
      await clientKey(),
      vectors.clientId,
      clientPublic,
      appPublic,
    );
    expect(toBase64(material.slice(0, 32))).toBe(vectors.requestKey);
    expect(toBase64(material.slice(32))).toBe(vectors.responseKey);

    const keys = await importKeys(material);
    expect(material.every((byte) => byte === 0)).toBe(true);

    const requestNonce = fromBase64(vectors.requestNonce);
    const { sealed } = await sealRequest(
      keys,
      vectors.clientId,
      new TextEncoder().encode(vectors.requestPlain),
      requestNonce,
    );
    expect(toBase64(sealed)).toBe(vectors.requestSealed);

    const opened = await openResponse(
      keys,
      vectors.clientId,
      requestNonce,
      fromBase64(vectors.responseNonce),
      fromBase64(vectors.responseSealed),
    );
    expect(decoder.decode(opened)).toBe(vectors.responsePlain);
  });

  it('refuses a response to another request or from another key', async () => {
    const material = await deriveKeyBytes(
      await clientKey(),
      vectors.clientId,
      fromBase64(vectors.clientPublic),
      fromBase64(vectors.appPublic),
    );
    const keys = await importKeys(material);
    const otherNonce = fromBase64(vectors.requestNonce);
    otherNonce[0] = (otherNonce[0] ?? 0) ^ 1;
    await expect(
      openResponse(
        keys,
        vectors.clientId,
        otherNonce,
        fromBase64(vectors.responseNonce),
        fromBase64(vectors.responseSealed),
      ),
    ).rejects.toThrow();
    await expect(
      openResponse(
        keys,
        'another-client-id-0000',
        fromBase64(vectors.requestNonce),
        fromBase64(vectors.responseNonce),
        fromBase64(vectors.responseSealed),
      ),
    ).rejects.toThrow();
  });

  it('makes fresh ids and keys', async () => {
    const id = newClientId();
    expect(id).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(newClientId()).not.toBe(id);
    const { publicKey } = await newKeyPair();
    expect(publicKey.length).toBe(65);
    expect(publicKey[0]).toBe(4);
    expect(base64url(concat(new Uint8Array([251, 255])))).toBe('-_8');
  });
});
