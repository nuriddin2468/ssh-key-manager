// The extension's side of the encrypted channel to the app, with WebCrypto
// only. It mirrors crates/sshkm-core/src/browser/channel.rs, label for
// label; channel-vectors.json checks that both compute the same.
//
// - Pairing: a P-256 key pair and a random client id; both sides show a
//   six-digit code made from the id and the public key. The app replies with
//   its public key, and HKDF-SHA-256 over the ECDH secret gives two
//   AES-256-GCM keys, for requests and for responses.
// - A request is sealed with a random nonce and the client id as associated
//   data; its response is bound to the client id and the request's nonce.

type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();
const LABEL = encoder.encode('sshkm-browser-v1');
const NONCE_LEN = 12;

export interface ChannelKeys {
  /** Seals requests. */
  request: CryptoKey;
  /** Opens responses. */
  response: CryptoKey;
}

function text(value: string): Bytes {
  return encoder.encode(value);
}

export function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}

export function randomBytes(length: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function fromBase64(value: string): Bytes {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** A random client id: 16 bytes as unpadded base64url. */
export function newClientId(): string {
  return toBase64(randomBytes(16)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A new P-256 key pair; the private key never leaves WebCrypto. */
export async function newKeyPair(): Promise<{ privateKey: CryptoKey; publicKey: Bytes }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, [
    'deriveBits',
  ]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { privateKey: pair.privateKey, publicKey };
}

/** The six digits the app shows too. */
export async function pairingCode(clientId: string, clientPublic: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    concat(LABEL, text(' code '), text(clientId), clientPublic),
  );
  const number = new DataView(digest).getUint32(0);
  return String(number % 1_000_000).padStart(6, '0');
}

/** The 64 bytes of key material: request key, then response key. */
export async function deriveKeyBytes(
  privateKey: CryptoKey,
  clientId: string,
  clientPublic: Uint8Array,
  appPublic: Uint8Array,
): Promise<Bytes> {
  const app = await crypto.subtle.importKey(
    'raw',
    concat(appPublic),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: app }, privateKey, 256);
  const hkdf = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveBits']);
  const okm = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: LABEL,
      info: concat(LABEL, text(' keys '), text(clientId), clientPublic, appPublic),
    },
    hkdf,
    512,
  );
  return new Uint8Array(okm);
}

/** Turns key material into non-extractable keys and wipes it. */
export async function importKeys(material: Bytes): Promise<ChannelKeys> {
  try {
    const [request, response] = await Promise.all([
      crypto.subtle.importKey('raw', material.slice(0, 32), 'AES-GCM', false, ['encrypt']),
      crypto.subtle.importKey('raw', material.slice(32, 64), 'AES-GCM', false, ['decrypt']),
    ]);
    return { request, response };
  } finally {
    material.fill(0);
  }
}

/** Seals a request; `nonce` is random unless given (tests). */
export async function sealRequest(
  keys: ChannelKeys,
  clientId: string,
  plain: Uint8Array,
  nonce: Bytes = randomBytes(NONCE_LEN),
): Promise<{ nonce: Bytes; sealed: Bytes }> {
  const sealed = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: concat(LABEL, text(' request '), text(clientId)),
    },
    keys.request,
    concat(plain),
  );
  return { nonce, sealed: new Uint8Array(sealed) };
}

/** Opens the response to the request with `requestNonce`. Throws if it was tampered with. */
export async function openResponse(
  keys: ChannelKeys,
  clientId: string,
  requestNonce: Uint8Array,
  nonce: Uint8Array,
  sealed: Uint8Array,
): Promise<Bytes> {
  const plain = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: concat(nonce),
      additionalData: concat(LABEL, text(' response '), text(clientId), requestNonce),
    },
    keys.response,
    concat(sealed),
  );
  return new Uint8Array(plain);
}
