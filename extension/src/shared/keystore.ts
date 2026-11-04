// The pairing with the app: the client id and the two channel keys, kept in
// the extension's IndexedDB as non-extractable CryptoKeys, so no script can
// read the key bytes back. Content scripts can't reach this database: they
// get the page's.

import type { ChannelKeys } from './channel';

export interface Pairing extends ChannelKeys {
  clientId: string;
  /** Milliseconds since 1970. */
  pairedAt: number;
  /** When the keys last changed, in milliseconds since 1970; `pairedAt` if never. */
  keysAt?: number;
}

const DB = 'sshkm-autofill';
const STORE = 'pairing';
const KEY = 'current';

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function run<T>(
  mode: IDBTransactionMode,
  work: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const request = work(db.transaction(STORE, mode).objectStore(STORE));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

export async function loadPairing(): Promise<Pairing | null> {
  const value = await run<unknown>('readonly', (store) => store.get(KEY));
  return (value as Pairing | undefined) ?? null;
}

export async function savePairing(pairing: Pairing): Promise<void> {
  await run('readwrite', (store) => store.put(pairing, KEY));
}

export async function forgetPairing(): Promise<void> {
  await run('readwrite', (store) => store.delete(KEY));
}
