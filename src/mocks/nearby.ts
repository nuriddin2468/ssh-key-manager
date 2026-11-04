// Mock Nearby for `pnpm dev`: two computers turn up a moment after the page
// starts looking; pairing with the first goes through the code, the second
// can't be reached. `?nearby=incoming` makes a third one ask to pair a few
// seconds after this one is shown, and send a login; `&item=group` or
// `&item=key` makes it send a hosts file group or a public key instead.

import type { Contact } from '@/bindings/Contact';
import type { ItemSummary } from '@/bindings/ItemSummary';
import type { NearbyDevice } from '@/bindings/NearbyDevice';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import type { Pairing } from '@/bindings/Pairing';
import type { ReceivedGroup } from '@/bindings/ReceivedGroup';
import type { SendRequest } from '@/bindings/SendRequest';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { MOCK_CHANGED_EVENT, MOCK_CONTACTS_EVENT } from '@/features/nearby/queries';
import { hostsFileInfo } from './hostsFile';
import { vaultHandlers } from './vault';

const FOUND: NearbyDevice[] = [
  { id: 'aziz', name: 'MacBook Aziza' },
  { id: 'office-pc', name: 'office-pc' },
];
const CODE = '482913';

let name = 'macbook-pro';
let visibleUntil: string | null = null;
let devices: NearbyDevice[] = [];
let pairing: Pairing | null = null;
let nextId = 1;
/** What the pairing going on goes on to send, or to receive. */
let sending: ItemSummary | null = null;
let receiving: ItemSummary | null = null;
const timers: number[] = [];
/** Hosts file groups received, by pairing. */
const receivedGroups = new Map<number, ReceivedGroup>();

/** What the computer that asks to pair sends, by `?item=`. */
const INCOMING: Record<string, ItemSummary> = {
  password: { type: 'password', title: 'Office Wi-Fi', username: 'guest', url: '', otp: false },
  group: {
    type: 'hostsGroup',
    name: 'Staging',
    entries: 3,
    names: ['qa-api.internal', 'qa-db.internal', 'qa-cache.internal'],
  },
  key: {
    type: 'publicKey',
    name: 'id_ed25519',
    keyType: 'ssh-ed25519',
    fingerprint: 'SHA256:76vvbGumhP/HpDH4tlyySHWs5hgRZJHr2wQ7hSDwRK8',
    comment: 'sardor@thinkpad',
  },
};

const GROUP_ENTRIES = [
  { address: '10.0.12.10', names: ['qa-api.internal'], enabled: true, expires: null },
  { address: '10.0.12.11', names: ['qa-db.internal'], enabled: true, expires: null },
  { address: '10.0.12.12', names: ['qa-cache.internal'], enabled: false, expires: null },
];

/** The summary the backend makes of what `request` names. */
function summary(request: SendRequest): ItemSummary {
  switch (request.type) {
    case 'host':
      return { type: 'host', alias: request.alias, address: 'ubuntu@10.0.4.12', hostKeys: 1 };
    case 'password':
      return { type: 'password', title: 'prod-api', username: 'deploy', url: '', otp: request.otp };
    case 'hostsGroup': {
      const entries = hostsFileInfo().view.entries.filter((e) => e.group === request.name);
      return {
        type: 'hostsGroup',
        name: request.name,
        entries: entries.length,
        names: [...new Set(entries.flatMap((e) => e.names.slice(0, 1)))].slice(0, 3),
      };
    }
    case 'publicKey': {
      // Mock key ids are `<fingerprint>#<file name>`.
      const [fingerprint = '', file = ''] = request.keyId.split('#');
      return {
        type: 'publicKey',
        name: file.replace(/\.pub$/, ''),
        keyType: 'ssh-ed25519',
        fingerprint,
        comment: 'dev@macbook-pro',
      };
    }
  }
}

/** The name a received item gets, as the backend gives it. */
function receivedName(item: ItemSummary, peer: string): string {
  switch (item.type) {
    case 'host':
      return item.alias;
    case 'password':
      return item.title;
    case 'hostsGroup':
      return item.name;
    case 'publicKey':
      return /^id_[a-z0-9_]+$/.test(item.name)
        ? `${item.name}-${peer.replace(/[^A-Za-z0-9_.]+/g, '-')}`
        : item.name;
  }
}

const contacts: Contact[] = [
  { key: 'bW9jay1ib2J1cg==', name: 'ThinkPad Bobura', paired: '2026-10-21T09:12:00Z' },
];

const fail = (code: string, message: string) => Promise.reject({ code, message });

function status(): NearbyStatus {
  return {
    name,
    visibleUntil,
    address: visibleUntil ? '192.168.1.24:48213' : null,
    devices: [...devices].sort((a, b) => a.name.localeCompare(b.name)),
    pairing,
  };
}

function changed(): NearbyStatus {
  const now = status();
  window.dispatchEvent(new CustomEvent(MOCK_CHANGED_EVENT, { detail: now }));
  return now;
}

function later(ms: number, step: () => void) {
  timers.push(window.setTimeout(step, ms));
}

function locked(): boolean {
  const vault = vaultHandlers.vault_status?.({}) as VaultStatus | undefined;
  return vault?.state !== 'unlocked';
}

/** Moves pairing `id` on, if it is still the one going on. */
function update(id: number, next: Partial<Pairing>) {
  if (pairing?.id !== id) return;
  pairing = { ...pairing, ...next };
  changed();
}

function start(outgoing: boolean, peer: string, reachable: boolean): number {
  const id = nextId++;
  pairing = { id, peer: null, outgoing, phase: { type: 'connecting' } };
  changed();
  later(800, () =>
    update(
      id,
      reachable
        ? { peer, phase: { type: 'compare', code: CODE } }
        : { phase: { type: 'failed', reason: 'unreachable' } },
    ),
  );
  return id;
}

const active = () =>
  pairing !== null &&
  ['connecting', 'compare', 'waiting', 'offering', 'offered'].includes(pairing.phase.type);

/** After pairing (or straight away, between contacts): send or receive. */
function afterPairing(id: number) {
  if (sending) {
    const item = sending;
    update(id, { phase: { type: 'offering', item } });
    later(2000, () => {
      if (pairing?.id === id && pairing.phase.type === 'offering') {
        update(id, { phase: { type: 'sent', item } });
      }
    });
  } else if (receiving) {
    update(id, { phase: { type: 'offered', item: receiving } });
  } else {
    update(id, { phase: { type: 'paired' } });
  }
}

export const nearbyHandlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  nearby_status: status,
  nearby_set_name: ({ name: next }) => {
    const clean = String(next).trim().replace(/\s+/g, ' ').slice(0, 64);
    if (!clean) return fail('invalid_input', 'a device needs a name');
    name = clean;
    return changed();
  },
  nearby_set_visible: ({ visible }) => {
    if (!visible) {
      visibleUntil = null;
      return changed();
    }
    if (locked()) return fail('vault_locked', 'the vault is locked');
    visibleUntil = new Date(Date.now() + 10 * 60_000).toISOString();
    if (new URLSearchParams(window.location.search).get('nearby') === 'incoming') {
      later(3000, () => {
        if (active()) return;
        sending = null;
        const kind = new URLSearchParams(window.location.search).get('item') ?? 'password';
        receiving = INCOMING[kind] ?? INCOMING.password ?? null;
        start(false, 'ThinkPad Sardora', true);
      });
    }
    return changed();
  },
  nearby_set_looking: ({ looking }) => {
    devices = [];
    if (looking) {
      later(1200, () => {
        devices = FOUND.slice(0, 1);
        changed();
      });
      later(2600, () => {
        devices = [...FOUND];
        changed();
      });
    }
    return changed();
  },
  nearby_pair: ({ target }) => {
    if (locked()) return fail('vault_locked', 'the vault is locked');
    if (active()) return fail('conflict', 'another pairing is going on');
    const found = devices.find((device) => device.id === target);
    sending = null;
    receiving = null;
    return start(true, found?.name ?? String(target), target === 'aziz');
  },
  nearby_send: ({ target, item }) => {
    if (locked()) return fail('vault_locked', 'the vault is locked');
    if (active()) return fail('conflict', 'another pairing is going on');
    receiving = null;
    sending = summary(item as SendRequest);
    const found = devices.find((device) => device.id === target);
    const peer = found?.name ?? String(target);
    if (!contacts.some((contact) => contact.name === peer)) {
      return start(true, peer, target === 'aziz');
    }
    // Contacts already: straight to the offer.
    const id = nextId++;
    pairing = { id, peer: null, outgoing: true, phase: { type: 'connecting' } };
    changed();
    later(700, () => {
      update(id, { peer });
      afterPairing(id);
    });
    return id;
  },
  nearby_answer: ({ id: raw, matched }) => {
    const id = Number(raw);
    if (pairing?.id === id && pairing.phase.type === 'offered') {
      const item = pairing.phase.item;
      const peer = pairing.peer ?? '?';
      if (matched && item.type === 'hostsGroup') {
        receivedGroups.set(id, {
          id,
          name: item.name,
          from: peer,
          entries: GROUP_ENTRIES.map((entry) => ({ ...entry, comment: null, group: item.name })),
        });
      }
      update(
        id,
        matched
          ? {
              phase: {
                type: 'received',
                item,
                name: receivedName(item, peer),
                keysDiffer: false,
              },
            }
          : { phase: { type: 'failed', reason: 'turned' } },
      );
      return undefined;
    }
    if (pairing?.id !== id || pairing.phase.type !== 'compare') {
      return fail('not_found', 'the pairing has ended');
    }
    if (!matched) {
      update(id, { phase: { type: 'failed', reason: 'declined' } });
      return undefined;
    }
    update(id, { phase: { type: 'waiting', code: CODE } });
    later(1800, () => {
      const current = pairing;
      if (current?.id !== id || current.phase.type !== 'waiting') return;
      contacts.push({
        key: btoa(`mock-${current.peer}`),
        name: current.peer ?? '?',
        paired: new Date().toISOString(),
      });
      window.dispatchEvent(new CustomEvent(MOCK_CONTACTS_EVENT));
      afterPairing(id);
    });
    return undefined;
  },
  nearby_close: ({ id }) => {
    if (pairing?.id !== id) return undefined;
    if (active()) update(Number(id), { phase: { type: 'failed', reason: 'cancelled' } });
    else {
      pairing = null;
      changed();
    }
    return undefined;
  },
  nearby_received_group: ({ id }) => receivedGroups.get(Number(id)) ?? null,
  nearby_contacts: () => {
    if (locked()) return fail('vault_locked', 'the vault is locked');
    return [...contacts].sort((a, b) => a.name.localeCompare(b.name));
  },
  nearby_remove_contact: ({ key }) => {
    const index = contacts.findIndex((contact) => contact.key === key);
    if (index < 0) return fail('not_found', 'that device is not a contact');
    contacts.splice(index, 1);
    return undefined;
  },
};
