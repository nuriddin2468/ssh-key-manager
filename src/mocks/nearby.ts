// Mock Nearby for `pnpm dev`: two computers turn up a moment after the page
// starts looking; pairing with the first goes through the code, the second
// can't be reached. `?nearby=incoming` makes a third one ask to pair a few
// seconds after this one is shown.

import type { Contact } from '@/bindings/Contact';
import type { NearbyDevice } from '@/bindings/NearbyDevice';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import type { Pairing } from '@/bindings/Pairing';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { MOCK_CHANGED_EVENT, MOCK_CONTACTS_EVENT } from '@/features/nearby/queries';
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
const timers: number[] = [];
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
  pairing !== null && ['connecting', 'compare', 'waiting'].includes(pairing.phase.type);

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
      later(3000, () => active() || start(false, 'ThinkPad Sardora', true));
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
    return start(true, found?.name ?? String(target), target === 'aziz');
  },
  nearby_answer: ({ id: raw, matched }) => {
    const id = Number(raw);
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
      update(id, { phase: { type: 'paired' } });
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
