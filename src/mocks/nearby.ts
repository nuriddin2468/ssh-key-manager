// Mock Nearby for `pnpm dev`. Computers turn up a moment after the page
// starts looking:
// - pairing with the first goes through the code;
// - the second can't be reached;
// - the third has no vault and waits to be added as one of the user's
//   devices.
// The user's devices are this computer and an iMac on the network.
//
// URL switches:
// - `?nearby=incoming`: a fourth computer asks to pair a few seconds after
//   this one is shown, and sends a login; `&item=group`, `&item=key` or
//   `&item=server` makes it send a hosts file group, a public key or a
//   server's password instead.
// - `?vault=missing&nearby=join`: another computer gives this one its vault
//   a few seconds after "Get it from my other computer".
// - `?nearby=sync`: "Sync" brings a conflict, a risky host and many
//   deletions to decide on.
// - `?nearby=renamed`: whatever computer the user sends to, a contact
//   answers that calls itself by that computer's name.

import type { Contact } from '@/bindings/Contact';
import type { ConversationKind } from '@/bindings/ConversationKind';
import type { ItemSummary } from '@/bindings/ItemSummary';
import type { MyDevice } from '@/bindings/MyDevice';
import type { NearbyDevice } from '@/bindings/NearbyDevice';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import type { Pairing } from '@/bindings/Pairing';
import type { ReceivedGroup } from '@/bindings/ReceivedGroup';
import type { Review } from '@/bindings/Review';
import type { SendRequest } from '@/bindings/SendRequest';
import type { SyncDecisions } from '@/bindings/SyncDecisions';
import type { SyncSummary } from '@/bindings/SyncSummary';
import type { VaultStatus } from '@/bindings/VaultStatus';
import {
  MOCK_CHANGED_EVENT,
  MOCK_CONTACTS_EVENT,
  MOCK_DEVICES_EVENT,
} from '@/features/nearby/queries';
import { envSummary } from './envs';
import { hostsFileInfo } from './hostsFile';
import { vaultHandlers } from './vault';

const FOUND: NearbyDevice[] = [
  { id: 'aziz', name: 'MacBook Aziza', joining: false },
  { id: 'office-pc', name: 'office-pc', joining: false },
  { id: 'thinkpad', name: 'ThinkPad X1', joining: true },
];
const CODE = '482913';
const IMAC = 'bW9jay1pbWFj';
const SWITCH = new URLSearchParams(window.location.search).get('nearby');

let name = 'macbook-pro';
let visibleUntil: string | null = null;
let joining = false;
let reachable = true;
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
  password: {
    type: 'password',
    title: 'Office Wi-Fi',
    username: 'guest',
    url: '',
    otp: false,
    host: null,
    server: null,
  },
  server: {
    type: 'password',
    title: 'prod-api',
    username: 'deploy',
    url: '',
    otp: true,
    host: 'prod',
    server: { user: 'deploy', hostName: '10.0.4.12', port: 22, proxyJump: null },
  },
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
      return {
        type: 'host',
        alias: request.alias,
        address: 'ubuntu@10.0.4.12',
        proxyJump: null,
        hostKeys: 1,
      };
    case 'password':
      return {
        type: 'password',
        title: 'prod-api',
        username: 'deploy',
        url: '',
        otp: request.otp,
        host: 'prod-api',
        server: { user: 'deploy', hostName: '10.0.4.12', port: 22, proxyJump: null },
      };
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
    case 'environment':
      return envSummary(request.envId);
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
    case 'environment':
      return [item.project, item.name].filter(Boolean).join(' · ');
    case 'unknown':
      return '';
  }
}

const contacts: Contact[] = [
  { key: 'bW9jay1ib2J1cg==', name: 'ThinkPad Bobura', paired: '2026-10-21T09:12:00Z' },
];
const mine: MyDevice[] = [
  {
    key: 'bW9jay10aGlz',
    name,
    added: '2026-09-02T08:00:00Z',
    this: true,
    lastSync: null,
    reachable: false,
  },
  {
    key: IMAC,
    name: 'iMac at home',
    added: '2026-09-02T08:05:00Z',
    this: false,
    lastSync: new Date(Date.now() - 2 * 3600_000).toISOString(),
    reachable: true,
  },
];

const fail = (code: string, message: string) => Promise.reject({ code, message });

function status(): NearbyStatus {
  return {
    name,
    visibleUntil,
    address: visibleUntil ? '192.168.1.24:48213' : null,
    joining,
    hiddenAfterAttempts: false,
    reachable,
    present: reachable && !locked(),
    ownFound: reachable && !locked() ? [IMAC] : [],
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

function vaultState(): VaultStatus['state'] | undefined {
  return (vaultHandlers.vault_status?.({}) as VaultStatus | undefined)?.state;
}

function locked(): boolean {
  return vaultState() !== 'unlocked';
}

/** Moves pairing `id` on, if it is still the one going on. */
function update(id: number, next: Partial<Pairing>) {
  if (pairing?.id !== id) return;
  pairing = { ...pairing, ...next };
  changed();
}

function start(
  outgoing: boolean,
  peer: string,
  reachable: boolean,
  kind: ConversationKind = 'pair',
): number {
  const id = nextId++;
  pairing = { id, peer: null, outgoing, kind, phase: { type: 'connecting' } };
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

const ACTIVE = [
  'connecting',
  'compare',
  'waiting',
  'nameMismatch',
  'offering',
  'offered',
  'authorize',
  'approving',
  'transfer',
  'setMaster',
  'syncing',
  'decide',
];
const active = () => pairing !== null && ACTIVE.includes(pairing.phase.type);

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

/** The vault goes over in a few steps, then `done`. */
function transfer(id: number, done: () => void) {
  const total = 2_400_000;
  for (const [step, share] of [0.25, 0.6, 1].entries()) {
    later(500 * (step + 1), () =>
      update(id, { phase: { type: 'transfer', done: total * share, total } }),
    );
  }
  later(1900, done);
}

/** After the codes matched, adding a device goes on. */
function afterCompare(id: number) {
  const current = pairing;
  if (!current) return;
  if (current.outgoing) {
    const vault = devices.find((device) => device.name === current.peer)?.joining ?? false;
    update(id, { phase: { type: 'authorize', vault } });
  } else {
    update(id, { phase: { type: 'approving' } });
    later(2500, () => transfer(id, () => update(id, { phase: { type: 'setMaster' } })));
  }
}

function addMine(peer: string) {
  mine.push({
    key: btoa(`mock-${peer}`),
    name: peer,
    added: new Date().toISOString(),
    this: false,
    lastSync: null,
    reachable: false,
  });
  window.dispatchEvent(new CustomEvent(MOCK_DEVICES_EVENT));
}

const REVIEW: Review = {
  conflicts: [
    {
      id: 'prod-api',
      mine: {
        id: 'prod-api',
        fields: [
          { key: 'HostName', values: ['10.0.4.12'] },
          { key: 'User', values: ['deploy'] },
        ],
      },
      theirs: {
        id: 'prod-api',
        fields: [
          { key: 'HostName', values: ['10.0.4.40'] },
          { key: 'User', values: ['deploy'] },
          { key: 'Port', values: ['2222'] },
        ],
      },
    },
  ],
  risky: [
    {
      id: 'lab-gpu',
      lines: [{ key: 'ProxyCommand', value: 'ssh -W %h:%p lab-gateway' }],
    },
  ],
  deletions: ['old-ci-1', 'old-ci-2', 'old-ci-3', 'old-ci-4', 'old-ci-5', 'old-ci-6', 'old-vpn'],
};

function syncSummary(decisions: SyncDecisions | null): SyncSummary {
  return {
    added: 2 + (decisions?.apply.length ?? 0),
    changed: 1 + (decisions?.theirs.length ?? 0),
    removed: decisions?.delete ? REVIEW.deletions.length : 0,
    keysAdded: 3,
    keysDiffer: [
      {
        host: 'legacy-nas',
        port: 22,
        here: ['SHA256:Zr2sJ1mJ8m9cGQh3yV2G4k1Xb0n1Lp0b3uYbW7bS5aQ'],
        there: ['SHA256:9pQ4o0wq7L2yKcH8u3tN6a1Jm5fVbX2rZsE4dW8gT1c'],
      },
    ],
    deferred: decisions
      ? REVIEW.risky.length -
        decisions.apply.length -
        decisions.decline.length +
        (decisions.delete ? 0 : REVIEW.deletions.length)
      : 0,
    deferredThere: 1,
    conflicts: decisions
      ? REVIEW.conflicts.length - decisions.mine.length - decisions.theirs.length
      : 0,
    failed: 0,
  };
}

function synced(id: number, decisions: SyncDecisions | null) {
  update(id, { phase: { type: 'synced', summary: syncSummary(decisions) } });
  const imac = mine.find((device) => device.key === IMAC);
  if (imac) imac.lastSync = new Date().toISOString();
  window.dispatchEvent(new CustomEvent(MOCK_DEVICES_EVENT));
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
    joining = false;
    if (!visible) {
      visibleUntil = null;
      return changed();
    }
    if (locked()) return fail('vault_locked', 'the vault is locked');
    visibleUntil = new Date(Date.now() + 10 * 60_000).toISOString();
    if (SWITCH === 'incoming') {
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
  nearby_join: ({ on }) => {
    if (!on) {
      joining = false;
      visibleUntil = null;
      return changed();
    }
    if (vaultState() !== 'missing')
      return fail('already_exists', 'this computer has a vault already');
    joining = true;
    visibleUntil = new Date(Date.now() + 10 * 60_000).toISOString();
    if (SWITCH === 'join') {
      later(3000, () => {
        if (!active()) start(false, 'MacBook Pro', true, 'device');
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
  nearby_add_device: ({ target }) => {
    if (locked()) return fail('vault_locked', 'the vault is locked');
    if (active()) return fail('conflict', 'another pairing is going on');
    const found = devices.find((device) => device.id === target);
    if (found && !found.joining) {
      // The colleague's MacBook has a vault of its own.
      const id = nextId++;
      pairing = { id, peer: null, outgoing: true, kind: 'device', phase: { type: 'connecting' } };
      changed();
      later(800, () =>
        update(id, { peer: found.name, phase: { type: 'failed', reason: 'otherVault' } }),
      );
      return id;
    }
    return start(true, found?.name ?? String(target), target !== 'office-pc', 'device');
  },
  nearby_authorize: ({ id: raw, master }) => {
    const id = Number(raw);
    if (pairing?.id !== id || pairing.phase.type !== 'authorize') {
      return fail('not_found', 'nothing to confirm');
    }
    if (master === 'wrong') return fail('wrong_passphrase', 'wrong passphrase');
    const vault = pairing.phase.vault;
    const peer = pairing.peer ?? '?';
    const done = () => {
      update(id, { phase: { type: 'added', vault } });
      addMine(peer);
    };
    if (vault) transfer(id, done);
    else later(600, done);
    return undefined;
  },
  nearby_finish_join: ({ id: raw, master }) => {
    const id = Number(raw);
    if (pairing?.id !== id || pairing.phase.type !== 'setMaster') {
      return fail('not_found', 'no vault waits here');
    }
    const created = vaultHandlers.vault_create?.({ master });
    if (created instanceof Promise) return created;
    joining = false;
    visibleUntil = null;
    addMine(pairing.peer ?? '?');
    update(id, { phase: { type: 'joined' } });
    return undefined;
  },
  nearby_devices: () => {
    if (locked()) return fail('vault_locked', 'the vault is locked');
    const found = status().ownFound;
    return mine.map((device) => ({
      ...device,
      name: device.this ? name : device.name,
      reachable: found.includes(device.key),
    }));
  },
  nearby_remove_device: ({ key }) => {
    const index = mine.findIndex((device) => device.key === key && !device.this);
    if (index < 0) return fail('not_found', 'that device is not one of yours');
    mine.splice(index, 1);
    window.dispatchEvent(new CustomEvent(MOCK_DEVICES_EVENT));
    return undefined;
  },
  nearby_set_reachable: ({ reachable: on }) => {
    reachable = Boolean(on);
    return changed();
  },
  nearby_sync: () => {
    if (locked()) return fail('vault_locked', 'the vault is locked');
    if (active()) return fail('conflict', 'another pairing is going on');
    if (status().ownFound.length === 0) return fail('not_found', 'no device of yours is reachable');
    const id = nextId++;
    pairing = { id, peer: null, outgoing: true, kind: 'sync', phase: { type: 'connecting' } };
    changed();
    later(600, () => update(id, { peer: 'iMac at home', phase: { type: 'syncing' } }));
    later(1600, () => {
      if (SWITCH === 'sync') update(id, { phase: { type: 'decide', review: REVIEW } });
      else synced(id, null);
    });
    return undefined;
  },
  nearby_decide: ({ id: raw, decisions }) => {
    const id = Number(raw);
    if (pairing?.id !== id || pairing.phase.type !== 'decide') {
      return fail('not_found', 'the pairing has ended');
    }
    update(id, { phase: { type: 'syncing' } });
    later(900, () => synced(id, decisions as SyncDecisions));
    return undefined;
  },
  nearby_send: ({ target, item }) => {
    if (locked()) return fail('vault_locked', 'the vault is locked');
    if (active()) return fail('conflict', 'another pairing is going on');
    receiving = null;
    sending = summary(item as SendRequest);
    const found = devices.find((device) => device.id === target);
    const peer = found?.name ?? String(target);
    if (SWITCH === 'renamed') {
      const id = nextId++;
      pairing = { id, peer: null, outgoing: true, kind: 'pair', phase: { type: 'connecting' } };
      changed();
      later(700, () =>
        update(id, {
          peer: contacts[0]?.name ?? '?',
          phase: { type: 'nameMismatch', announced: peer },
        }),
      );
      return id;
    }
    if (!contacts.some((contact) => contact.name === peer)) {
      return start(true, peer, target === 'aziz');
    }
    // Contacts already: straight to the offer.
    const id = nextId++;
    pairing = { id, peer: null, outgoing: true, kind: 'pair', phase: { type: 'connecting' } };
    changed();
    later(700, () => {
      update(id, { peer });
      afterPairing(id);
    });
    return id;
  },
  nearby_answer: ({ id: raw, matched }) => {
    const id = Number(raw);
    if (pairing?.id === id && pairing.phase.type === 'nameMismatch') {
      if (matched) afterPairing(id);
      else update(id, { phase: { type: 'failed', reason: 'cancelled' } });
      return undefined;
    }
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
      if (current.kind === 'device') {
        afterCompare(id);
        return;
      }
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
    if (active() && pairing?.phase.type !== 'setMaster') {
      update(Number(id), { phase: { type: 'failed', reason: 'cancelled' } });
    } else {
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
