// Mock chats for `pnpm dev`: ThinkPad Bobura (a paired computer) is online
// with a conversation going on: texts, a secret, variables and a host
// offered; the iMac (one of the user's devices) is offline.
//
// URL switches:
// - `?chat=offline`: every computer is offline.
// - `?chat=empty`: no conversation yet.

import type { ChatEntry } from '@/bindings/ChatEntry';
import type { ChatList } from '@/bindings/ChatList';
import type { ChatSummary } from '@/bindings/ChatSummary';
import type { SendRequest } from '@/bindings/SendRequest';
import type { VarReview } from '@/bindings/VarReview';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { MOCK_CHATS_EVENT } from '@/features/nearby/chat/events';
import { vaultHandlers } from './vault';

const BOBURA = 'bW9jay1ib2J1cg==';
const IMAC = 'bW9jay1pbWFj';
const params = new URLSearchParams(window.location.search);
const allOffline = params.get('chat') === 'offline';

const fail = (code: string, message: string) => Promise.reject({ code, message });

function locked(): boolean {
  return (vaultHandlers.vault_status?.({}) as VaultStatus | undefined)?.state !== 'unlocked';
}

const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString();
const later = (minutes: number) => new Date(Date.now() + minutes * 60_000).toISOString();
const newId = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) =>
    b.toString(16).padStart(2, '0'),
  ).join('');

interface Peer {
  key: string;
  name: string;
  own: boolean;
  online: boolean;
  entries: ChatEntry[];
  read: number;
}

/** Values the page may ask for, by message id (and variable name). */
const values = new Map<string, string>();

function seed(): ChatEntry[] {
  if (params.get('chat') === 'empty') return [];
  const secret = newId();
  const vars = newId();
  values.set(secret, 'Xq7#staging-2026!');
  values.set(`${vars}:DATABASE_URL`, 'postgres://app:s3cret@10.0.4.12:5432/shop');
  values.set(`${vars}:API_KEY`, 'sk_test_51NzQ…');
  return [
    {
      id: newId(),
      mine: false,
      at: ago(52),
      delivery: { state: 'received' },
      body: { kind: 'text', text: 'Hi! Are you on the staging rollout today?' },
    },
    {
      id: newId(),
      mine: true,
      at: ago(50),
      delivery: { state: 'delivered' },
      body: { kind: 'text', text: 'Yes. I need the database password for staging.' },
    },
    {
      id: secret,
      mine: false,
      at: ago(5),
      delivery: { state: 'received' },
      body: { kind: 'secret', label: 'staging DB password', expires: later(55), gone: null },
    },
    {
      id: vars,
      mine: false,
      at: ago(4),
      delivery: { state: 'received' },
      body: {
        kind: 'variables',
        label: 'shop · staging',
        expires: later(23 * 60),
        gone: null,
        variables: [
          { name: 'DATABASE_URL', secret: true, value: null, risky: false },
          { name: 'API_KEY', secret: true, value: null, risky: false },
          { name: 'LOG_LEVEL', secret: false, value: 'debug', risky: false },
          {
            name: 'NODE_OPTIONS',
            secret: false,
            value: '--max-old-space-size=4096',
            risky: true,
          },
        ],
      },
    },
    {
      id: newId(),
      mine: false,
      at: ago(3),
      delivery: { state: 'received' },
      body: {
        kind: 'card',
        item: {
          type: 'host',
          alias: 'staging',
          address: 'deploy@10.0.4.12',
          proxyJump: 'bastion',
          hostKeys: 1,
        },
        outcome: 'waiting',
        name: null,
        keysDiffer: false,
        group: null,
      },
    },
    {
      id: newId(),
      mine: true,
      at: ago(1),
      delivery: { state: 'notDelivered' },
      body: { kind: 'text', text: 'Thanks! Got it.' },
    },
  ];
}

const peers: Peer[] = [
  { key: IMAC, name: 'iMac at home', own: true, online: false, entries: [], read: 0 },
  {
    key: BOBURA,
    name: 'ThinkPad Bobura',
    own: false,
    online: !allOffline,
    entries: seed(),
    read: 2,
  },
];
let open = false;

function changed(key: string | null = null) {
  window.dispatchEvent(new CustomEvent(MOCK_CHATS_EVENT, { detail: { key } }));
}

function peer(key: unknown): Peer | undefined {
  return peers.find((item) => item.key === key);
}

function online(item: Peer): boolean {
  return open && item.online;
}

function summary(item: Peer): ChatSummary {
  const last = item.entries.at(-1);
  return {
    key: item.key,
    name: item.name,
    own: item.own,
    online: online(item),
    unread: item.entries.slice(item.read).filter((entry) => !entry.mine).length,
    last: last
      ? {
          at: last.at,
          mine: last.mine,
          kind: last.body.kind,
          text: last.body.kind === 'text' ? (last.body.text.split('\n')[0] ?? '') : null,
        }
      : null,
  };
}

/** Adds a message of the user's: delivered a moment later if the other is online. */
function send(item: Peer, body: ChatEntry['body']): Promise<void> | undefined {
  if (locked()) return fail('vault_locked', 'the vault is locked');
  if (!online(item)) return fail('not_found', 'the other computer is offline');
  const entry: ChatEntry = {
    id: newId(),
    mine: true,
    at: new Date().toISOString(),
    delivery: { state: 'sending' },
    body,
  };
  item.entries.push(entry);
  item.read = item.entries.length;
  changed(item.key);
  setTimeout(() => {
    entry.delivery = { state: 'delivered' };
    changed(item.key);
  }, 600);
  return undefined;
}

function entry(item: Peer, id: unknown): ChatEntry | undefined {
  return item.entries.find((candidate) => candidate.id === id);
}

const RISKY =
  /^(PATH|LD_.*|DYLD_.*|NODE_OPTIONS|NODE_PATH|PYTHON(PATH|STARTUP|HOME)|BASH_ENV|ENV)$/i;

export const chatHandlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  chat_set_open: ({ open: next }) => {
    open = Boolean(next);
    changed();
  },
  chat_list: (): ChatList | Promise<never> => {
    if (locked()) return fail('vault_locked', 'the vault is locked');
    return { online: open, chats: peers.map(summary) };
  },
  chat_history: ({ key }) => {
    const item = peer(key);
    if (!item) return fail('not_found', 'that computer is not a contact');
    return item.entries;
  },
  chat_mark_read: ({ key }) => {
    const item = peer(key);
    if (item && item.read !== item.entries.length) {
      item.read = item.entries.length;
      changed(item.key);
    }
  },
  chat_send_text: ({ key, text }) => {
    const item = peer(key);
    if (!item) return fail('not_found', 'that computer is not a contact');
    return send(item, { kind: 'text', text: String(text).trimEnd() });
  },
  chat_send_secret: ({ key, label, value, ttl }) => {
    const item = peer(key);
    if (!item) return fail('not_found', 'that computer is not a contact');
    const result = send(item, {
      kind: 'secret',
      label: String(label),
      expires: new Date(Date.now() + Number(ttl) * 1000).toISOString(),
      gone: null,
    });
    const last = item.entries.at(-1);
    if (!result && last) values.set(last.id, String(value));
    return result;
  },
  chat_send_variables: ({ key, names, ttl }) => {
    const item = peer(key);
    if (!item) return fail('not_found', 'that computer is not a contact');
    return send(item, {
      kind: 'variables',
      label: 'shop · prod',
      expires: new Date(Date.now() + Number(ttl) * 1000).toISOString(),
      gone: null,
      variables: (names as string[]).map((name) => ({
        name,
        secret: true,
        value: null,
        risky: RISKY.test(name),
      })),
    });
  },
  chat_send_item: ({ key, request }) => {
    const item = peer(key);
    if (!item) return fail('not_found', 'that computer is not a contact');
    const what = request as SendRequest;
    const result = send(item, {
      kind: 'card',
      item:
        what.type === 'host'
          ? { type: 'host', alias: what.alias, address: what.alias, proxyJump: null, hostKeys: 1 }
          : {
              type: 'password',
              title: 'Router admin',
              username: 'admin',
              url: '',
              otp: false,
            },
      outcome: 'waiting',
      name: null,
      keysDiffer: false,
      group: null,
    });
    const card = item.entries.at(-1);
    if (!result && card?.body.kind === 'card') {
      const body = card.body;
      setTimeout(() => {
        body.outcome = 'saved';
        body.name = what.type === 'host' ? what.alias : 'Router admin';
        changed(item.key);
      }, 2500);
    }
    return result;
  },
  chat_answer: ({ key, id, accept }) => {
    const item = peer(key);
    const card = item && entry(item, id);
    if (!item || card?.body.kind !== 'card') return fail('not_found', 'the offer has ended');
    const body = card.body;
    body.outcome = accept ? 'accepted' : 'declined';
    changed(item.key);
    if (accept) {
      setTimeout(() => {
        body.outcome = 'saved';
        body.name = body.item.type === 'host' ? `${body.item.alias}-2` : 'received';
        changed(item.key);
      }, 700);
    }
  },
  chat_reveal: ({ key, id, name }) => {
    const value = values.get(name ? `${id}:${name}` : String(id));
    if (!peer(key) || value === undefined) return fail('not_found', 'the value is gone');
    return value;
  },
  chat_copy: ({ key, id, name }) => {
    if (!peer(key) || !values.has(name ? `${id}:${name}` : String(id))) {
      return fail('not_found', 'the value is gone');
    }
    return { clearsInSecs: 30 };
  },
  chat_revoke: ({ key, id, everywhere }) => {
    const item = peer(key);
    const found = item && entry(item, id);
    if (!item || !found?.mine) return fail('not_found', 'nothing to wipe');
    if (everywhere && !online(item)) return fail('not_found', 'the other computer is offline');
    if (found.body.kind === 'secret' || found.body.kind === 'variables') {
      found.body.gone = 'wiped';
      found.body.expires = null;
      values.delete(found.id);
    }
    changed(item.key);
  },
  chat_retry: ({ key, id }) => {
    const item = peer(key);
    const found = item && entry(item, id);
    if (!item || !found) return fail('not_found', 'nothing to send again');
    if (!online(item)) return fail('not_found', 'the other computer is offline');
    found.delivery = { state: 'sending' };
    changed(item.key);
    setTimeout(() => {
      found.delivery = { state: 'delivered' };
      changed(item.key);
    }, 600);
  },
  chat_review_variables: ({ key, id, envId }): VarReview[] | Promise<never> => {
    const item = peer(key);
    const found = item && entry(item, id);
    if (found?.body.kind !== 'variables' || found.body.gone) {
      return fail('not_found', 'the variables are gone');
    }
    return found.body.variables.map((variable) => ({
      name: variable.name,
      secret: variable.secret,
      change: envId && variable.name === 'LOG_LEVEL' ? 'replaces' : 'new',
      risky: variable.risky,
    }));
  },
  chat_add_variables: ({ names }) => {
    if ((names as string[]).length === 0) return fail('invalid_input', 'no variables picked');
    return 'env-mock-received';
  },
  chat_delete: ({ key }) => {
    const item = peer(key);
    if (item) {
      item.entries = [];
      item.read = 0;
      changed(item.key);
    }
  },
};
