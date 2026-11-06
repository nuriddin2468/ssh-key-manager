// The palette's items, made from what the app knows: each is one action on
// one thing ("Connect" to a host, "Copy password" of an entry), so a query
// can name both. What an item does comes from the caller: the command
// palette and the quick search window run them differently.

import type { TFunction } from 'i18next';
import {
  AppWindow,
  Copy,
  Cpu,
  KeyRound,
  type LucideIcon,
  RectangleEllipsis,
  Server,
  SquareTerminal,
  TimerReset,
  UserRound,
} from 'lucide-react';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import type { Tone } from '@/components/ui/Tile';
import { algorithmBadge, keyTone } from '@/features/keys/model';
import { isConnectable } from '@/features/terminal/model';
import type { Scope, Searchable } from './search';

export type ItemScope = Exclude<Scope, 'all'> | 'keys';

export interface PaletteItem extends Searchable {
  scope: ItemScope;
  /** Next to the title: a host's address, an entry's user name. */
  detail?: string;
  /** What Enter does, at the end of the row. */
  action: string;
  /** A keyboard shortcut that does the same, shown with the action. */
  shortcut?: string;
  icon: LucideIcon;
  tone: Tone;
  run: () => void;
}

export interface PaletteHost {
  /** An alias, or a pattern block's patterns. */
  alias: string;
  user: string | null;
  hostName: string | null;
  /** The block in the config, for "Open host"; the quick window has none. */
  hostId?: number;
  /** A single name `ssh` can be started with. */
  connectable: boolean;
}

/** An entry as the palette needs it: never a secret. */
export type PaletteEntry = Pick<
  EntrySummary,
  'id' | 'title' | 'username' | 'url' | 'kind' | 'hasPassword' | 'hasOtp'
>;

/** The config's `Host` blocks: each alias once, and each pattern block as a whole. */
export function hostsOf(blocks: readonly HostEntry[]): PaletteHost[] {
  const hosts: PaletteHost[] = [];
  const seen = new Set<string>();
  for (const block of blocks) {
    if (block.kind !== 'host' || block.patterns.length === 0) continue;
    const base = { user: block.user, hostName: block.hostName, hostId: block.id };
    if (block.isWildcard) {
      hosts.push({ ...base, alias: block.patterns.join(' '), connectable: false });
      continue;
    }
    for (const alias of block.patterns) {
      if (seen.has(alias)) continue;
      seen.add(alias);
      hosts.push({ ...base, alias, connectable: isConnectable(alias) });
    }
  }
  return hosts;
}

const address = (host: Pick<PaletteHost, 'user' | 'hostName'>) =>
  [host.user, host.hostName].filter(Boolean).join('@');

export function hostItems(
  t: TFunction,
  hosts: readonly PaletteHost[],
  run: { connect: (alias: string) => void; open?: (hostId: number) => void },
): PaletteItem[] {
  const items: PaletteItem[] = [];
  for (const host of hosts) {
    const detail = address(host) || undefined;
    const keywords = [host.hostName, host.user].filter((word): word is string => Boolean(word));
    const base = { title: host.alias, detail, keywords, scope: 'hosts' as const };
    if (host.connectable) {
      items.push({
        ...base,
        id: `host:${host.alias}:connect`,
        action: t('palette.verbs.connect'),
        verbs: [t('palette.verbs.connect'), 'connect', 'ssh', 'terminal'],
        primary: true,
        icon: SquareTerminal,
        tone: 'green',
        run: () => run.connect(host.alias),
      });
    }
    const { open } = run;
    const hostId = host.hostId;
    if (open && hostId !== undefined) {
      items.push({
        ...base,
        id: `host:${host.alias}:open`,
        action: t('palette.verbs.openHost'),
        verbs: [t('palette.verbs.openHost'), 'open', 'host', 'edit'],
        primary: !host.connectable,
        icon: Server,
        tone: 'blue',
        run: () => open(hostId),
      });
    }
  }
  return items;
}

export function keyItems(
  t: TFunction,
  keys: readonly KeyView[],
  run: {
    open: (key: KeyView) => void;
    copyPublic: (key: KeyView) => void;
    addToAgent: (key: KeyView) => void;
  },
): PaletteItem[] {
  return keys.flatMap((key) => {
    const base = {
      title: key.name,
      detail: [algorithmBadge(key), key.comment].filter(Boolean).join(' · '),
      keywords: [key.comment, key.fingerprint ?? ''].filter(Boolean),
      scope: 'keys' as const,
      tone: keyTone(key),
    };
    const items: PaletteItem[] = [
      {
        ...base,
        id: `key:${key.id}:open`,
        action: t('palette.verbs.openKey'),
        verbs: [t('palette.verbs.openKey'), 'open', 'key'],
        primary: true,
        icon: KeyRound,
        run: () => run.open(key),
      },
    ];
    if (key.publicKey) {
      items.push({
        ...base,
        id: `key:${key.id}:copy`,
        action: t('palette.verbs.copyPublic'),
        verbs: [t('palette.verbs.copyPublic'), 'copy', 'public', 'pub'],
        icon: Copy,
        run: () => run.copyPublic(key),
      });
    }
    if (key.privatePath && !key.inAgent) {
      items.push({
        ...base,
        id: `key:${key.id}:agent`,
        action: t('palette.verbs.addToAgent'),
        verbs: [t('palette.verbs.addToAgent'), 'add', 'agent', 'load'],
        icon: Cpu,
        run: () => run.addToAgent(key),
      });
    }
    return items;
  });
}

/** What can be copied from an entry, through the backend (`vault_copy`). */
export type EntryCopy = 'password' | 'username' | 'otp';

function siteOf(url: string): string {
  try {
    return new URL(url).host || url;
  } catch {
    return url;
  }
}

export function entryItems(
  t: TFunction,
  entries: readonly PaletteEntry[],
  run: { copy: (entry: PaletteEntry, field: EntryCopy) => void; open?: (id: string) => void },
): PaletteItem[] {
  return entries.flatMap((entry) => {
    const base = {
      title: entry.title || entry.username || siteOf(entry.url),
      detail: [entry.username, siteOf(entry.url)].filter(Boolean).join(' · ') || undefined,
      keywords: [entry.username, entry.url].filter(Boolean),
      scope: 'passwords' as const,
      tone: 'pink' as const,
    };
    const copy = (
      field: EntryCopy,
      action: string,
      words: string[],
      icon: LucideIcon,
      primary = false,
    ): PaletteItem => ({
      ...base,
      id: `entry:${entry.id}:${field}`,
      action,
      verbs: [action, 'copy', ...words],
      primary,
      icon,
      run: () => run.copy(entry, field),
    });
    const items: PaletteItem[] = [];
    if (entry.hasPassword) {
      const label =
        entry.kind === 'key' ? t('palette.verbs.copyPassphrase') : t('palette.verbs.copyPassword');
      items.push(
        copy('password', label, ['password', 'passphrase', 'pass'], RectangleEllipsis, true),
      );
    }
    if (entry.username) {
      items.push(
        copy('username', t('palette.verbs.copyUsername'), ['user', 'username', 'login'], UserRound),
      );
    }
    if (entry.hasOtp) {
      items.push(
        copy('otp', t('palette.verbs.copyOtp'), ['otp', '2fa', 'code', 'totp'], TimerReset),
      );
    }
    const { open } = run;
    if (open) {
      items.push({
        ...base,
        id: `entry:${entry.id}:open`,
        action: t('palette.verbs.openEntry'),
        verbs: [t('palette.verbs.openEntry'), 'open', 'entry'],
        primary: items.length === 0,
        icon: AppWindow,
        run: () => open(entry.id),
      });
    }
    return items;
  });
}
