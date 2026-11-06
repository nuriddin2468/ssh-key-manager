// What the network tools share: reading a host and a port as typed, the
// hosts of ~/.ssh/config to pick from, and how a connection's state reads.

import type { HostEntry } from '@/bindings/HostEntry';
import type { PortState } from '@/bindings/PortState';
import type { BadgeTone } from '@/components/ui/Badge';
import { isValidName } from '@/features/hostsFile/model';

/** A port as typed, or null when it isn't one. */
export function parsePort(text: string): number | null {
  const trimmed = text.trim();
  if (!/^\d{1,5}$/.test(trimmed)) return null;
  const port = Number(trimmed);
  return port >= 1 && port <= 65535 ? port : null;
}

/** A host name, an IPv4 address or an IPv6 address (with or without brackets). */
export function isHost(text: string): boolean {
  const value = text.trim();
  if (/^\[[0-9A-Fa-f:.]+\]$/.test(value)) return value.includes(':');
  if (/^[0-9A-Fa-f:.]+$/.test(value) && value.includes(':')) return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    return value.split('.').every((part) => Number(part) <= 255);
  }
  return isValidName(value) && !/^[\d.]+$/.test(value);
}

/** An IP address rather than a name, which DNS has nothing to say about. */
export function isAddress(text: string): boolean {
  const value = text.trim();
  return value.includes(':') || /^\d{1,3}(\.\d{1,3}){3}$/.test(value);
}

/** A host of ~/.ssh/config and where `ssh` connects for it. */
export interface ConfigTarget {
  alias: string;
  host: string;
  port: number;
  /** Its `ProxyJump`, when it is reached through another host. */
  jump: string | null;
}

/** The `Host` blocks for one name each (no patterns), in file order. */
export function configTargets(entries: readonly HostEntry[]): ConfigTarget[] {
  const out: ConfigTarget[] = [];
  for (const entry of entries) {
    if (entry.kind !== 'host' || entry.isWildcard) continue;
    for (const alias of entry.patterns) {
      if (alias.startsWith('!') || out.some((t) => t.alias === alias)) continue;
      const jump = entry.proxyJump?.trim();
      out.push({
        alias,
        host: entry.hostName?.trim() || alias,
        port: entry.port ?? 22,
        jump: jump && jump.toLowerCase() !== 'none' ? jump : null,
      });
    }
  }
  return out;
}

/** The badge colour of a connection's state. */
export const STATE_TONE: Record<PortState, BadgeTone> = {
  open: 'accent',
  closed: 'critical',
  noAnswer: 'warning',
  unreachable: 'critical',
  noAddress: 'warning',
};

/** `23.4` → `23`, `3.14` → `3.1`: milliseconds as people read them. */
export function formatMs(ms: number, locale: string): string {
  return new Intl.NumberFormat(locale, {
    maximumFractionDigits: ms < 10 ? 1 : 0,
  }).format(ms);
}
