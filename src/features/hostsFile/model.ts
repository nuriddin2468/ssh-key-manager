import { Ban, Globe, Laptop, type LucideIcon, Network } from 'lucide-react';
import type { HostsAddressKind } from '@/bindings/HostsAddressKind';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { Tone } from '@/components/ui/Tile';

export const KIND_STYLE: Record<
  HostsAddressKind,
  {
    tone: Tone;
    Icon: LucideIcon;
    label:
      | 'hostsFile.kindLoopback'
      | 'hostsFile.kindBlocked'
      | 'hostsFile.kindPrivate'
      | 'hostsFile.kindPublic';
  }
> = {
  loopback: { tone: 'slate', Icon: Laptop, label: 'hostsFile.kindLoopback' },
  blocked: { tone: 'rose', Icon: Ban, label: 'hostsFile.kindBlocked' },
  private: { tone: 'indigo', Icon: Network, label: 'hostsFile.kindPrivate' },
  public: { tone: 'amber', Icon: Globe, label: 'hostsFile.kindPublic' },
};

/** The form resolvers compare names in: lower case, without a final dot. */
/** Longest group name, in characters, as the backend allows. */
export const MAX_GROUP_NAME = 64;

export function normalizeName(name: string): string {
  return name.replace(/\.$/, '').toLowerCase();
}

/** Same rule as `hosts_file::is_valid_name` in the core. */
export function isValidName(name: string): boolean {
  const bare = name.replace(/\.$/, '');
  return (
    bare.length > 0 &&
    bare.length <= 253 &&
    bare.split('.').every((label) => /^[A-Za-z0-9_-]{1,63}$/.test(label))
  );
}

/** An IPv4 or IPv6 literal, which needs no lookup. */
export function isAddress(value: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || value.includes(':');
}

export interface HostsMatch {
  entry: HostsFileEntry;
  /** The first line for its address family, which resolvers use. */
  used: boolean;
}

/** Turned-on entries that list `name`, in file order. */
export function lookupName(entries: readonly HostsFileEntry[], name: string): HostsMatch[] {
  const wanted = normalizeName(name);
  const families = new Set<boolean>();
  return entries
    .filter((entry) => entry.enabled && entry.names.some((n) => normalizeName(n) === wanted))
    .map((entry) => {
      const ipv6 = entry.address.includes(':');
      const used = !families.has(ipv6);
      families.add(ipv6);
      return { entry, used };
    });
}

/** Names the operating system relies on; same list as the core. */
const SYSTEM_NAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'localhost4',
  'localhost4.localdomain4',
  'localhost6',
  'localhost6.localdomain6',
  'broadcasthost',
  'ip6-localhost',
  'ip6-loopback',
  'ip6-localnet',
  'ip6-mcastprefix',
  'ip6-allnodes',
  'ip6-allrouters',
  'ip6-allhosts',
]);

export function isSystemName(name: string): boolean {
  return SYSTEM_NAMES.has(normalizeName(name));
}

/**
 * A line that lists a name the system needs (`127.0.0.1 localhost app.test`):
 * the core refuses to change it, so the app leaves it as it is. (`system` is
 * only set when every name on the line is one.)
 */
export function listsSystemName(entry: { names: readonly string[] }): boolean {
  return entry.names.some(isSystemName);
}

/**
 * A valid IPv4 or IPv6 address; IPv6 may carry a scope of up to 64 letters,
 * digits, `_`, `.` and `-` (`fe80::1%lo0`). Same rule as `parse_address` in the core.
 */
export function isIpAddress(value: string): boolean {
  const v4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  if (v4.test(value)) return true;
  const [address, scope, ...rest] = value.split('%');
  if (!address?.includes(':') || rest.length > 0) return false;
  if (scope !== undefined && !/^[A-Za-z0-9_.-]{1,64}$/.test(scope)) return false;
  // The URL parser drops tabs and line breaks, so they are refused here.
  if (/[\s\p{Cc}]/u.test(address)) return false;
  try {
    return new URL(`http://[${address}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

/** Splits the names field: whitespace-separated, empty ones dropped. */
export function splitNames(value: string): string[] {
  return value.split(/\s+/).filter(Boolean);
}

/** The expiry time `seconds` from now, as RFC 3339 in UTC. */
export function expiryIn(seconds: number, now = Date.now()): string {
  return new Date(Math.floor(now / 1000) * 1000 + seconds * 1000)
    .toISOString()
    .replace('.000Z', 'Z');
}

export function isExpired(expires: string | null, now = Date.now()): boolean {
  return expires !== null && Date.parse(expires) <= now;
}
