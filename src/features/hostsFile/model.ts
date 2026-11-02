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
