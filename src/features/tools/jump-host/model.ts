import type { HostEntry } from '@/bindings/HostEntry';
import { isPlainAlias } from '../ssh/parts';

/** The name the wizard tests a block by: its first plain alias. */
export function firstAlias(host: HostEntry): string {
  return host.patterns.find(isPlainAlias) ?? host.patterns[0] ?? '';
}

/** `ssh` uses whichever of ProxyCommand and ProxyJump comes first. */
export function hasProxyCommand(host: HostEntry): boolean {
  return host.options.some((option) => option.key.toLowerCase() === 'proxycommand');
}

/** What setting `ProxyJump jump` changes in each block: the lines it replaces. */
export function changesFor(
  hosts: readonly HostEntry[],
  jump: string,
): { host: HostEntry; removed: string[] }[] {
  return hosts
    .map((host) => ({
      host,
      removed: host.options
        .filter((option) => option.key.toLowerCase() === 'proxyjump')
        .map((option) => option.value),
    }))
    .filter(({ removed }) => !(removed.length === 1 && removed[0] === jump));
}
