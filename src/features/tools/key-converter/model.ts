import type { KeyFileFormat } from '@/bindings/KeyFileFormat';
import type { KeyFileInfo } from '@/bindings/KeyFileInfo';
import { algorithmBadge } from '@/features/keys/model';

/** The formats a key converts to, in the order the cards show them. */
export const FORMATS: readonly KeyFileFormat[] = ['openssh', 'ppk3', 'ppk2', 'pem', 'pkcs8'];

/** `ED25519`, `RSA 3072`, … */
export function algorithmText(info: KeyFileInfo): string {
  return info.algorithm
    ? algorithmBadge({ algorithm: info.algorithm, bits: info.bits, keyType: '' })
    : '';
}

/** Ed25519 has no PEM (PKCS#1 / SEC1) form. */
export function pemAllowed(info: KeyFileInfo): boolean {
  return info.algorithm !== 'ed25519';
}

/** Why `~/.ssh/<name>` won't do, as an error code; `null` if it will. */
export function fileNameProblem(
  name: string,
  taken: readonly string[],
): 'invalid_input' | 'already_exists' | null {
  const reserved = ['config', 'known_hosts', 'known_hosts2', 'authorized_keys', 'authorized_keys2'];
  if (
    !/^[A-Za-z0-9._-]{1,200}$/.test(name) ||
    name.startsWith('.') ||
    name.endsWith('.') ||
    name.toLowerCase().endsWith('.pub') ||
    reserved.includes(name.toLowerCase())
  ) {
    return 'invalid_input';
  }
  return taken.includes(name) ? 'already_exists' : null;
}

/** `base` as a key file name, with `-2`, `-3`… if the name is taken. */
export function uniqueName(base: string, taken: readonly string[]): string {
  const clean =
    base
      .replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^[.-]+|[.-]+$/g, '')
      .slice(0, 180) || 'key';
  if (!taken.includes(clean)) return clean;
  for (let n = 2; ; n += 1) {
    const candidate = `${clean}-${n}`;
    if (!taken.includes(candidate)) return candidate;
  }
}
