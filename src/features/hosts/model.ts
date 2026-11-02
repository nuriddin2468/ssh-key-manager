import type { HostEdit } from '@/bindings/HostEdit';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostOption } from '@/bindings/HostOption';
import type { Tone } from '@/components/ui/Tile';

/** Options the form edits with dedicated controls; everything else is listed as is. */
const KNOWN = [
  'hostname',
  'user',
  'port',
  'identityfile',
  'identitiesonly',
  'proxyjump',
  'forwardagent',
];

/** An option row in the form; `uid` keeps React rows stable while editing. */
export type OptionRow = HostOption & { uid: number };

let lastUid = 0;
export const optionRow = (key = '', value = ''): OptionRow => ({ key, value, uid: ++lastUid });

export interface HostForm {
  patterns: string;
  hostName: string;
  user: string;
  port: string;
  identityFile: string;
  proxyJump: string;
  identitiesOnly: boolean;
  forwardAgent: boolean;
  other: OptionRow[];
}

export const EMPTY_FORM: HostForm = {
  patterns: '',
  hostName: '',
  user: '',
  port: '',
  identityFile: '',
  proxyJump: '',
  identitiesOnly: true,
  forwardAgent: false,
  other: [],
};

const yes = (value: string | undefined) => value?.toLowerCase() === 'yes';

export function formFromHost(host: HostEntry): HostForm {
  const first = (key: string) => host.options.find((o) => o.key.toLowerCase() === key)?.value;
  // The first occurrence of a known keyword gets its control; repeats (a
  // second IdentityFile, say) stay in the generic list so nothing is lost.
  const seen = new Set<string>();
  const other = host.options.filter((option) => {
    const key = option.key.toLowerCase();
    if (KNOWN.includes(key) && !seen.has(key)) {
      seen.add(key);
      return false;
    }
    return true;
  });
  return {
    patterns: host.patterns.join(' '),
    hostName: first('hostname') ?? '',
    user: first('user') ?? '',
    port: first('port') ?? '',
    identityFile: first('identityfile') ?? '',
    proxyJump: first('proxyjump') ?? '',
    identitiesOnly: yes(first('identitiesonly')),
    forwardAgent: yes(first('forwardagent')),
    other: other.map((option) => optionRow(option.key, option.value)),
  };
}

export function editFromForm(form: HostForm, id: number | null): HostEdit {
  const options: HostOption[] = [];
  const push = (key: string, value: string) => {
    if (value.trim()) options.push({ key, value: value.trim() });
  };
  push('HostName', form.hostName);
  push('User', form.user);
  push('Port', form.port);
  push('IdentityFile', form.identityFile);
  if (form.identitiesOnly) push('IdentitiesOnly', 'yes');
  push('ProxyJump', form.proxyJump);
  if (form.forwardAgent) push('ForwardAgent', 'yes');
  for (const option of form.other) {
    const { key, value } = splitOption(option);
    if (key) options.push({ key, value });
  }
  return { id, patterns: form.patterns.split(/\s+/).filter(Boolean), options };
}

/**
 * The edit that points `host` at the key file `file`, through the same form
 * model as the editor, so every other option is kept:
 * - unless the block already lists the key (`isKey` recognises another
 *   spelling of its path), it becomes the first `IdentityFile`, and the ones
 *   listed before stay after it;
 * - `identitiesOnly` turns `IdentitiesOnly yes` on; it never turns it off.
 *
 * `changed` is false when the block already says all that.
 */
export function pointHostAtKey(
  host: HostEntry,
  file: string,
  options: { identitiesOnly: boolean; isKey?: (raw: string) => boolean },
): { edit: HostEdit; changed: boolean } {
  const isKey = options.isKey ?? ((raw: string) => raw === file);
  const before = formFromHost(host);
  const form: HostForm = { ...before, other: [...before.other] };
  const listed = [
    form.identityFile,
    ...form.other.filter((o) => o.key.toLowerCase() === 'identityfile').map((o) => o.value),
  ].some((value) => value !== '' && isKey(value));
  if (!listed) {
    if (form.identityFile) form.other.unshift(optionRow('IdentityFile', form.identityFile));
    form.identityFile = file;
  }
  if (options.identitiesOnly) form.identitiesOnly = true;
  const edit = editFromForm(form, host.id);
  const changed = JSON.stringify(edit) !== JSON.stringify(editFromForm(before, host.id));
  return { edit, changed };
}

/**
 * People often type a whole config line (`HostKeyAlias github.com`) into the
 * name field; treat that as name and value, the way ssh_config would.
 */
export function splitOption(option: HostOption): HostOption {
  const key = option.key.trim();
  const value = option.value.trim();
  if (value) return { key, value };
  const [first = '', ...rest] = key.split(/\s+/);
  return { key: first, value: rest.join(' ') };
}

/** Why an option row can't be saved, if it can't. */
export function optionProblem(option: HostOption): 'missingName' | 'oneWord' | null {
  const { key, value } = splitOption(option);
  if (!key && value) return 'missingName';
  if (/\s/.test(key)) return 'oneWord';
  return null;
}

/** The block as it will be written, for the preview. */
export function previewLines(edit: HostEdit): { key: string; value: string; header: boolean }[] {
  return [
    { key: 'Host', value: edit.patterns.join(' ') || '…', header: true },
    ...edit.options.map((option) => ({ ...option, header: false })),
  ];
}

export function validatePort(port: string): boolean {
  if (!port.trim()) return true;
  const value = Number(port);
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

/** `user@host:port via jump` — how the list describes a host. */
export function hostTarget(host: HostEntry, via: (jump: string) => string): string {
  const name = host.hostName ?? host.patterns[0] ?? '';
  let target = host.user ? `${host.user}@${name}` : name;
  if (host.port && host.port !== 22) target += `:${host.port}`;
  if (host.proxyJump && host.proxyJump.toLowerCase() !== 'none')
    target += ` ${via(host.proxyJump)}`;
  return target;
}

const MONO_TONES: Tone[] = ['indigo', 'teal', 'pink', 'orange', 'blue', 'violet', 'amber', 'rose'];

export function hostMonogram(host: HostEntry): { text: string; tone: Tone } {
  const label = host.kind === 'match' ? 'match' : (host.patterns[0] ?? '?');
  if (host.isWildcard && label.includes('*')) return { text: '*', tone: 'blue' };
  const words = label
    .replace(/^[^A-Za-z0-9]+/, '')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean);
  const text = (
    words.length > 1 ? `${words[0]?.[0] ?? ''}${words[1]?.[0] ?? ''}` : label.slice(0, 2)
  ).toUpperCase();
  let hash = 0;
  for (const char of label) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return { text: text || '?', tone: MONO_TONES[hash % MONO_TONES.length] ?? 'slate' };
}

export function hostLabel(host: HostEntry): string {
  return host.kind === 'match' ? `Match ${host.criteria ?? ''}`.trim() : host.patterns.join(' ');
}
