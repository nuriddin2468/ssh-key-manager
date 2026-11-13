import type { EntrySummary } from '@/bindings/EntrySummary';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostOption } from '@/bindings/HostOption';
import type { Tone } from '@/components/ui/Tile';

/** Options the form edits with dedicated controls; everything else is listed as is. */
const COMMON = ['hostname', 'user', 'port', 'proxyjump', 'forwardagent'];
/**
 * How a concrete host signs in. Patterns keep these in the generic list:
 * they set defaults for many hosts, which the sign-in section doesn't model.
 */
const SIGN_IN = ['identityfile', 'identitiesonly', 'pubkeyauthentication'];

/**
 * An option row in the form; `uid` keeps React rows stable while editing.
 * `loaded`: the row came from the file (only those can be set aside by the
 * sign-in method, see `suppressedOption`).
 */
export type OptionRow = HostOption & { uid: number; loaded?: boolean };

let lastUid = 0;
export const optionRow = (key = '', value = '', loaded = false): OptionRow => ({
  key,
  value,
  uid: ++lastUid,
  ...(loaded ? { loaded } : {}),
});

/**
 * How `ssh` signs in to a host:
 * - `key`: with a key only (a saved password isn't used);
 * - `password`: with the password; `PubkeyAuthentication no` keeps keys out;
 * - `both`: the key first, then the password.
 *
 * `key` and `both` write the same config; the vault tells them apart (a
 * password saved for the host means `both`).
 */
export type SignInMethod = 'key' | 'password' | 'both';

/** How the editor's subtitle names each method (translation keys). */
export const METHOD_LABEL = {
  key: 'hosts.signIn.labelKey',
  password: 'hosts.signIn.labelPassword',
  both: 'hosts.signIn.labelBoth',
} as const satisfies Record<SignInMethod, string>;

/** The sign-in options a block had when the form was made from it. */
export interface SavedSignIn {
  /** `both` is saved as `key`: the config can't tell them apart. */
  method: 'key' | 'password';
  identityFile: string;
  identitiesOnly: boolean;
}

export interface HostForm {
  patterns: string;
  hostName: string;
  user: string;
  port: string;
  /**
   * How `ssh` signs in; `null` for a pattern block, whose `IdentityFile` and
   * the like stay in `other`.
   */
  method: SignInMethod | null;
  /** The key to offer; empty: any key from the agent and `~/.ssh`. */
  identityFile: string;
  /** `IdentitiesOnly yes`: offer only `identityFile`. */
  identitiesOnly: boolean;
  proxyJump: string;
  forwardAgent: boolean;
  other: OptionRow[];
  /**
   * The block's sign-in options as saved; `null` for a new block. While the
   * form still says the same (the method may have gone away and back), they
   * are written back exactly as they were; once it says otherwise, the
   * method's mapping (`signInOptions`) decides.
   */
  saved: SavedSignIn | null;
}

export const EMPTY_FORM: HostForm = {
  patterns: '',
  hostName: '',
  user: '',
  port: '',
  method: 'key',
  identityFile: '',
  identitiesOnly: true,
  proxyJump: '',
  forwardAgent: false,
  other: [],
  saved: null,
};

const yes = (value: string | undefined) => value?.toLowerCase() === 'yes';

/** A block `ssh` can be run with by name: a `Host` without wildcards. */
export const isConcrete = (host: HostEntry) => host.kind === 'host' && !host.isWildcard;

/** How a host signs in, by the same rule as its form; `null` for patterns. */
export function hostMethod(host: HostEntry, passwordSaved: boolean): SignInMethod | null {
  return formFromHost(host, { passwordSaved }).method;
}

/**
 * The form for a block. The sign-in method of a concrete host:
 * `PubkeyAuthentication no` means `password`; otherwise a password saved in
 * the vault for it (`passwordSaved`) means `both`; otherwise `key`.
 */
export function formFromHost(
  host: HostEntry,
  { passwordSaved = false }: { passwordSaved?: boolean } = {},
): HostForm {
  const concrete = isConcrete(host);
  const known = concrete ? [...COMMON, ...SIGN_IN] : COMMON;
  // The first occurrence of a known keyword gets its control; repeats (a
  // second IdentityFile, say) stay in the generic list so nothing is lost.
  // `PubkeyAuthentication` has a control only for `no` (the Password method).
  const values = new Map<string, string>();
  const seen = new Set<string>();
  const other = host.options.filter((option) => {
    const key = option.key.toLowerCase();
    if (!known.includes(key) || seen.has(key)) return true;
    seen.add(key);
    if (key === 'pubkeyauthentication' && option.value.toLowerCase() !== 'no') return true;
    values.set(key, option.value);
    return false;
  });
  const identityFile = values.get('identityfile') ?? '';
  const identitiesOnly = yes(values.get('identitiesonly'));
  const pubkeyOff = values.has('pubkeyauthentication');
  return {
    patterns: host.patterns.join(' '),
    hostName: values.get('hostname') ?? '',
    user: values.get('user') ?? '',
    port: values.get('port') ?? '',
    method: concrete ? (pubkeyOff ? 'password' : passwordSaved ? 'both' : 'key') : null,
    identityFile,
    identitiesOnly,
    proxyJump: values.get('proxyjump') ?? '',
    forwardAgent: yes(values.get('forwardagent')),
    other: other.map((option) => optionRow(option.key, option.value, true)),
    saved: concrete
      ? { method: pubkeyOff ? 'password' : 'key', identityFile, identitiesOnly }
      : null,
  };
}

/** The method as the config sees it: `key` and `both` write the same block. */
export const configMethod = (method: SignInMethod) => (method === 'password' ? 'password' : 'key');

/** The form's sign-in options are still the ones the block was saved with. */
export function signInUnchanged(form: HostForm): boolean {
  const { saved, method } = form;
  return (
    saved !== null &&
    method !== null &&
    configMethod(method) === saved.method &&
    form.identityFile === saved.identityFile &&
    form.identitiesOnly === saved.identitiesOnly
  );
}

/**
 * The sign-in options the form writes:
 *
 * | Method           | Writes                                     | Removes                   |
 * |------------------|--------------------------------------------|---------------------------|
 * | Key, specific    | `IdentityFile`, `IdentitiesOnly yes` if on | `PubkeyAuthentication no` |
 * | Key, any         | —                                          | `IdentityFile`, `IdentitiesOnly`, `PubkeyAuthentication no` |
 * | Password         | `PubkeyAuthentication no`                  | `IdentityFile`, `IdentitiesOnly` |
 * | Key and password | as Key                                     | `PubkeyAuthentication no` |
 *
 * Until the sign-in options change, the saved ones are written back as they
 * were (an `IdentityFile` next to `PubkeyAuthentication no`, say).
 */
export function signInOptions(form: HostForm): HostOption[] {
  if (form.method === null) return [];
  const unchanged = signInUnchanged(form);
  const password = form.method === 'password';
  const file = form.identityFile.trim();
  const options: HostOption[] = [];
  if (!password || unchanged) {
    if (file) options.push({ key: 'IdentityFile', value: file });
    if (form.identitiesOnly && (file || unchanged)) {
      options.push({ key: 'IdentitiesOnly', value: 'yes' });
    }
  }
  if (password) options.push({ key: 'PubkeyAuthentication', value: 'no' });
  return options;
}

/**
 * A row from the file that the sign-in method removes (a second
 * `IdentityFile` once the method is Password, say). The form keeps it, so
 * switching back brings it back, but it is neither shown nor written.
 */
export function suppressedOption(form: HostForm, row: OptionRow): boolean {
  if (!row.loaded || form.method === null || signInUnchanged(form)) return false;
  const { key, value } = splitOption(row);
  const name = key.toLowerCase();
  if (form.method === 'password') return SIGN_IN.includes(name);
  if (name === 'pubkeyauthentication') return value.toLowerCase() === 'no';
  if (!form.identityFile.trim()) return name === 'identityfile' || name === 'identitiesonly';
  return false;
}

/**
 * Picks the key to offer (`''`: any key). Going from any key to a specific
 * one turns "Only offer this key" on, so ssh doesn't try every key first.
 */
export function chooseKey(form: HostForm, file: string): HostForm {
  const identitiesOnly = !form.identityFile && file ? true : form.identitiesOnly;
  return { ...form, identityFile: file, identitiesOnly };
}

export function editFromForm(form: HostForm, id: number | null): HostEdit {
  const options: HostOption[] = [];
  const push = (key: string, value: string) => {
    if (value.trim()) options.push({ key, value: value.trim() });
  };
  push('HostName', form.hostName);
  push('User', form.user);
  push('Port', form.port);
  options.push(...signInOptions(form));
  push('ProxyJump', form.proxyJump);
  if (form.forwardAgent) push('ForwardAgent', 'yes');
  for (const option of form.other) {
    if (suppressedOption(form, option)) continue;
    const { key, value } = splitOption(option);
    if (key) options.push({ key, value });
  }
  return { id, patterns: form.patterns.split(/\s+/).filter(Boolean), options };
}

/** The two forms write the same block. */
export function sameEdit(a: HostForm, b: HostForm, id: number | null): boolean {
  return JSON.stringify(editFromForm(a, id)) === JSON.stringify(editFromForm(b, id));
}

/**
 * The edit that points `host` at the key file `file`, through the same form
 * model as the editor, so every other option is kept:
 * - unless the block already lists the key (`isKey` recognises another
 *   spelling of its path), it becomes the first `IdentityFile`, and the ones
 *   listed before stay after it;
 * - `identitiesOnly` turns `IdentitiesOnly yes` on; it never turns it off;
 * - a host that signed in with a password alone tries the key from now on
 *   (`PubkeyAuthentication no` goes).
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
  if (form.method === 'password') form.method = 'key';
  const edit = editFromForm(form, host.id);
  return { edit, changed: !sameEdit(form, before, host.id) };
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

export interface PreviewLine {
  key: string;
  value: string;
  header: boolean;
}

/** The block as it will be written, for the preview. */
export function previewLines(edit: HostEdit): PreviewLine[] {
  return [
    { key: 'Host', value: edit.patterns.join(' ') || '…', header: true },
    ...edit.options.map((option) => ({ ...option, header: false })),
  ];
}

/**
 * Which preview lines the saved block doesn't have as they are: a new or
 * changed header or option. Options match by keyword (in any case) and
 * value, each saved line once.
 */
export function changedLines(lines: readonly PreviewLine[], saved: HostEntry): boolean[] {
  const left = saved.options.map((o) => `${o.key.toLowerCase()} ${o.value}`);
  return lines.map((line) => {
    if (line.header) return line.value !== saved.patterns.join(' ');
    const index = left.indexOf(`${line.key.toLowerCase()} ${line.value}`);
    if (index === -1) return true;
    left.splice(index, 1);
    return false;
  });
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

export function hostMonogram(host: Pick<HostEntry, 'kind' | 'patterns' | 'isWildcard'>): {
  text: string;
  tone: Tone;
} {
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

/** Git hosting services by the host names their SSH servers answer on. */
const GIT_SERVICES: [domain: string, name: string][] = [
  ['github.com', 'GitHub'],
  ['gitlab.com', 'GitLab'],
  ['bitbucket.org', 'Bitbucket'],
  ['codeberg.org', 'Codeberg'],
  ['ssh.dev.azure.com', 'Azure DevOps'],
  ['vs-ssh.visualstudio.com', 'Azure DevOps'],
];

/**
 * The git service a host signs in to, which gives no shell (so the editor
 * offers Check rather than Connect): a known service by its address or alias
 * (`ssh.github.com` and the like too), or any server whose user is `git`.
 * `null` for other hosts.
 */
export function gitService(host: HostEntry): string | null {
  if (!isConcrete(host)) return null;
  const names = [host.hostName, ...host.patterns]
    .filter((name): name is string => Boolean(name))
    .map((name) => name.toLowerCase());
  for (const [domain, service] of GIT_SERVICES) {
    if (names.some((name) => name === domain || name.endsWith(`.${domain}`))) return service;
  }
  if (host.user === 'git') return host.hostName ?? host.patterns[0] ?? null;
  return null;
}

/** The account a git service greets you as, read from what `ssh` printed. */
export function gitAccount(output: string): string | null {
  const greetings = [
    // GitHub; Gitea, Forgejo and Codeberg say "Hi there, name!".
    /Hi(?: there,)? ([^!\s]+)! You.ve successfully authenticated/,
    /Welcome to GitLab, @([^!\s]+)!/,
    /logged in as ([^\s.]+)/,
  ];
  for (const greeting of greetings) {
    const match = greeting.exec(output);
    if (match?.[1]) return match[1];
  }
  return null;
}

/**
 * The entry for `alias`'s password, as the backend's `host_entry` picks it:
 * of the host entries outside the recycle bin that name it, the one made
 * first (one without a time counting as older still), then by id. Titles
 * don't decide, so an entry made later never takes the place of another.
 */
export function hostEntry<T extends EntrySummary>(
  entries: readonly T[],
  alias: string,
): T | undefined {
  let first: T | undefined;
  for (const entry of entries) {
    if (entry.kind !== 'host' || entry.inTrash || entry.host !== alias) continue;
    if (first === undefined || madeBefore(entry, first)) first = entry;
  }
  return first;
}

/** Whether `a` was made before `b`: one without a time first, then by time, then by id. */
function madeBefore(a: EntrySummary, b: EntrySummary): boolean {
  if ((a.created === null) !== (b.created === null)) return a.created === null;
  if (a.created !== b.created) return (a.created ?? '') < (b.created ?? '');
  return a.id < b.id;
}
