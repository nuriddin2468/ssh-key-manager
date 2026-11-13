// Mock SSH tools of the Tools page (src-tauri/src/commands/ssh_tools.rs):
// tunnels that come up after a moment (one asks for a passphrase, one finds
// its port taken), ProxyJump edits of the mock config, a PuTTY key to convert
// and `authorized_keys` lines built as the core builds them.

import type { AuthorizedLine } from '@/bindings/AuthorizedLine';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostOption } from '@/bindings/HostOption';
import type { KeyFileFormat } from '@/bindings/KeyFileFormat';
import type { KeyFileInfo } from '@/bindings/KeyFileInfo';
import type { KeyInstall } from '@/bindings/KeyInstall';
import type { KeyView } from '@/bindings/KeyView';
import type { LineOptions } from '@/bindings/LineOptions';
import type { LineProblem } from '@/bindings/LineProblem';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { PromptRequest } from '@/bindings/PromptRequest';
import type { Tunnel } from '@/bindings/Tunnel';
import type { TunnelFailure } from '@/bindings/TunnelFailure';
import type { TunnelState } from '@/bindings/TunnelState';
import type { TunnelView } from '@/bindings/TunnelView';

type Handler = (args: Record<string, unknown>) => unknown;

interface Config {
  hosts: () => HostEntry[];
  config: () => ConfigFile;
  revision: () => string;
  /** Replaces a host block's options. */
  setOptions: (id: number, options: HostOption[]) => void;
  keys: () => KeyView[];
  addKey: (partial: Pick<KeyView, 'name' | 'fingerprint' | 'comment' | 'encrypted'>) => KeyView;
}

const fail = (code: string, message: string) => Promise.reject({ code, message });

interface Running {
  state: TunnelState;
  prompt: PromptRequest | null;
  timer?: ReturnType<typeof setTimeout>;
}

const tunnels: Tunnel[] = [
  {
    id: 'grafana',
    name: 'Grafana',
    alias: 'prod-api',
    kind: 'local',
    bindAddress: null,
    listenPort: 3000,
    targetHost: 'localhost',
    targetPort: 3000,
    autoReconnect: true,
  },
  {
    id: 'postgres',
    name: '',
    alias: 'bastion',
    kind: 'local',
    bindAddress: null,
    listenPort: 5432,
    targetHost: 'db.internal',
    targetPort: 5432,
    autoReconnect: false,
  },
  {
    id: 'preview',
    name: 'Preview for the team',
    alias: 'staging-api',
    kind: 'remote',
    bindAddress: '*',
    listenPort: 8080,
    targetHost: 'localhost',
    targetPort: 5173,
    autoReconnect: false,
  },
  {
    id: 'socks',
    name: '',
    alias: 'old-vpn',
    kind: 'dynamic',
    bindAddress: null,
    listenPort: 1080,
    targetHost: null,
    targetPort: null,
    autoReconnect: false,
  },
];

const now = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');

const running = new Map<string, Running>([
  ['grafana', { state: { state: 'up', since: now() }, prompt: null }],
]);
const ended = new Map<string, TunnelFailure>([
  [
    'socks',
    {
      reason: 'connectionLost',
      exitCode: 255,
      output: 'Timeout, server vpn.example.org not responding.',
    },
  ],
]);
let nextPrompt = 0;

function bracketed(host: string) {
  return host.includes(':') ? `[${host}]` : host;
}

function listenOf(tunnel: Tunnel) {
  const bind = tunnel.bindAddress ?? (tunnel.kind === 'remote' ? null : 'localhost');
  return bind ? `${bracketed(bind)}:${tunnel.listenPort}` : String(tunnel.listenPort);
}

function view(tunnel: Tunnel): TunnelView {
  const run = running.get(tunnel.id);
  const failure = ended.get(tunnel.id);
  const state: TunnelState =
    run?.state ?? (failure ? { state: 'failed', failure } : { state: 'off' });
  const target = `${bracketed(tunnel.targetHost ?? '')}:${tunnel.targetPort ?? ''}`;
  const keyword =
    tunnel.kind === 'local'
      ? 'LocalForward'
      : tunnel.kind === 'remote'
        ? 'RemoteForward'
        : 'DynamicForward';
  const host =
    !tunnel.bindAddress || ['*', '0.0.0.0', '::'].includes(tunnel.bindAddress)
      ? 'localhost'
      : bracketed(tunnel.bindAddress);
  return {
    tunnel,
    state,
    prompt: run?.prompt ?? null,
    browserUrl:
      tunnel.kind === 'local'
        ? `${[443, 8443].includes(tunnel.targetPort ?? 0) ? 'https' : 'http'}://${host}:${tunnel.listenPort}/`
        : null,
    exposed:
      tunnel.bindAddress !== null &&
      tunnel.bindAddress !== 'localhost' &&
      !['127.0.0.1', '::1'].includes(tunnel.bindAddress),
    configLine:
      tunnel.kind === 'dynamic'
        ? `${keyword} ${listenOf(tunnel)}`
        : `${keyword} ${listenOf(tunnel)} ${target}`,
  };
}

function find(id: unknown) {
  return tunnels.find((t) => t.id === id);
}

/** What happens once `ssh` has been "starting" for a moment. */
function connect(tunnel: Tunnel) {
  const run: Running = { state: { state: 'connecting', attempt: 1 }, prompt: null };
  running.set(tunnel.id, run);
  ended.delete(tunnel.id);
  run.timer = setTimeout(() => {
    if (running.get(tunnel.id) !== run) return;
    if (tunnel.alias === 'bastion') {
      nextPrompt += 1;
      run.prompt = {
        id: nextPrompt,
        ask: {
          type: 'passphrase',
          key: '/Users/dev/.ssh/id_ed25519_work',
          retry: false,
          save: 'new',
        },
      };
    } else if (tunnel.listenPort === 8000) {
      stop(tunnel.id);
      ended.set(tunnel.id, {
        reason: 'portUnavailable',
        exitCode: 255,
        output:
          'bind [127.0.0.1]:8000: Address already in use\n' +
          'channel_setup_fwd_listener_tcpip: cannot listen to port: 8000\n' +
          'Could not request local forwarding.',
      });
    } else {
      run.state = { state: 'up', since: now() };
    }
  }, 1400);
}

function stop(id: string) {
  const run = running.get(id);
  if (run?.timer) clearTimeout(run.timer);
  running.delete(id);
}

function validate(tunnel: Tunnel): string | null {
  const port = (n: number | null) => n !== null && Number.isInteger(n) && n >= 1 && n <= 65535;
  if (!/^[A-Za-z0-9._@:[\]-]+$/.test(tunnel.alias) || tunnel.alias.startsWith('-'))
    return 'not a host alias';
  if (!port(tunnel.listenPort)) return 'the port must be from 1 to 65535';
  if (tunnel.kind !== 'dynamic') {
    if (!tunnel.targetHost || !/^[A-Za-z0-9._:-]+$/.test(tunnel.targetHost))
      return 'the destination must be a host name or an IP address';
    if (!port(tunnel.targetPort)) return 'the destination port must be from 1 to 65535';
  }
  return null;
}

// --- authorized_keys line, as `sshkm_core::authorized_line` builds it -------

function isPattern(pattern: string): boolean {
  const body = pattern.startsWith('!') ? pattern.slice(1) : pattern;
  const [address, bits, extra] = body.split('/');
  if (bits !== undefined) {
    return extra === undefined && /^[0-9a-fA-F.:]+$/.test(address ?? '') && /^\d{1,3}$/.test(bits);
  }
  return body.length > 0 && /^[A-Za-z0-9.\-_:*?]+$/.test(body);
}

function expiry(value: string): Date | null {
  const digits = value.replace(/[Zz]$/, '');
  if (!/^\d+$/.test(digits) || ![8, 12, 14].includes(digits.length)) return null;
  const part = (at: number, length = 2) => Number(digits.slice(at, at + length) || '0');
  const [y, mo, d, h, mi, s] = [part(0, 4), part(4), part(6), part(8), part(10), part(12)];
  const date = new Date(Date.UTC(y, mo - 1, d, h, mi, s));
  return date.getUTCMonth() === mo - 1 && date.getUTCDate() === d && h < 24 ? date : null;
}

function buildLine(publicKey: string, options: LineOptions): AuthorizedLine {
  const problems: LineProblem[] = [];
  const key = publicKey.trim();
  if (!key) problems.push({ kind: 'keyMissing' });
  else if (key.includes('PRIVATE KEY') || key.startsWith('PuTTY-User-Key-File-'))
    problems.push({ kind: 'keyPrivate' });
  else if (!/^(ssh-|ecdsa-|sk-)\S+ AAAA[A-Za-z0-9+/=]{20,}( \S.*)?$/.test(key))
    problems.push({ kind: 'keyInvalid' });
  const parts: string[] = options.restrict ? ['restrict'] : [];
  const patterns = options.from.map((p) => p.trim()).filter(Boolean);
  for (const pattern of patterns) {
    if (!isPattern(pattern)) problems.push({ kind: 'fromInvalid', pattern });
  }
  if (patterns.length > 0 && patterns.every((p) => p.startsWith('!')))
    problems.push({ kind: 'fromOnlyExcludes' });
  if (patterns.length > 0) parts.push(`from="${patterns.join(',')}"`);
  const command = options.command?.trim();
  if (command) {
    // biome-ignore lint/suspicious/noControlCharactersInRegex: control characters are what it refuses
    if (/[\u0000-\u001f]/.test(command)) problems.push({ kind: 'commandInvalid' });
    else parts.push(`command="${command.replaceAll('"', '\\"')}"`);
  }
  const until = options.expiryTime?.trim();
  if (until) {
    const date = expiry(until);
    if (!date) problems.push({ kind: 'expiryInvalid' });
    else if (date.getTime() < Date.now() - 24 * 3600 * 1000) problems.push({ kind: 'expiryPast' });
    else parts.push(`expiry-time="${until}"`);
  }
  if (!options.restrict) {
    if (options.noAgentForwarding) parts.push('no-agent-forwarding');
    if (options.noPortForwarding) parts.push('no-port-forwarding');
    if (options.noPty) parts.push('no-pty');
    if (options.noX11Forwarding) parts.push('no-X11-forwarding');
  }
  const keyOk = !problems.some((p) => p.kind.startsWith('key'));
  return {
    line: problems.length === 0 ? (parts.length ? `${parts.join(',')} ${key}` : key) : null,
    fingerprint: keyOk ? 'SHA256:UCUiLr7Pjs9wFFJMDByLgc3NrtdU344OgUM45wZPcIQ' : null,
    problems,
  };
}

// --- Key converter ----------------------------------------------------------

/** `ssh-keygen -lv` of the sample PuTTY key (the `ssh-key` crate's Ed25519 fixture). */
const SAMPLE = {
  publicKey:
    'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti user@example.com',
  sha256: 'SHA256:UCUiLr7Pjs9wFFJMDByLgc3NrtdU344OgUM45wZPcIQ',
  md5: 'MD5:ae:6f:ba:1b:70:2c:ae:c7:5c:ab:6e:4d:5e:d4:c7:23',
  randomart: [
    '+--[ED25519 256]--+',
    '|o+oO==+ o..      |',
    '|.o++Eo+o..       |',
    '|. +.oO.o . .     |',
    '| . o..B.. . .    |',
    '|  ...+ .S. o     |',
    '|  .o. . . . .    |',
    '|  o..    o       |',
    '|   B      .      |',
    '|  .o*            |',
    '+----[SHA256]-----+',
  ].join('\n'),
};

/** Passphrases that open the mock's encrypted files. */
const OPENS = new Set(['123', 'secret']);

function inspect(
  path: string,
  passphrase: string | null,
  keys: KeyView[],
): KeyFileInfo | Promise<never> {
  const stem = (path.split('/').pop() ?? 'key').replace(/\.[^.]+$/, '') || 'key';
  const inSsh = keys.find((k) => k.privatePath === path);
  if (inSsh) {
    const opened = !inSsh.encrypted || (passphrase !== null && OPENS.has(passphrase));
    if (inSsh.encrypted && passphrase && !opened) return fail('wrong_passphrase', 'wrong');
    return {
      format: 'openssh',
      algorithm: inSsh.algorithm,
      bits: inSsh.bits,
      comment: inSsh.comment,
      encrypted: Boolean(inSsh.encrypted),
      opened,
      fingerprints: {
        sha256: inSsh.fingerprint ?? SAMPLE.sha256,
        md5: SAMPLE.md5,
        randomart: SAMPLE.randomart,
        publicKey: inSsh.publicKey ?? SAMPLE.publicKey,
      },
      suggestedName: stem,
    };
  }
  const pem = path.endsWith('.pem');
  if (passphrase && !OPENS.has(passphrase)) return fail('wrong_passphrase', 'wrong');
  const opened = passphrase !== null;
  return {
    format: pem ? 'pkcs8' : 'ppk3',
    algorithm: opened || !pem ? 'ed25519' : null,
    bits: opened || !pem ? 256 : null,
    comment: opened || !pem ? 'user@example.com' : '',
    encrypted: true,
    opened,
    fingerprints:
      opened || !pem
        ? {
            sha256: SAMPLE.sha256,
            md5: SAMPLE.md5,
            randomart: SAMPLE.randomart,
            publicKey: SAMPLE.publicKey,
          }
        : null,
    suggestedName: stem,
  };
}

export function sshToolsHandlers(config: Config): Record<string, Handler> {
  const opens = (args: Record<string, unknown>) => {
    const info = inspect(
      String(args.path),
      (args.passphrase as string | null) ?? null,
      config.keys(),
    );
    if (info instanceof Promise) return info;
    if (info.encrypted && !info.opened) return fail('passphrase_required', 'passphrase');
    return info;
  };
  return {
    tunnel_list: () => tunnels.map(view),
    tunnel_save: ({ tunnel }) => {
      const input = tunnel as Tunnel;
      const problem = validate(input);
      if (problem) return fail('invalid_input', problem);
      const local = (t: Tunnel) => t.kind !== 'remote';
      const clash = tunnels.find(
        (t) =>
          t.id !== input.id &&
          t.listenPort === input.listenPort &&
          local(t) === local(input) &&
          (local(t) || t.alias === input.alias),
      );
      if (clash) return fail('already_exists', `port ${input.listenPort} is taken`);
      const saved: Tunnel = { ...input, id: input.id || `t${Date.now()}`, name: input.name.trim() };
      const index = tunnels.findIndex((t) => t.id === saved.id);
      if (index === -1) tunnels.push(saved);
      else tunnels[index] = saved;
      if (running.has(saved.id)) {
        stop(saved.id);
        connect(saved);
      }
      return view(saved);
    },
    tunnel_delete: ({ id }) => {
      stop(String(id));
      ended.delete(String(id));
      const index = tunnels.findIndex((t) => t.id === id);
      if (index !== -1) tunnels.splice(index, 1);
    },
    tunnel_set_on: ({ id, on }) => {
      const tunnel = find(id);
      if (!tunnel) return fail('not_found', 'no such tunnel');
      if (on) {
        if (!running.has(tunnel.id)) connect(tunnel);
      } else {
        stop(tunnel.id);
        ended.delete(tunnel.id);
      }
      return view(tunnel);
    },
    tunnel_answer: ({ id, prompt, answer }) => {
      const run = running.get(String(id));
      const tunnel = find(id);
      if (!run || !tunnel || run.prompt?.id !== prompt) return false;
      run.prompt = null;
      const given = answer as PromptAnswer;
      if (given.type === 'secret' && OPENS.has(given.value)) {
        run.state = { state: 'up', since: now() };
      } else {
        stop(tunnel.id);
        ended.set(tunnel.id, {
          reason: given.type === 'cancel' ? 'cancelled' : 'notAccepted',
          exitCode: 255,
          output: 'deploy@bastion.example.net: Permission denied (publickey).',
        });
      }
      return true;
    },
    tunnel_stop_all: () => {
      for (const id of [...running.keys()]) stop(id);
    },
    tunnel_export: ({ id, revision }) => {
      if (revision !== config.revision()) return fail('conflict', 'config changed');
      const tunnel = find(id);
      if (!tunnel) return fail('not_found', 'no such tunnel');
      const host = config
        .hosts()
        .find((h) => h.kind === 'host' && h.patterns.includes(tunnel.alias));
      if (!host) return fail('not_found', `no Host block names ${tunnel.alias}`);
      const [key = '', ...rest] = view(tunnel).configLine.split(' ');
      config.setOptions(host.id, [...host.options, { key, value: rest.join(' ') }]);
      return config.config();
    },
    set_proxy_jump: ({ jump, targets, revision }) => {
      if (revision !== config.revision()) return fail('conflict', 'config changed');
      for (const id of targets as number[]) {
        const host = config.hosts().find((h) => h.id === id);
        if (!host) return fail('not_found', `host block ${id}`);
        if (jump && host.patterns.includes(String(jump)))
          return fail('invalid_input', 'a host can’t jump through itself');
        const options = host.options.filter((o) => o.key.toLowerCase() !== 'proxyjump');
        const at = host.options.findIndex((o) => o.key.toLowerCase() === 'proxyjump');
        if (jump) {
          const line = { key: 'ProxyJump', value: String(jump) };
          if (at === -1) options.push(line);
          else options.splice(at, 0, line);
        }
        config.setOptions(id, options);
      }
      return config.config();
    },
    // The backend's file dialog: a PuTTY key in Downloads.
    key_convert_pick: () => '/Users/dev/Downloads/server-key.ppk',
    key_convert_inspect: ({ path, passphrase }) =>
      inspect(String(path), (passphrase as string | null) ?? null, config.keys()),
    key_convert_import: async (args) => {
      const info = await opens(args);
      const name = String(args.fileName);
      if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]*$/.test(name)) return fail('invalid_input', 'file name');
      if (config.keys().some((k) => k.name === name)) return fail('already_exists', name);
      return config.addKey({
        name,
        fingerprint: info.fingerprints?.sha256 ?? SAMPLE.sha256,
        comment: (args.comment as string | null) ?? info.comment,
        encrypted: Boolean(args.newPassphrase),
      });
    },
    key_convert_save: async (args) => {
      await opens(args);
      const format = args.format as KeyFileFormat;
      if (format === 'pem' && args.newPassphrase) return fail('unsupported', 'PEM');
      const stem =
        String(args.path)
          .split('/')
          .pop()
          ?.replace(/\.[^.]+$/, '') || 'key';
      const extension = format.startsWith('ppk')
        ? '.ppk'
        : format === 'openssh'
          ? '-openssh'
          : '.pem';
      return `/Users/dev/Downloads/${stem}${extension}`;
    },
    authorized_line: ({ publicKey, options }) =>
      buildLine(String(publicKey), options as LineOptions),
    install_authorized_line: ({ alias }): KeyInstall | Promise<never> => {
      if (alias === 'old-vpn') {
        return {
          ok: false,
          added: false,
          output: 'ssh: connect to host vpn.example.org port 22: Operation timed out',
          prompts: [],
        };
      }
      if (alias === 'staging-api') return { ok: true, added: false, output: '', prompts: [] };
      return { ok: true, added: true, output: '', prompts: [] };
    },
  };
}
