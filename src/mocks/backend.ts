// In-memory backend for `pnpm dev` in a plain browser. It mirrors the Tauri
// commands closely enough to build and review the UI; production builds
// never import it (see `call` in lib/ipc.ts).

import type { AgentView } from '@/bindings/AgentView';
import type { AuditReport } from '@/bindings/AuditReport';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { Environment } from '@/bindings/Environment';
import type { Finding } from '@/bindings/Finding';
import type { GenerateKeyRequest } from '@/bindings/GenerateKeyRequest';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostOption } from '@/bindings/HostOption';
import type { KeysView } from '@/bindings/KeysView';
import type { KeyView } from '@/bindings/KeyView';
import type { KnownHostEntry } from '@/bindings/KnownHostEntry';
import type { PermissionFix } from '@/bindings/PermissionFix';
import { terminalHandlers } from './terminal';
import { vaultHandlers } from './vault';
import { vaultFilesHandlers } from './vaultFiles';
import { vaultLinkHandlers } from './vaultLinks';

const HOME = '/Users/dev';
const DIR = `${HOME}/.ssh`;
const ok = { ok: true, mode: '600', problem: null } as const;

function key(partial: Partial<KeyView> & Pick<KeyView, 'name' | 'fingerprint'>): KeyView {
  return {
    id: `${partial.fingerprint}#${partial.name}`,
    privatePath: `${DIR}/${partial.name}`,
    publicPath: `${DIR}/${partial.name}.pub`,
    algorithm: 'ed25519',
    keyType: 'ssh-ed25519',
    bits: 256,
    comment: '',
    encrypted: true,
    hardware: false,
    format: 'openssh',
    publicKey: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI${partial.fingerprint?.slice(7, 40)} ${partial.comment ?? ''}`,
    modified: '2026-03-12T09:14:00Z',
    pairMismatch: false,
    permissions: ok,
    inAgent: false,
    usedBy: [],
    ...partial,
  };
}

let keys: KeyView[] = [
  key({
    name: 'id_ed25519',
    comment: 'dev@macbook-pro',
    fingerprint: 'SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw',
  }),
  key({
    name: 'id_ed25519_work',
    comment: 'work laptop',
    fingerprint: 'SHA256:Qm7Tz2LkP9wX4cVb1NrY8sHd3FgJ6aE0uKoBiWq5ZxR',
  }),
  key({
    name: 'id_rsa',
    comment: 'old-macbook',
    fingerprint: 'SHA256:u9Fh2KdL7pQ3zX8mV1bN6rT4wY0sGcJ5aE2iOkHjUyB',
    algorithm: 'rsa',
    keyType: 'ssh-rsa',
    bits: 2048,
    encrypted: false,
    publicKey:
      'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7vX2mN4kP8qR1sT5wY9zB3cF6hJ0lM2nQ4rU7xA1dG5iK8oS3vZ6yE9bH2jL4pN7tW0qC5fI8mR1uX4aD7gK0nP3sV6yB9eH2kM5qT8wZ1cF4iL7oR0uX3aD6gJ9mP2sV5yB8 old-macbook',
    modified: '2019-09-03T11:00:00Z',
    permissions: { ok: false, mode: '644', problem: 'groupOrOtherAccess' },
  }),
  key({
    name: 'deploy_ci',
    comment: 'github-actions deploy',
    fingerprint: 'SHA256:Ze4Wq8Tn1Lm6Xc3Vb9Rk2Hs7Dj5Fg0Ay8Up4Io1Ke6W',
    encrypted: false,
    modified: '2026-10-02T08:30:00Z',
  }),
  key({
    name: 'id_ecdsa_sk',
    comment: 'YubiKey 5C',
    fingerprint: 'SHA256:Bn5Rt1Yx9Lk3Pm7Qw2Zc6Vd0Hf4Js8Ga1Ue5Io9Kr3T',
    algorithm: 'skEcdsaP256',
    keyType: 'sk-ecdsa-sha2-nistp256@openssh.com',
    encrypted: false,
    hardware: true,
  }),
  key({
    name: 'old_server',
    comment: 'admin@old-server',
    fingerprint: 'SHA256:Hy2Gt6Rf0Ed4Ws8Qa3Zx7Cv1Bn5Mk9Lj2Hg6Fd0Sa4P',
    privatePath: null,
    algorithm: 'rsa',
    keyType: 'ssh-rsa',
    bits: 4096,
    encrypted: null,
    format: 'publicOnly',
    permissions: { ok: true, mode: '644', problem: null },
  }),
];

const agentLoaded = new Map<string, string | null>([
  ['SHA256:k3XbV9qL2mT8sRw4YzN1cJ6hD0fGpA5uE7oIiKjBnHw', null],
  [
    'SHA256:Qm7Tz2LkP9wX4cVb1NrY8sHd3FgJ6aE0uKoBiWq5ZxR',
    new Date(Date.now() + (3 * 3600 + 12 * 60) * 1000).toISOString(),
  ],
]);

const opt = (key: string, value: string): HostOption => ({ key, value });
let hostSpecs: { patterns: string[]; options: HostOption[] }[] = [
  {
    patterns: ['github.com'],
    options: [
      opt('User', 'git'),
      opt('IdentityFile', '~/.ssh/id_ed25519'),
      opt('IdentitiesOnly', 'yes'),
    ],
  },
  {
    patterns: ['gitlab.com'],
    options: [opt('User', 'git'), opt('IdentityFile', '~/.ssh/id_ed25519')],
  },
  {
    patterns: ['bastion'],
    options: [
      opt('HostName', 'bastion.example.net'),
      opt('User', 'deploy'),
      opt('Port', '2222'),
      opt('IdentityFile', '~/.ssh/id_ed25519_work'),
    ],
  },
  {
    patterns: ['prod-api'],
    options: [
      opt('HostName', '10.0.4.12'),
      opt('User', 'ubuntu'),
      opt('IdentityFile', '~/.ssh/id_ed25519_work'),
      opt('IdentitiesOnly', 'yes'),
      opt('ProxyJump', 'bastion'),
      opt('ServerAliveInterval', '60'),
    ],
  },
  {
    patterns: ['staging-api'],
    options: [
      opt('HostName', '10.0.8.20'),
      opt('User', 'ubuntu'),
      opt('IdentityFile', '~/.ssh/id_ed25519_work'),
      opt('ProxyJump', 'bastion'),
    ],
  },
  {
    patterns: ['legacy-nas'],
    options: [
      opt('HostName', '192.168.1.20'),
      opt('User', 'admin'),
      opt('IdentityFile', '~/.ssh/id_rsa'),
    ],
  },
  {
    patterns: ['old-vpn'],
    options: [
      opt('HostName', 'vpn.example.org'),
      opt('User', 'root'),
      opt('IdentityFile', '~/.ssh/vpn_key'),
    ],
  },
  { patterns: ['*'], options: [opt('AddKeysToAgent', 'yes'), opt('UseKeychain', 'yes')] },
];

let known: KnownHostEntry[] = [
  ['github.com', 'ssh-ed25519', 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU', 3],
  ['github.com', 'ecdsa-sha2-nistp256', 'SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM', 4],
  ['gitlab.com', 'ssh-ed25519', 'SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8', 7],
  [
    '[bastion.example.net]:2222',
    'ssh-ed25519',
    'SHA256:Vx3mK8qP1sT5wY9zB2cF6hJ0lN4rU7aD1gE5iO8kR3t',
    9,
  ],
  ['10.0.4.12', 'ecdsa-sha2-nistp256', 'SHA256:Lq9Wn2Tx6Bz0Hc4Vm8Rk1Ps5Yd3Fg7Ja0Ue2Io6Kt9N', 12],
  [null, 'ssh-ed25519', 'SHA256:Rt5Gy1Hu9Jk3Lm7Np2Qw6Xc0Vb4Zs8Df1Ae5Io3Ku7P', 14],
  [null, 'ssh-rsa', 'SHA256:Cv8Bn2Mk6Lj0Hg4Fd8Sa1Qw5Er9Ty3Ui7Op1As5Df9G', 15],
  ['192.168.1.20', 'ssh-rsa', 'SHA256:Wq4Er8Ty2Ui6Op0As4Df8Gh2Jk6Lz0Xc4Vb8Nm2Qw6E', 18],
].map(([host, keyType, fingerprint, line]) => ({
  line: line as number,
  marker: 'none',
  hosts: host ? [host as string] : [],
  hashed: host === null,
  keyType: keyType as string,
  fingerprint: fingerprint as string,
  comment: null,
}));
known.push({
  line: 21,
  marker: 'certAuthority',
  hosts: ['*.corp.example.com'],
  hashed: false,
  keyType: 'ssh-ed25519',
  fingerprint: 'SHA256:Ka7Sd1Fg5Hj9Kl3Zx7Cv1Bn5Mq9Wr3Ty7Ui1Op5As9D',
  comment: null,
});

function hosts(): HostEntry[] {
  let line = 1;
  return hostSpecs.map((spec, id) => {
    const first = (k: string) => spec.options.find((o) => o.key.toLowerCase() === k)?.value ?? null;
    const lineStart = line;
    line += spec.options.length + 2;
    const port = first('port');
    return {
      id,
      kind: 'host',
      patterns: spec.patterns,
      criteria: null,
      options: spec.options,
      hostName: first('hostname'),
      user: first('user'),
      port: port ? Number(port) : null,
      identityFiles: spec.options.filter((o) => o.key === 'IdentityFile').map((o) => o.value),
      proxyJump: first('proxyjump'),
      isWildcard: spec.patterns.some((p) => /[*?]/.test(p)),
      lineStart,
      lineEnd: lineStart + spec.options.length,
    };
  });
}

function configFile(): ConfigFile {
  const entries = hosts();
  const usage = entries.flatMap((host) =>
    host.identityFiles.map((raw) => {
      const path = raw.replace('~', HOME);
      return {
        hostId: host.id,
        patterns: host.patterns,
        path,
        raw,
        resolved: true,
        exists: keys.some((k) => k.privatePath === path || k.publicPath === path),
      };
    }),
  );
  return {
    path: `${DIR}/config`,
    exists: true,
    view: { globalOptions: [], hosts: entries, includes: [], issues: [] },
    usage,
  };
}

function keysView(): KeysView {
  const usage = configFile().usage;
  return {
    keys: keys.map((k) => ({
      ...k,
      inAgent: k.fingerprint !== null && agentLoaded.has(k.fingerprint),
      usedBy: usage
        .filter((u) => u.path === k.privatePath)
        .map((u) => ({ hostId: u.hostId, patterns: u.patterns })),
    })),
    skipped: [],
  };
}

function audit(): AuditReport {
  const findings: Finding[] = [];
  const subject = (keyId: string) => ({ keyId, hostId: null, path: null });
  for (const k of keys) {
    if (k.privatePath && !k.permissions.ok) {
      findings.push({
        id: `privateKeyPermissions:${k.id}`,
        severity: 'critical',
        kind: {
          kind: 'privateKeyPermissions',
          mode: k.permissions.mode,
          problem: 'groupOrOtherAccess',
        },
        subject: { ...subject(k.id), path: k.privatePath },
        fix: { kind: 'fixPermissions', path: k.privatePath, target: 'privateKey' },
      });
    }
    if (k.algorithm === 'rsa' && k.privatePath && (k.bits ?? 0) < 3072) {
      findings.push({
        id: `rsaBelowRecommended:${k.id}`,
        severity: 'warning',
        kind: { kind: 'rsaBelowRecommended', bits: k.bits ?? 0 },
        subject: subject(k.id),
        fix: null,
      });
    }
    if (k.privatePath && k.encrypted === false && !k.hardware) {
      findings.push({
        id: `unencryptedKey:${k.id}`,
        severity: 'warning',
        kind: { kind: 'unencryptedKey' },
        subject: subject(k.id),
        fix: { kind: 'addPassphrase', keyId: k.id },
      });
    }
    if (!k.privatePath) {
      findings.push({
        id: `orphanPublicKey:${k.id}`,
        severity: 'info',
        kind: { kind: 'orphanPublicKey' },
        subject: subject(k.id),
        fix: null,
      });
    }
  }
  for (const usage of configFile().usage.filter((u) => !u.exists)) {
    findings.push({
      id: `identityFileMissing:${usage.hostId}:${usage.raw}`,
      severity: 'warning',
      kind: { kind: 'identityFileMissing', path: usage.path, patterns: usage.patterns },
      subject: { keyId: null, hostId: usage.hostId, path: usage.path },
      fix: { kind: 'removeIdentityFile', hostId: usage.hostId, path: usage.raw },
    });
  }
  const order = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);
  const count = (s: Finding['severity']) => findings.filter((f) => f.severity === s).length;
  return {
    findings,
    counts: { critical: count('critical'), warning: count('warning'), info: count('info') },
  };
}

function agentView(): AgentView {
  const now = Date.now();
  for (const [fp, expires] of agentLoaded)
    if (expires && Date.parse(expires) < now) agentLoaded.delete(fp);
  return {
    status: {
      available: true,
      socket: '/private/tmp/com.apple.launchd.Xq3vR8/Listeners',
      identities: agentLoaded.size,
      error: null,
    },
    identities: [...agentLoaded].map(([fingerprint, expiresAt]) => {
      const k = keys.find((x) => x.fingerprint === fingerprint);
      return {
        fingerprint,
        algorithm: k?.algorithm ?? 'ed25519',
        keyType: k?.keyType ?? 'ssh-ed25519',
        bits: k?.bits ?? null,
        comment: k?.comment ?? '',
        publicKey: k?.publicKey ?? '',
        certificate: false,
        keyId: k?.id ?? null,
        expiresAt,
      };
    }),
  };
}

const fail = (code: string, message: string) => Promise.reject({ code, message });
const findKey = (id: unknown) => keys.find((k) => k.id === id);

const handlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  ...vaultHandlers,
  ...vaultLinkHandlers({ keys: () => keys, hosts, agent: agentLoaded }),
  ...vaultFilesHandlers,
  ...terminalHandlers(hosts),
  get_environment: (): Environment => ({
    paths: { home: HOME, dir: DIR, config: `${DIR}/config`, knownHosts: `${DIR}/known_hosts` },
    platform: 'macos',
    opensshVersion: 'OpenSSH_9.9p1',
    appVersion: '0.1.0',
    defaultComment: 'dev@macbook-pro',
    backupDir: `${HOME}/Library/Application Support/dev.sshkeymanager.desktop/backups`,
  }),
  list_keys: keysView,
  generate_key: ({ request }) => {
    const { key: req, addToAgent, agentLifetimeSecs } = request as GenerateKeyRequest;
    if (keys.some((k) => k.name === req.fileName)) return fail('already_exists', 'exists');
    const fingerprint = `SHA256:${Math.random().toString(36).slice(2, 12)}${Math.random().toString(36).slice(2, 12)}NewKeyAbcdEfGhIj`;
    const algo = req.algorithm;
    keys.push(
      key({
        name: req.fileName,
        comment: req.comment,
        fingerprint,
        encrypted: Boolean(req.passphrase),
        algorithm: algo.kind === 'rsa' ? 'rsa' : algo.kind === 'ecdsa' ? 'ecdsaP256' : 'ed25519',
        keyType:
          algo.kind === 'rsa'
            ? 'ssh-rsa'
            : algo.kind === 'ecdsa'
              ? 'ecdsa-sha2-nistp256'
              : 'ssh-ed25519',
        bits: algo.kind === 'rsa' ? algo.bits : 256,
        modified: new Date().toISOString(),
      }),
    );
    if (addToAgent) {
      agentLoaded.set(
        fingerprint,
        agentLifetimeSecs ? new Date(Date.now() + agentLifetimeSecs * 1000).toISOString() : null,
      );
    }
    return keysView().keys.find((k) => k.fingerprint === fingerprint);
  },
  change_passphrase: ({ keyId, old, new: next }) => {
    const k = findKey(keyId);
    if (!k) return fail('not_found', 'key');
    if (k.encrypted && old !== 'secret') return fail('wrong_passphrase', 'wrong passphrase');
    k.encrypted = Boolean(next);
    return keysView().keys.find((x) => x.id === keyId);
  },
  regenerate_public: ({ keyId }) => keysView().keys.find((x) => x.id === keyId),
  import_key: () => {
    keys.push(
      key({
        name: 'id_ed25519_laptop',
        comment: 'imported',
        fingerprint: 'SHA256:Imp0rtedKeyFingerprintAbCdEfGh1234567890xyz',
      }),
    );
    return keysView().keys.at(-1);
  },
  trash_key: ({ keyId }) => {
    keys = keys.filter((k) => k.id !== keyId);
  },
  agent_view: agentView,
  agent_add: ({ keyId, passphrase, lifetimeSecs }) => {
    const k = findKey(keyId);
    if (!k?.fingerprint) return fail('not_found', 'key');
    if (k.encrypted && passphrase !== 'secret') return fail('wrong_passphrase', 'wrong passphrase');
    agentLoaded.set(
      k.fingerprint,
      lifetimeSecs ? new Date(Date.now() + Number(lifetimeSecs) * 1000).toISOString() : null,
    );
  },
  agent_remove: ({ fingerprint }) => {
    agentLoaded.delete(fingerprint as string);
  },
  agent_remove_all: () => agentLoaded.clear(),
  read_config: configFile,
  save_host: ({ edit }) => {
    const { id, patterns, options } = edit as HostEdit;
    if (id === null) {
      const star = hostSpecs.findIndex((h) => h.patterns.join() === '*');
      const index = star === -1 ? hostSpecs.length : star;
      hostSpecs.splice(index, 0, { patterns, options });
      return { file: configFile(), id: index };
    }
    hostSpecs[id] = { patterns, options };
    return { file: configFile(), id };
  },
  delete_host: ({ id }) => {
    hostSpecs = hostSpecs.filter((_, index) => index !== id);
    return configFile();
  },
  remove_identity_file: ({ hostId, value }) => {
    const spec = hostSpecs[hostId as number];
    if (spec)
      spec.options = spec.options.filter((o) => !(o.key === 'IdentityFile' && o.value === value));
    return configFile();
  },
  read_config_raw: () =>
    hostSpecs
      .map((h) =>
        [`Host ${h.patterns.join(' ')}`, ...h.options.map((o) => `    ${o.key} ${o.value}`)].join(
          '\n',
        ),
      )
      .join('\n\n'),
  write_config_raw: configFile,
  test_connection: ({ alias }) =>
    alias === 'github.com'
      ? {
          ok: true,
          output:
            "Hi dev! You've successfully authenticated, but GitHub does not provide shell access.",
          prompts: [],
        }
      : {
          ok: false,
          // Batch mode: an unknown host key fails outright, and servers
          // that want a password turn every key down.
          output:
            alias === 'legacy-nas'
              ? 'Host key verification failed.'
              : ['prod-api', 'staging-api', 'bastion'].includes(String(alias))
                ? `ubuntu@${alias}: Permission denied (publickey,password).`
                : `ssh: connect to host ${alias} port 22: Operation timed out`,
          prompts: [],
        },
  install_public_key: ({ alias }) => ({
    ok: false,
    added: false,
    output: `deploy@${alias}: Permission denied (publickey,password).`,
    prompts: [],
  }),
  read_known_hosts: () => ({
    path: `${DIR}/known_hosts`,
    exists: true,
    view: { entries: known, invalid: [] },
  }),
  find_known_hosts: ({ host }) => (host === 'example.org' ? [14] : []),
  remove_known_hosts: ({ lines }) => {
    known = known.filter((e) => !(lines as number[]).includes(e.line));
    return { path: `${DIR}/known_hosts`, exists: true, view: { entries: known, invalid: [] } };
  },
  check_host_key: ({ host }) => {
    const saved = known.filter((e) => e.hosts.includes(host as string));
    if (host === 'unreachable.test')
      return { status: 'failed', offered: [], saved, error: 'no answer' };
    const offered = [
      {
        keyType: 'ssh-ed25519',
        fingerprint: saved[0]?.fingerprint ?? 'SHA256:Fr3shK3yOfferedByTheServerRightNow0123456',
      },
    ];
    if (host === '192.168.1.20') {
      return {
        status: 'changed',
        offered: [
          {
            keyType: 'ssh-ed25519',
            fingerprint: 'SHA256:N3wServerKeyAfterReinstall0000000000000000',
          },
        ],
        saved,
        error: null,
      };
    }
    return { status: saved.length ? 'match' : 'unknown', offered, saved, error: null };
  },
  run_audit: audit,
  fix_permissions: ({ items }) => {
    for (const item of items as PermissionFix[]) {
      const k = keys.find((x) => x.privatePath === item.path);
      if (k) k.permissions = ok;
    }
    return (items as unknown[]).length;
  },
};

/** Keystrokes must keep their order, so they skip the simulated latency. */
const INSTANT = new Set(['terminal_write', 'terminal_resize', 'terminal_answer']);

export async function invoke(
  command: string,
  args: Record<string, unknown> = {},
): Promise<unknown> {
  if (!INSTANT.has(command)) {
    await new Promise((resolve) => setTimeout(resolve, 120 + Math.random() * 200));
  }
  const handler = handlers[command];
  if (!handler) throw { code: 'unsupported', message: `mock: no handler for ${command}` };
  return structuredClone(await handler(args));
}
