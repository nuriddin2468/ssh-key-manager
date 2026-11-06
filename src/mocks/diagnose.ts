// "Why it failed" in `pnpm dev`: what the backend would read from ssh's
// output for the sample hosts, the port probe and the permission fix.
//
// The usual sample hosts fail as before, now with a diagnosis. With
// `?diagnose` in the address, more hosts join the config, one for each
// cause (`diag-…`), so the README's screenshots stay as they are.

import type { Diagnosis } from '@/bindings/Diagnosis';
import type { FailReason } from '@/bindings/FailReason';
import type { HostOption } from '@/bindings/HostOption';
import type { PortProbe } from '@/bindings/PortProbe';

type Handler = (args: Record<string, unknown>) => unknown;

const HOME = '/Users/dev';
const WORK_KEY = `${HOME}/.ssh/id_ed25519_work`;
const opt = (key: string, value: string): HostOption => ({ key, value });

interface Sample {
  options: HostOption[];
  /** What ssh printed (without `-v`'s lines). */
  output: string;
  diagnosis: Diagnosis;
}

const offered = [
  {
    name: WORK_KEY,
    keyType: 'ED25519',
    fingerprint: 'SHA256:7fQvYkS3u1dGm0bL2pX9wHcN4rE6tA8iO5jU0yKzMv1',
    agent: false,
  },
  {
    name: 'dev@macbook-pro',
    keyType: 'ED25519',
    fingerprint: 'SHA256:Zx9yQe1R0r9cGkT2mJb0FqgWnDk3p8a7HlU1sVwXyZ4',
    agent: true,
  },
];

const diagnosis = (cause: Diagnosis['cause'], lines: string[], hop: string | null = null) => ({
  cause,
  hop,
  lines,
});

const network = (
  problem: Extract<Diagnosis['cause'], { kind: 'network' }>['problem'],
  host: string,
  line: string,
): Sample => ({
  options: [opt('HostName', host), opt('User', 'dev')],
  output: line,
  diagnosis: diagnosis({ kind: 'network', problem, host, port: 22 }, [line]),
});

/** One sample host for each cause, by alias. */
const SAMPLES: Record<string, Sample> = {
  'diag-keys': {
    options: [
      opt('HostName', '10.0.5.10'),
      opt('User', 'deploy'),
      opt('IdentityFile', '~/.ssh/id_ed25519_work'),
    ],
    output: 'deploy@10.0.5.10: Permission denied (publickey).',
    diagnosis: diagnosis({ kind: 'keysRejected', offered, passwordAllowed: false }, [
      `debug1: Offering public key: ${WORK_KEY} ED25519 ${offered[0]?.fingerprint} explicit`,
      `debug1: Offering public key: dev@macbook-pro ED25519 ${offered[1]?.fingerprint} agent`,
      'deploy@10.0.5.10: Permission denied (publickey).',
    ]),
  },
  'diag-no-key': {
    options: [opt('HostName', '10.0.5.11'), opt('User', 'deploy')],
    output: 'deploy@10.0.5.11: Permission denied (publickey).',
    diagnosis: diagnosis({ kind: 'keysRejected', offered, passwordAllowed: false }, [
      'deploy@10.0.5.11: Permission denied (publickey).',
    ]),
  },
  'diag-locked': {
    options: [
      opt('HostName', '10.0.5.12'),
      opt('User', 'deploy'),
      opt('IdentityFile', '~/.ssh/id_ed25519_work'),
    ],
    output: 'deploy@10.0.5.12: Permission denied (publickey).',
    diagnosis: diagnosis({ kind: 'keyLocked', key: WORK_KEY }, [
      `debug1: Server accepts key: ${WORK_KEY} ED25519 ${offered[0]?.fingerprint} explicit`,
      'deploy@10.0.5.12: Permission denied (publickey).',
    ]),
  },
  'diag-missing-key': {
    options: [
      opt('HostName', '10.0.5.13'),
      opt('User', 'deploy'),
      opt('IdentityFile', '~/.ssh/id_ed25519_old'),
    ],
    output: `no such identity: ${HOME}/.ssh/id_ed25519_old: No such file or directory\ndeploy@10.0.5.13: Permission denied (publickey).`,
    diagnosis: diagnosis({ kind: 'identityFileMissing', path: `${HOME}/.ssh/id_ed25519_old` }, [
      `no such identity: ${HOME}/.ssh/id_ed25519_old: No such file or directory`,
      'deploy@10.0.5.13: Permission denied (publickey).',
    ]),
  },
  'diag-password': {
    options: [opt('HostName', 'nas.lan'), opt('User', 'admin')],
    output: 'admin@nas.lan: Permission denied (publickey,password).',
    diagnosis: diagnosis({ kind: 'passwordRejected' }, [
      'debug1: Next authentication method: password',
      'admin@nas.lan: Permission denied (publickey,password).',
    ]),
  },
  'diag-too-many': {
    options: [
      opt('HostName', '10.0.5.14'),
      opt('User', 'deploy'),
      opt('IdentityFile', '~/.ssh/id_ed25519_work'),
    ],
    output:
      'Received disconnect from 10.0.5.14 port 22:2: Too many authentication failures\nDisconnected from 10.0.5.14 port 22',
    diagnosis: diagnosis({ kind: 'tooManyAuthFailures', offered }, [
      'Received disconnect from 10.0.5.14 port 22:2: Too many authentication failures',
      'Disconnected from 10.0.5.14 port 22',
    ]),
  },
  'diag-host-key': {
    options: [opt('HostName', '10.0.5.15'), opt('User', 'deploy')],
    output:
      '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed.',
    diagnosis: diagnosis(
      {
        kind: 'hostKeyChanged',
        host: '10.0.5.15',
        keyType: 'ED25519',
        fingerprint: 'SHA256:N3wServerKeyAfterReinstall0000000000000000',
        knownHosts: `${HOME}/.ssh/known_hosts:14`,
      },
      [
        '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @',
        'The fingerprint for the ED25519 key sent by the remote host is',
        'SHA256:N3wServerKeyAfterReinstall0000000000000000.',
        `Offending ED25519 key in ${HOME}/.ssh/known_hosts:14`,
        'Host key for 10.0.5.15 has changed and you have requested strict checking.',
        'Host key verification failed.',
      ],
    ),
  },
  'diag-refused': network(
    'refused',
    '10.0.5.16',
    'ssh: connect to host 10.0.5.16 port 22: Connection refused',
  ),
  'diag-no-route': network(
    'noRoute',
    '192.168.50.20',
    'ssh: connect to host 192.168.50.20 port 22: No route to host',
  ),
  'diag-reset': network('reset', '10.0.5.17', 'Connection reset by 10.0.5.17 port 22'),
  'diag-not-ssh': network(
    'notSsh',
    '10.0.5.18',
    'banner exchange: Connection to 10.0.5.18 port 22: invalid format',
  ),
  'diag-dns': {
    options: [opt('HostName', 'build.internal.example'), opt('User', 'ci')],
    output:
      'ssh: Could not resolve hostname build.internal.example: nodename nor servname provided, or not known',
    diagnosis: diagnosis({ kind: 'nameNotResolved', host: 'build.internal.example' }, [
      'ssh: Could not resolve hostname build.internal.example: nodename nor servname provided, or not known',
    ]),
  },
  'diag-permissions': {
    options: [
      opt('HostName', '10.0.5.19'),
      opt('User', 'deploy'),
      opt('IdentityFile', '~/.ssh/id_ed25519_work'),
    ],
    output: `Permissions 0644 for '${WORK_KEY}' are too open.\nLoad key "${WORK_KEY}": bad permissions\ndeploy@10.0.5.19: Permission denied (publickey).`,
    diagnosis: diagnosis({ kind: 'badPermissions', path: WORK_KEY, file: 'privateKey' }, [
      '@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @',
      `Permissions 0644 for '${WORK_KEY}' are too open.`,
      `Load key "${WORK_KEY}": bad permissions`,
    ]),
  },
  'diag-legacy': {
    options: [opt('HostName', '192.168.1.1'), opt('User', 'admin')],
    output:
      'Unable to negotiate with 192.168.1.1 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss',
    diagnosis: diagnosis(
      {
        kind: 'legacy',
        what: 'hostKey',
        offer: ['ssh-rsa', 'ssh-dss'],
        option: 'HostKeyAlgorithms',
        value: '+ssh-rsa',
      },
      [
        'Unable to negotiate with 192.168.1.1 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss',
      ],
    ),
  },
  'diag-jump': {
    options: [opt('HostName', '10.0.4.30'), opt('User', 'ubuntu'), opt('ProxyJump', 'bastion')],
    output:
      'channel 0: open failed: connect failed: Connection refused\nstdio forwarding failed\nConnection closed by UNKNOWN port 65535',
    diagnosis: diagnosis(
      { kind: 'proxy', problem: 'nextHopUnreachable', detail: 'Connection refused' },
      ['channel 0: open failed: connect failed: Connection refused', 'stdio forwarding failed'],
      'bastion',
    ),
  },
  'diag-proxy-command': {
    options: [
      opt('HostName', 'db.internal'),
      opt('User', 'dev'),
      opt('ProxyCommand', 'cloudflared access ssh --hostname %h'),
    ],
    output:
      'zsh:1: command not found: cloudflared\nkex_exchange_identification: Connection closed by remote host\nConnection closed by UNKNOWN port 65535',
    diagnosis: diagnosis({ kind: 'proxy', problem: 'commandFailed', detail: null }, [
      'debug1: Executing proxy command: exec cloudflared access ssh --hostname db.internal',
      'zsh:1: command not found: cloudflared',
      'Connection closed by UNKNOWN port 65535',
    ]),
  },
  'diag-unknown': {
    options: [opt('HostName', '10.0.5.20'), opt('User', 'dev')],
    output: 'mux_client_request_session: read from master failed: Broken pipe',
    diagnosis: diagnosis({ kind: 'unknown' }, [
      'mux_client_request_session: read from master failed: Broken pipe',
    ]),
  },
};

/** The diagnoses of the usual sample hosts' failures. */
const USUAL: Record<string, Diagnosis> = {
  bastion: diagnosis(
    { kind: 'keysRejected', offered: offered.slice(0, 1), passwordAllowed: true },
    ['deploy@bastion.example.net: Permission denied (publickey,password).'],
  ),
  'prod-api': diagnosis({ kind: 'keysRejected', offered, passwordAllowed: true }, [
    'ubuntu@10.0.4.12: Permission denied (publickey,password).',
  ]),
  'staging-api': diagnosis({ kind: 'passwordRequired' }, [
    'ubuntu@10.0.8.20: Permission denied (password).',
  ]),
  'legacy-nas': diagnosis({ kind: 'hostKeyUnknown', host: '192.168.1.20' }, [
    'No ED25519 host key is known for 192.168.1.20 and you have requested strict checking.',
    'Host key verification failed.',
  ]),
};

const timedOut = (host: string) =>
  diagnosis({ kind: 'network', problem: 'timedOut', host, port: 22 }, [
    `ssh: connect to host ${host} port 22: Operation timed out`,
  ]);

/** Whether the sample hosts for each cause are in the config (`?diagnose`). */
export const diagnoseSamplesShown =
  typeof window !== 'undefined' && new URLSearchParams(window.location.search).has('diagnose');

/** The sample hosts' blocks, before `Host *`. */
export const diagnoseHostSpecs: { patterns: string[]; options: HostOption[] }[] =
  diagnoseSamplesShown
    ? Object.entries(SAMPLES).map(([alias, sample]) => ({
        patterns: [alias],
        options: sample.options,
      }))
    : [];

/** A check's result with the diagnosis the backend would add; sample hosts fail in their own way. */
export function diagnosed(alias: string, result: unknown): unknown {
  const sample = diagnoseSamplesShown ? SAMPLES[alias] : undefined;
  if (sample) {
    return { ok: false, output: sample.output, prompts: [], diagnosis: sample.diagnosis };
  }
  if (result instanceof Promise) return result.then((r: unknown) => diagnosed(alias, r));
  if (!result || typeof result !== 'object' || !('ok' in result)) return result;
  const test = result as { ok: boolean; output: string; diagnosis?: Diagnosis | null };
  if (test.ok || test.diagnosis) return { ...test, diagnosis: test.diagnosis ?? null };
  const timeout = /connect to host (\S+) port \d+: Operation timed out/.exec(test.output);
  return {
    ...test,
    diagnosis:
      USUAL[alias] ??
      (timeout?.[1]
        ? timedOut(timeout[1])
        : diagnosis({ kind: 'unknown' }, test.output.split('\n'))),
  };
}

/** A failed terminal session's diagnosis, as the backend reads it from the output. */
export function sessionDiagnosis(alias: string, output: string): Diagnosis {
  if (output.includes('REMOTE HOST IDENTIFICATION HAS CHANGED')) {
    const lines = output.trim().split('\n');
    return diagnosis(
      {
        kind: 'hostKeyChanged',
        host: alias,
        keyType: 'ED25519',
        fingerprint: lines.find((l) => l.startsWith('SHA256:'))?.replace(/\.$/, '') ?? null,
        knownHosts: /Offending \S+ key in (\S+)/.exec(output)?.[1] ?? null,
      },
      lines,
    );
  }
  const shown = diagnosed(alias, { ok: false, output, prompts: [] }) as { diagnosis: Diagnosis };
  return shown.diagnosis;
}

/** How a sample host's terminal session fails: the terminal's reason and what ssh printed. */
export function sampleFailure(alias: string): { reason: FailReason; output: string } | undefined {
  const sample = diagnoseSamplesShown ? SAMPLES[alias] : undefined;
  if (!sample) return undefined;
  const reason: FailReason = (() => {
    switch (sample.diagnosis.cause.kind) {
      case 'keysRejected':
      case 'keyLocked':
      case 'identityFileMissing':
      case 'tooManyAuthFailures':
      case 'badPermissions':
        return 'notAccepted';
      case 'network':
      case 'nameNotResolved':
      case 'proxy':
      case 'legacy':
        return 'unreachable';
      case 'hostKeyChanged':
        return 'hostKeyChanged';
      case 'passwordRejected':
        return 'passwordRejected';
      default:
        return 'other';
    }
  })();
  return { reason, output: sample.output };
}

/** Ports that answer: the usual sample hosts' and the ones that refuse ssh only. */
const PROBES: Record<string, PortProbe['outcome']> = {
  'old-vpn': 'timedOut',
  'gitlab.com': 'open',
  'diag-refused': 'refused',
  'diag-no-route': 'unreachable',
  'diag-reset': 'open',
  'diag-not-ssh': 'open',
  'diag-unknown': 'open',
};

export const diagnoseHandlers: Record<string, Handler> = {
  diagnose_probe: ({ alias }) => {
    const name = String(alias);
    if (name === 'diag-proxy-command') {
      return Promise.reject({ code: 'unsupported', message: 'reached through a ProxyCommand' });
    }
    const host =
      SAMPLES[name]?.options.find((o) => o.key === 'HostName')?.value ??
      (name === 'old-vpn' ? 'vpn.example.org' : name);
    const outcome = PROBES[name] ?? 'open';
    return {
      host,
      port: 22,
      addresses: outcome === 'notResolved' ? [] : ['10.0.5.16'],
      outcome,
    } satisfies PortProbe;
  },
  diagnose_fix_permissions: ({ path }) => path === WORK_KEY,
};
