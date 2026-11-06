// The Tools page for `pnpm dev`: the secret generator (with WebCrypto's
// random numbers, like the real one with the OS's) and canned answers from
// the network tools for the sample hosts.

import type { CertSummary } from '@/bindings/CertSummary';
import type { CopyResult } from '@/bindings/CopyResult';
import type { DnsAnswer } from '@/bindings/DnsAnswer';
import type { DnsRecord } from '@/bindings/DnsRecord';
import type { DnsReport } from '@/bindings/DnsReport';
import type { GeneratedSecret } from '@/bindings/GeneratedSecret';
import type { PortCheck } from '@/bindings/PortCheck';
import type { PortState } from '@/bindings/PortState';
import type { RecordType } from '@/bindings/RecordType';
import type { SecretPreset } from '@/bindings/SecretPreset';
import type { SshPing } from '@/bindings/SshPing';
import type { TlsReport } from '@/bindings/TlsReport';

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const DJANGO = 'abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)';
const WIFI = 'abcdefghjkmnpqrstuvwxyz23456789';
const WORDS = [
  'acorn',
  'banjo',
  'cactus',
  'dolphin',
  'ember',
  'falcon',
  'glacier',
  'harbor',
  'igloo',
  'jasmine',
  'kettle',
  'lantern',
  'meadow',
  'nectar',
  'orbit',
  'pepper',
  'quartz',
  'raven',
  'saddle',
  'timber',
  'umbrella',
  'velvet',
  'walnut',
  'yonder',
];

function fail(code: string, message: string): Promise<never> {
  return Promise.reject({ code, message });
}

function randomIndex(n: number): number {
  const zone = 2 ** 32 - (2 ** 32 % n);
  const word = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(word);
    const x = word[0] ?? 0;
    if (x < zone) return x % n;
  }
}

const pick = (alphabet: string, length: number) =>
  Array.from({ length }, () => alphabet[randomIndex(alphabet.length)]).join('');

function bytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

const hex = (data: Uint8Array) => Array.from(data, (b) => b.toString(16).padStart(2, '0')).join('');
const base64 = (data: Uint8Array) => btoa(String.fromCharCode(...data));
const base64url = (data: Uint8Array) =>
  base64(data).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function safePassword(length: number, symbols: string): GeneratedSecret | Promise<never> {
  if (length < 16 || length > 64) return fail('invalid_input', 'length must be 16 to 64');
  const classes = [LOWER, UPPER, DIGITS, symbols];
  const all = classes.join('');
  for (;;) {
    const value = pick(all, length);
    if (/^[A-Za-z0-9]/.test(value) && classes.every((c) => [...value].some((x) => c.includes(x)))) {
      return { value, bits: Math.floor(length * Math.log2(all.length)) };
    }
  }
}

function uuid(version: 'v4' | 'v7'): string {
  const b = bytes(16);
  if (version === 'v7') {
    let ms = Date.now();
    for (let i = 5; i >= 0; i--) {
      b[i] = ms % 256;
      ms = Math.floor(ms / 256);
    }
  }
  b[6] = ((b[6] ?? 0) & 0x0f) | (version === 'v7' ? 0x70 : 0x40);
  b[8] = ((b[8] ?? 0) & 0x3f) | 0x80;
  const h = hex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function guessable(pin: string): boolean {
  const d = [...pin].map(Number);
  const all = (step: (a: number, b: number) => boolean) =>
    d.slice(1).every((b, i) => step(d[i] ?? 0, b));
  return all((a, b) => a === b) || all((a, b) => b === a + 1) || all((a, b) => a === b + 1);
}

function generate(preset: SecretPreset): GeneratedSecret | Promise<never> {
  switch (preset.kind) {
    case 'databasePassword':
      return safePassword(preset.length, '-_');
    case 'shellPassword':
      return safePassword(preset.length, '-_.+:');
    case 'envPassword':
      return safePassword(preset.length, '%+,-./:@_');
    case 'apiToken':
    case 'jwtSecret': {
      const n = preset.kind === 'apiToken' ? 32 : 64;
      const data = bytes(n);
      return { value: preset.encoding === 'hex' ? hex(data) : base64url(data), bits: n * 8 };
    }
    case 'uuid':
      return { value: uuid(preset.version), bits: preset.version === 'v4' ? 122 : 74 };
    case 'laravelAppKey':
      return { value: `base64:${base64(bytes(32))}`, bits: 256 };
    case 'djangoSecretKey':
      return { value: pick(DJANGO, 50), bits: Math.floor(50 * Math.log2(DJANGO.length)) };
    case 'railsSecretKeyBase':
      return { value: hex(bytes(64)), bits: 512 };
    case 'wifiPassword': {
      if (preset.groups < 3 || preset.groups > 8) {
        return fail('invalid_input', 'groups must be 3 to 8');
      }
      const groups = Array.from({ length: preset.groups }, () => pick(WIFI, 4));
      return { value: groups.join('-'), bits: Math.floor(preset.groups * 4 * Math.log2(31)) };
    }
    case 'passphrase': {
      if (preset.words < 3 || preset.words > 12) {
        return fail('invalid_input', 'words must be 3 to 12');
      }
      const words = Array.from({ length: preset.words }, () => WORDS[randomIndex(WORDS.length)]);
      return { value: words.join('-'), bits: Math.floor(preset.words * Math.log2(7776)) };
    }
    case 'pin': {
      if (preset.digits < 4 || preset.digits > 12) {
        return fail('invalid_input', 'digits must be 4 to 12');
      }
      for (;;) {
        const value = pick(DIGITS, preset.digits);
        if (!guessable(value)) return { value, bits: Math.floor(preset.digits * Math.log2(10)) };
      }
    }
  }
}

/** Where the sample hosts lead, and what answers there. */
interface MockHost {
  addresses: string[];
  /** Open ports; anything else is closed, or silent with `firewalled`. */
  open: number[];
  firewalled?: boolean;
  /** Milliseconds a connection takes. */
  rtt: number;
  banner?: string;
  cert?: 'valid' | 'expiring' | 'expired' | 'selfSigned';
}

const HOSTS: Record<string, MockHost> = {
  'github.com': {
    addresses: ['140.82.121.4'],
    open: [22, 80, 443],
    rtt: 24,
    banner: 'SSH-2.0-a4f1b7e',
    cert: 'valid',
  },
  'gitlab.com': {
    addresses: ['172.65.251.78', '2606:4700:90:0:f22e:fbec:5bed:a9b9'],
    open: [22, 80, 443],
    rtt: 31,
    banner: 'SSH-2.0-GitLab-SSHD',
    cert: 'valid',
  },
  'bastion.example.net': {
    addresses: ['203.0.113.10'],
    open: [2222, 443],
    rtt: 48,
    banner: 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5',
    cert: 'expiring',
  },
  '192.168.1.20': {
    addresses: ['192.168.1.20'],
    open: [22, 80, 443, 5000],
    rtt: 3,
    banner: 'SSH-2.0-OpenSSH_7.4',
    cert: 'selfSigned',
  },
  'vpn.example.org': {
    addresses: ['198.51.100.7'],
    open: [22, 443],
    rtt: 92,
    banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10',
    cert: 'expired',
  },
  '10.0.4.12': { addresses: ['10.0.4.12'], open: [], firewalled: true, rtt: 0 },
  '10.0.8.20': {
    addresses: ['10.0.8.20'],
    open: [22, 5432, 6379],
    rtt: 12,
    banner: 'SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3',
  },
  'example.com': { addresses: ['93.184.216.34'], open: [80, 443], rtt: 40, cert: 'valid' },
};

function host(name: unknown): [string, MockHost | undefined] {
  const key = String(name).trim().toLowerCase().replace(/\.$/, '');
  return [key, HOSTS[key]];
}

function stateOf(target: MockHost, port: number): PortState {
  if (target.open.includes(port)) return 'open';
  return target.firewalled ? 'noAnswer' : 'closed';
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const jitter = (rtt: number) => Math.round((rtt + Math.random() * rtt * 0.4) * 10) / 10;

function parseBanner(line: string) {
  const [, protocol = '', rest = ''] = /^SSH-([^-]+)-(.*)$/.exec(line) ?? [];
  const [software = '', ...comment] = rest.split(' ');
  const openssh = /^OpenSSH_(?:for_Windows_)?(\d.*)$/.exec(software)?.[1] ?? null;
  const major = openssh ? Number.parseFloat(openssh) : null;
  return {
    line,
    protocol,
    software,
    comment: comment.length ? comment.join(' ') : null,
    openssh,
    outdated: major !== null && major < 8,
  };
}

function sshPing(name: unknown, port: number, samples: number): SshPing {
  const [, target] = host(name);
  const empty: SshPing = {
    state: 'noAddress',
    address: null,
    addresses: [],
    message: 'nodename nor servname provided, or not known',
    samples: [],
    min: null,
    avg: null,
    max: null,
    lost: 0,
    banner: null,
    other: null,
  };
  if (!target) return empty;
  const address = target.addresses[0] ?? null;
  const state = stateOf(target, port);
  if (state !== 'open') {
    return {
      ...empty,
      state,
      address,
      addresses: target.addresses,
      message: state === 'closed' ? 'Connection refused (os error 61)' : 'connection timed out',
      samples: [null],
      lost: 1,
    };
  }
  const times = Array.from({ length: samples }, (_, i) =>
    i === 2 && target.rtt > 80 ? null : jitter(target.rtt),
  );
  const ok = times.filter((t): t is number => t !== null);
  const isSsh = port === 22 || port === 2222;
  return {
    ...empty,
    state,
    address,
    addresses: target.addresses,
    message: null,
    samples: times,
    min: Math.min(...ok),
    max: Math.max(...ok),
    avg: Math.round((ok.reduce((a, b) => a + b, 0) / ok.length) * 10) / 10,
    lost: times.length - ok.length,
    banner: isSsh && target.banner ? parseBanner(target.banner) : null,
    other: isSsh ? null : port === 443 ? '????' : 'HTTP/1.1 400 Bad Request',
  };
}

function portCheck(name: unknown, port: number): PortCheck {
  const [, target] = host(name);
  if (!target) {
    return {
      state: 'noAddress',
      address: null,
      addresses: [],
      millis: null,
      message: 'nodename nor servname provided, or not known',
    };
  }
  const state = stateOf(target, port);
  return {
    state,
    address: target.addresses[0] ?? null,
    addresses: target.addresses,
    millis: state === 'open' ? jitter(target.rtt) : null,
    message:
      state === 'open'
        ? null
        : state === 'closed'
          ? 'Connection refused (os error 61)'
          : 'connection timed out',
  };
}

const day = 86_400_000;
const iso = (offsetDays: number) =>
  new Date(Date.now() + offsetDays * day).toISOString().replace(/\.\d+Z$/, 'Z');

function cert(partial: Partial<CertSummary>): CertSummary {
  return {
    subject: null,
    issuer: null,
    issuerOrganization: null,
    notBefore: iso(-30),
    notAfter: iso(60),
    daysLeft: 60,
    names: [],
    key: 'ECDSA P-256',
    selfSigned: false,
    sha256:
      '3F:A1:9C:42:7B:0E:D5:66:18:C2:9A:E4:71:0B:5D:F3:88:21:6C:9E:47:B0:12:DA:5F:73:A8:C1:3E:90:6B:24',
    ...partial,
  };
}

function tlsCheck(name: unknown, port: number): TlsReport {
  const [key, target] = host(name);
  const base: TlsReport = {
    state: 'noAddress',
    address: null,
    addresses: [],
    message: 'nodename nor servname provided, or not known',
    handshake: false,
    notTls: false,
    protocol: null,
    cipher: null,
    trusted: false,
    problem: null,
    problemMessage: null,
    chain: [],
  };
  if (!target) return base;
  const state = stateOf(target, port);
  const connected = {
    ...base,
    state,
    address: target.addresses[0] ?? null,
    addresses: target.addresses,
    message: null,
  };
  if (state !== 'open') {
    return {
      ...connected,
      message: state === 'closed' ? 'Connection refused (os error 61)' : 'no answer',
    };
  }
  if (!target.cert || port !== 443) {
    return {
      ...connected,
      notTls: true,
      message: 'received corrupt message of type InvalidContentType',
    };
  }
  const intermediate = cert({
    subject: 'R11',
    issuer: 'ISRG Root X1',
    issuerOrganization: 'Internet Security Research Group',
    notBefore: iso(-600),
    notAfter: iso(500),
    daysLeft: 500,
    key: 'RSA 2048',
  });
  const handshake = {
    ...connected,
    handshake: true,
    protocol: 'TLS 1.3',
    cipher: 'TLS13_AES_128_GCM_SHA256',
  };
  switch (target.cert) {
    case 'valid':
      return {
        ...handshake,
        trusted: true,
        chain: [
          cert({
            subject: key,
            issuer: 'R11',
            issuerOrganization: "Let's Encrypt",
            names: [key, `www.${key}`],
            notAfter: iso(54),
            daysLeft: 54,
          }),
          intermediate,
        ],
      };
    case 'expiring':
      return {
        ...handshake,
        trusted: true,
        chain: [
          cert({
            subject: key,
            issuer: 'R11',
            issuerOrganization: "Let's Encrypt",
            names: [key],
            notBefore: iso(-84),
            notAfter: iso(6),
            daysLeft: 6,
          }),
          intermediate,
        ],
      };
    case 'expired':
      return {
        ...handshake,
        problem: 'expired',
        problemMessage: 'invalid peer certificate: certificate expired',
        chain: [
          cert({
            subject: key,
            issuer: 'R11',
            issuerOrganization: "Let's Encrypt",
            names: [key],
            notBefore: iso(-93),
            notAfter: iso(-3),
            daysLeft: -3,
          }),
          intermediate,
        ],
      };
    case 'selfSigned':
      return {
        ...handshake,
        protocol: 'TLS 1.2',
        cipher: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        problem: 'unknownIssuer',
        problemMessage: 'invalid peer certificate: UnknownIssuer',
        chain: [
          cert({
            subject: 'Synology',
            issuer: 'Synology',
            issuerOrganization: 'Synology Inc.',
            names: ['synology.local'],
            notBefore: iso(-900),
            notAfter: iso(2750),
            daysLeft: 2750,
            key: 'RSA 2048',
            selfSigned: true,
          }),
        ],
      };
  }
}

const RECORDS: Record<string, Partial<Record<RecordType, Omit<DnsRecord, 'kind'>[]>>> = {
  'github.com': {
    a: [{ name: 'github.com', ttl: 60, value: '140.82.121.4', priority: null }],
    mx: [
      { name: 'github.com', ttl: 3600, value: 'aspmx.l.google.com', priority: 1 },
      { name: 'github.com', ttl: 3600, value: 'alt1.aspmx.l.google.com', priority: 5 },
    ],
    txt: [
      {
        name: 'github.com',
        ttl: 3600,
        value:
          'v=spf1 ip4:192.30.252.0/22 include:_netblocks.google.com include:_spf.salesforce.com ~all',
        priority: null,
      },
    ],
  },
  'gitlab.com': {
    a: [{ name: 'gitlab.com', ttl: 300, value: '172.65.251.78', priority: null }],
    aaaa: [
      { name: 'gitlab.com', ttl: 300, value: '2606:4700:90:0:f22e:fbec:5bed:a9b9', priority: null },
    ],
    mx: [{ name: 'gitlab.com', ttl: 300, value: 'aspmx.l.google.com', priority: 1 }],
  },
  'www.github.com': {
    a: [
      { name: 'www.github.com', ttl: 3600, value: 'github.com', priority: null },
      { name: 'github.com', ttl: 60, value: '140.82.121.4', priority: null },
    ],
    cname: [{ name: 'www.github.com', ttl: 3600, value: 'github.com', priority: null }],
  },
  'staging-api.internal': {
    a: [{ name: 'staging-api.internal', ttl: 300, value: '10.0.8.25', priority: null }],
  },
  'example.com': {
    a: [{ name: 'example.com', ttl: 3600, value: '93.184.216.34', priority: null }],
    aaaa: [
      {
        name: 'example.com',
        ttl: 3600,
        value: '2606:2800:220:1:248:1893:25c8:1946',
        priority: null,
      },
    ],
    txt: [{ name: 'example.com', ttl: 3600, value: 'v=spf1 -all', priority: null }],
  },
};
const TYPES: RecordType[] = ['a', 'aaaa', 'cname', 'mx', 'txt'];

function dnsLookup(name: unknown): DnsReport | Promise<never> {
  const key = String(name).trim().toLowerCase().replace(/\.$/, '');
  if (!/^[a-z0-9_.-]+$/.test(key) || key.split('.').some((label) => !label)) {
    return fail('invalid_input', 'not a host name');
  }
  if (/^\d+(\.\d+){3}$/.test(key) || key.includes(':')) {
    return fail('invalid_input', 'enter a name, not an address');
  }
  const known = RECORDS[key];
  const answers: DnsAnswer[] = TYPES.map((kind) => {
    const records = (known?.[kind] ?? []).map((record) => ({
      ...record,
      // A CNAME on the way to an address is a CNAME record.
      kind: kind === 'a' && record.value === 'github.com' ? ('cname' as const) : kind,
    }));
    return {
      kind,
      status: !known ? 'noSuchName' : records.length ? 'found' : 'noRecords',
      records,
      server: '192.168.1.1',
      message: null,
    };
  });
  return { name: key, servers: ['192.168.1.1'], answers };
}

export const toolsNetHandlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  tools_generate_secret: ({ preset }) => generate(preset as SecretPreset),
  tools_copy_secret: async ({ text }): Promise<CopyResult> => {
    await navigator.clipboard.writeText(String(text)).catch(() => undefined);
    return { clearsInSecs: 30 };
  },
  tools_ssh_ping: async ({ host: name, port, samples }) => {
    const ping = sshPing(name, Number(port), Number(samples));
    await sleep(ping.state === 'noAnswer' ? 1500 : 200 * Number(samples));
    return ping;
  },
  tools_port_check: async ({ host: name, port, timeoutMs }) => {
    const check = portCheck(name, Number(port));
    if (check.state === 'noAnswer') await sleep(Math.min(Number(timeoutMs), 2500));
    return check;
  },
  tools_dns_lookup: ({ name }) => dnsLookup(name),
  tools_tls_check: async ({ host: name, port }) => {
    await sleep(300);
    return tlsCheck(name, Number(port));
  },
};
