// The hosts file for `pnpm dev`: plain text and a small parser that mirrors
// `sshkm-core`'s closely enough to build the editing UI against.

import type { Finding } from '@/bindings/Finding';
import type { HostsAddressKind } from '@/bindings/HostsAddressKind';
import type { HostsApplyResult } from '@/bindings/HostsApplyResult';
import type { HostsChange } from '@/bindings/HostsChange';
import type { HostsDiffLine } from '@/bindings/HostsDiffLine';
import type { HostsEntryEdit } from '@/bindings/HostsEntryEdit';
import type { HostsFileEntry } from '@/bindings/HostsFileEntry';
import type { HostsFileInfo } from '@/bindings/HostsFileInfo';
import type { HostsFileView } from '@/bindings/HostsFileView';

const PATH = '/etc/hosts';
const SYSTEM = new Set(['localhost', 'broadcasthost']);
const inTwoHours = new Date(Date.now() + 2 * 3600_000).toISOString().replace(/\.\d+Z$/, 'Z');
const anHourAgo = new Date(Date.now() - 3600_000).toISOString().replace(/\.\d+Z$/, 'Z');

let lines = [
  '##',
  '# Host Database',
  '#',
  '# localhost is used to configure the loopback interface',
  '# when the system is booting.  Do not change this entry.',
  '##',
  '127.0.0.1\tlocalhost',
  '255.255.255.255\tbroadcasthost',
  '::1             localhost',
  '',
  '# Local development',
  '127.0.0.1\tapp.test api.test admin.test',
  '10.0.4.12\tprod-db.internal',
  '192.168.1.20\tnas.home nas',
  `10.0.9.1\tdemo.local\t# sshkm-until=${anHourAgo}`,
  '',
  '# >>> sshkm: Staging',
  '10.0.8.20\tstaging-api.internal\t# behind the VPN',
  '# 10.0.8.21\tstaging-api.internal\t# new staging, not live yet',
  '10.0.8.30\tstaging-api.internal',
  `10.0.8.40\tpreview.staging\t# sshkm-until=${inTwoHours}`,
  '# <<< sshkm: Staging',
  '# >>> sshkm: Blocklist',
  '0.0.0.0\ttracker.example.com',
  '0.0.0.0\tads.example.net',
  '# <<< sshkm: Blocklist',
];
let revision = 1;
const backups: { path: string; saved: string; lines: string[] }[] = [];

const DNS: Record<string, string[]> = {
  'github.com': ['140.82.121.4'],
  'gitlab.com': ['172.65.251.78', '2606:4700:90:0:f22e:fbec:5bed:a9b9'],
  'bastion.example.net': ['203.0.113.10'],
  'vpn.example.org': ['198.51.100.7'],
};

function kindOf(address: string): HostsAddressKind {
  if (address === '0.0.0.0' || address === '::') return 'blocked';
  if (address === '::1' || address.startsWith('127.')) return 'loopback';
  return /^(10\.|192\.168\.|255\.|fe80)/.test(address) ? 'private' : 'public';
}

type Parsed =
  | { kind: 'entry'; address: string; names: string[]; comment: string | null; enabled: boolean }
  | { kind: 'start'; name: string }
  | { kind: 'end' }
  | { kind: 'other' };

function parse(line: string): Parsed {
  const hash = line.indexOf('#');
  const data = hash === -1 ? line : line.slice(0, hash);
  const comment = hash === -1 ? null : line.slice(hash + 1);
  const fields = (text: string, enabled: boolean, note: string | null): Parsed => {
    const [address, ...names] = text.trim().split(/\s+/);
    if (!address || names.length === 0 || !/^[\d.:a-f%]+$/i.test(address)) return { kind: 'other' };
    return { kind: 'entry', address, names, comment: note?.trim() || null, enabled };
  };
  if (data.trim()) return fields(data, true, comment);
  if (comment === null) return { kind: 'other' };
  const body = comment.replace(/^#*/, '').trim();
  if (body.startsWith('>>> sshkm:')) return { kind: 'start', name: body.slice(10).trim() };
  if (body.startsWith('<<< sshkm')) return { kind: 'end' };
  const inner = comment.replace(/^#*/, '');
  const innerHash = inner.indexOf('#');
  return innerHash === -1
    ? fields(inner, false, null)
    : fields(inner.slice(0, innerHash), false, inner.slice(innerHash + 1));
}

function view(): HostsFileView {
  const entries: HostsFileEntry[] = [];
  const groups: HostsFileView['groups'] = [];
  const seen = new Set<string>();
  let group: string | null = null;
  lines.forEach((text, index) => {
    const parsed = parse(text);
    if (parsed.kind === 'start') {
      group = parsed.name;
      groups.push({ name: parsed.name, line: index + 1, endLine: null });
    } else if (parsed.kind === 'end') {
      const last = groups.at(-1);
      if (last && group !== null) last.endLine = index + 1;
      group = null;
    } else if (parsed.kind === 'entry') {
      const until = parsed.comment?.match(/sshkm-until=(\S+)/);
      const comment = parsed.comment?.replace(/\s*sshkm-until=\S+\s*/, ' ').trim() || null;
      const family = parsed.address.includes(':') ? '6' : '4';
      const shadowed = parsed.enabled
        ? parsed.names.filter((name) => {
            const key = `${family}${name.toLowerCase()}`;
            const dup = seen.has(key);
            seen.add(key);
            return dup;
          })
        : [];
      entries.push({
        line: index + 1,
        address: parsed.address,
        kind: kindOf(parsed.address),
        names: parsed.names,
        comment,
        enabled: parsed.enabled,
        system: parsed.names.every((name) => SYSTEM.has(name)),
        shadowed,
        group,
        expires: until?.[1] ?? null,
      });
    }
  });
  return { entries, invalid: [], groups };
}

export function hostsFileInfo(): HostsFileInfo {
  return { path: PATH, exists: true, revision: `rev-${revision}`, readOnly: null, view: view() };
}

function render(edit: HostsEntryEdit): string {
  const note = [edit.comment, edit.expires ? `sshkm-until=${edit.expires}` : null].filter(Boolean);
  const text = `${edit.address}\t${edit.names.join(' ')}${note.length ? `\t# ${note.join(' ')}` : ''}`;
  return edit.enabled ? text : `# ${text}`;
}

/** Applies changes like the core does; returns the new lines and the full diff. */
function edited(changes: HostsChange[]): { next: string[]; diff: HostsDiffLine[] } {
  const current = view();
  const byLine = new Map(current.entries.map((e) => [e.line, e]));
  const ops = new Map<number, string | null>();
  const finals = new Map<string, string | null>();
  const adds: [string | null, string][] = [];
  for (const change of changes) {
    if (change.kind === 'renameGroup' || change.kind === 'ungroup') {
      const group = current.groups.find((g) => g.name === change.name);
      if (!group) throw { code: 'not_found', message: `group ${change.name}` };
      const to = change.kind === 'renameGroup' ? change.to : null;
      ops.set(group.line, to === null ? null : `# >>> sshkm: ${to}`);
      if (group.endLine) ops.set(group.endLine, to === null ? null : `# <<< sshkm: ${to}`);
      finals.set(change.name, to);
    }
  }
  const finalName = (name: string | null) =>
    name === null ? null : finals.has(name) ? (finals.get(name) ?? null) : name;
  for (const change of changes) {
    if (change.kind === 'set') {
      const base = byLine.get(change.line);
      if (!base || base.system) throw { code: 'invalid_input', message: `line ${change.line}` };
      const { entry } = change;
      if (entry.group !== finalName(base.group)) {
        ops.set(change.line, null);
        adds.push([entry.group, render(entry)]);
      } else {
        const same =
          base.address === entry.address &&
          base.names.join() === entry.names.join() &&
          base.comment === entry.comment &&
          base.expires === entry.expires;
        const text = lines[change.line - 1] ?? '';
        ops.set(
          change.line,
          !same
            ? render(entry)
            : entry.enabled === base.enabled
              ? text
              : entry.enabled
                ? text.replace(/^\s*#+\s?/, '')
                : `# ${text}`,
        );
      }
    } else if (change.kind === 'remove') {
      ops.set(change.line, null);
    } else if (change.kind === 'add') {
      adds.push([change.entry.group, render(change.entry)]);
    }
  }
  const ends = new Map<string, number>();
  for (const group of current.groups) {
    const name = finalName(group.name);
    if (name !== null) ends.set(name, (group.endLine ?? lines.length + 1) - 1);
  }
  const before = new Map<number, string[]>();
  const loose: string[] = [];
  const fresh = new Map<string, string[]>();
  for (const [group, text] of adds) {
    const end = group === null ? undefined : ends.get(group);
    if (group === null) loose.push(text);
    else if (end !== undefined) before.set(end, [...(before.get(end) ?? []), text]);
    else fresh.set(group, [...(fresh.get(group) ?? []), text]);
  }
  const next: string[] = [];
  const diff: HostsDiffLine[] = [];
  const row = (kind: HostsDiffLine['kind'], text: string, oldLine: number | null) =>
    diff.push({ kind, text, oldLine, newLine: kind === 'removed' ? null : next.length, count: 0 });
  const add = (text: string) => {
    next.push(text);
    row('added', text, null);
  };
  lines.forEach((text, index) => {
    for (const extra of before.get(index) ?? []) add(extra);
    const op = ops.get(index + 1);
    if (op === undefined) {
      next.push(text);
      row('same', text, index + 1);
    } else if (op === null) {
      row('removed', text, index + 1);
    } else {
      row('removed', text, index + 1);
      add(op);
    }
  });
  for (const extra of before.get(lines.length) ?? []) add(extra);
  for (const text of loose) add(text);
  for (const [name, texts] of fresh) {
    if (next.at(-1)) add('');
    add(`# >>> sshkm: ${name}`);
    for (const text of texts) add(text);
    add(`# <<< sshkm: ${name}`);
  }
  return { next, diff };
}

function compress(rows: HostsDiffLine[]): HostsDiffLine[] {
  const changed = rows.flatMap((r, i) => (r.kind === 'same' ? [] : [i]));
  const out: HostsDiffLine[] = [];
  rows.forEach((r, i) => {
    if (r.kind !== 'same' || changed.some((c) => Math.abs(c - i) <= 2)) out.push(r);
    else if (out.at(-1)?.kind === 'skipped') (out.at(-1) as HostsDiffLine).count += 1;
    else out.push({ kind: 'skipped', text: '', oldLine: null, newLine: null, count: 1 });
  });
  return out;
}

function install(next: string[]): HostsApplyResult {
  const backup = `/backups/hosts.${revision}.bak`;
  backups.push({ path: backup, saved: new Date().toISOString(), lines });
  lines = next;
  revision += 1;
  return { outcome: 'applied', file: hostsFileInfo(), backup };
}

export const hostsFileHandlers: Record<string, (args: Record<string, unknown>) => unknown> = {
  read_hosts_file: hostsFileInfo,
  preview_hosts_changes: ({ revision: rev, changes }) =>
    rev !== `rev-${revision}`
      ? { stale: true, diff: [] }
      : { stale: false, diff: compress(edited(changes as HostsChange[]).diff) },
  apply_hosts_changes: ({ revision: rev, changes }) =>
    rev !== `rev-${revision}`
      ? { outcome: 'stale', file: hostsFileInfo(), backup: null }
      : install(edited(changes as HostsChange[]).next),
  list_hosts_backups: () =>
    [...backups].reverse().map((b) => ({
      path: b.path,
      saved: b.saved,
      entries: b.lines.filter((l) => parse(l).kind === 'entry').length,
    })),
  restore_hosts_backup: ({ path, revision: rev }) => {
    const backup = backups.find((b) => b.path === path);
    if (!backup) return Promise.reject({ code: 'invalid_input', message: 'not a backup' });
    // An Undo restores only over the file it changed.
    if (rev && rev !== `rev-${revision}`) {
      return { outcome: 'stale', file: hostsFileInfo(), backup: null };
    }
    return install(backup.lines);
  },
  lookup_host: ({ name }) => {
    const wanted = String(name).toLowerCase();
    const listed = view().entries.find((e) => e.enabled && e.names.includes(wanted));
    const addresses = listed ? [listed.address] : (DNS[wanted] ?? []);
    return {
      addresses,
      error: addresses.length
        ? null
        : 'failed to lookup address information: nodename nor servname provided, or not known',
    };
  },
};

/** The audit's hosts file findings, computed the way the core does. */
export function hostsFileFindings(): Finding[] {
  const findings: Finding[] = [];
  const subject = { keyId: null, hostId: null, path: null };
  const byName = new Map<string, { addresses: string[]; lines: number[] }>();
  for (const entry of view().entries.filter((e) => e.enabled)) {
    if (entry.expires && Date.parse(entry.expires) <= Date.now()) {
      findings.push({
        id: `hostsFileExpired:${entry.address}:${entry.names.join(',')}`,
        severity: 'warning',
        kind: {
          kind: 'hostsFileExpired',
          names: entry.names,
          address: entry.address,
          line: entry.line,
          expires: entry.expires,
        },
        subject,
        fix: { kind: 'turnOffHostsEntry', line: entry.line },
      });
    }
    for (const name of entry.names) {
      const key = `${name.toLowerCase()}|${entry.address.includes(':') ? 'ipv6' : 'ipv4'}`;
      const use = byName.get(key) ?? { addresses: [], lines: [] };
      if (!use.addresses.includes(entry.address)) use.addresses.push(entry.address);
      use.lines.push(entry.line);
      byName.set(key, use);
    }
  }
  for (const [key, use] of byName) {
    if (use.addresses.length < 2) continue;
    const [name = '', family] = key.split('|');
    findings.push({
      id: `hostsFileConflict:${name}:${family}`,
      severity: 'warning',
      kind: { kind: 'hostsFileConflict', name, addresses: use.addresses, lines: use.lines },
      subject,
      fix: null,
    });
  }
  return findings;
}
