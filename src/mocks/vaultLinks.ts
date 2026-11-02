// Mocks of the commands that join the vault and the SSH features, for
// `pnpm dev` (see backend.ts): unlocking keys with saved passphrases and the
// vault audit. They go through the in-memory vault's own handlers, and get
// the mock keys, hosts and agent from backend.ts.

import type { AddFromVaultReport } from '@/bindings/AddFromVaultReport';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { KeyView } from '@/bindings/KeyView';
import type { Strength } from '@/bindings/Strength';
import type { VaultAudit } from '@/bindings/VaultAudit';
import type { VaultFinding } from '@/bindings/VaultFinding';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { findKeyEntry } from '@/features/keys/vaultKey';
import { vaultHandlers } from './vault';

type Handler = (args: Record<string, unknown>) => unknown;

export interface MockSsh {
  keys: () => KeyView[];
  /** `Host` blocks of the config. */
  hosts: () => { id: number; patterns: string[] }[];
  /** Fingerprint → expiry of the keys ssh-agent holds. */
  agent: Map<string, string | null>;
}

const YEAR_MS = 365 * 24 * 3600 * 1000;
const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 } as const;

/** Calls one of the in-memory vault's handlers. */
function callVault(command: string, args: Record<string, unknown> = {}): unknown {
  const handler = vaultHandlers[command];
  if (!handler) throw { code: 'unsupported', message: `mock: no handler for ${command}` };
  return handler(args);
}

const vault = {
  state: () => (callVault('vault_status') as VaultStatus).state,
  entries: async () => (await callVault('vault_entries')) as EntrySummary[],
  entry: async (id: string) => (await callVault('vault_entry', { id })) as EntryDetail,
  password: async (id: string) =>
    (await callVault('vault_reveal', { id, field: 'password' })) as string,
  strength: (password: string, context: string[]) =>
    callVault('vault_strength', { password, context }) as Strength,
};

const fail = (code: string, message: string) => Promise.reject({ code, message });

function load(ssh: MockSsh, key: KeyView, lifetimeSecs: unknown) {
  if (!key.fingerprint) return;
  ssh.agent.set(
    key.fingerprint,
    lifetimeSecs ? new Date(Date.now() + Number(lifetimeSecs) * 1000).toISOString() : null,
  );
}

async function audit(ssh: MockSsh): Promise<VaultAudit> {
  const state = vault.state();
  if (state !== 'unlocked') return { state, findings: [] };
  const keys = ssh.keys();
  const hosts = ssh.hosts();
  const findings: VaultFinding[] = [];
  const byPassword = new Map<string, EntrySummary[]>();

  for (const entry of (await vault.entries()).filter((e) => !e.inTrash)) {
    const keyId =
      entry.kind === 'key'
        ? (keys.find((k) => k.fingerprint === entry.keyFingerprint)?.id ?? null)
        : null;
    const hostId =
      entry.kind === 'host'
        ? (hosts.find((h) => h.patterns.some((p) => p.toLowerCase() === entry.host?.toLowerCase()))
            ?.id ?? null)
        : null;
    const finding = (
      rule: string,
      severity: VaultFinding['severity'],
      kind: VaultFinding['kind'],
    ) =>
      findings.push({
        id: `${rule}:${entry.id}`,
        severity,
        kind,
        entryId: entry.id,
        keyId,
        hostId,
      });

    if (entry.kind === 'key' && entry.keyFingerprint && !keyId) {
      finding('keyNotFound', 'info', { kind: 'keyNotFound', fingerprint: entry.keyFingerprint });
    }
    if (entry.kind === 'host' && entry.host) {
      if (hostId === null)
        finding('hostNotFound', 'info', { kind: 'hostNotFound', host: entry.host });
      else if (entry.hasPassword)
        finding('passwordLogin', 'info', { kind: 'passwordLogin', host: entry.host });
    }
    if (!entry.hasPassword) continue;

    const password = await vault.password(entry.id);
    byPassword.set(password, [...(byPassword.get(password) ?? []), entry]);
    const { score } = vault.strength(password, [entry.title, entry.username]);
    if (score <= 1) {
      finding('weakPassword', score === 0 ? 'critical' : 'warning', {
        kind: 'weakPassword',
        score,
      });
    }
    const changed = (await vault.entry(entry.id)).passwordChanged;
    const age = changed ? Date.now() - Date.parse(changed) : 0;
    if (changed && age > YEAR_MS) {
      finding('oldPassword', 'info', {
        kind: 'oldPassword',
        changed,
        years: Math.floor(age / YEAR_MS),
      });
    }
  }

  for (const group of byPassword.values()) {
    if (group.length < 2) continue;
    const [first] = group;
    if (!first) continue;
    findings.push({
      id: `reusedPassword:${group.map((e) => e.id).sort()[0]}`,
      severity: 'warning',
      kind: { kind: 'reusedPassword', entryIds: group.map((e) => e.id) },
      entryId: first.id,
      keyId: null,
      hostId: null,
    });
  }
  findings.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.id.localeCompare(b.id),
  );
  return { state, findings };
}

/** Handlers for backend.ts. A saved passphrase always opens its key here. */
export function vaultLinkHandlers(ssh: MockSsh): Record<string, Handler> {
  return {
    agent_add_from_vault: async ({ keyId, lifetimeSecs }) => {
      const key = ssh.keys().find((k) => k.id === keyId);
      if (!key) return fail('not_found', `key ${keyId}`);
      if (vault.state() !== 'unlocked') return fail('vault_locked', 'the vault is locked');
      if (!findKeyEntry(await vault.entries(), key.fingerprint)) {
        return fail('not_found', `saved passphrase of ${key.name}`);
      }
      load(ssh, key, lifetimeSecs);
    },
    agent_add_all_from_vault: async ({ lifetimeSecs }): Promise<AddFromVaultReport> => {
      if (vault.state() !== 'unlocked') return fail('vault_locked', 'the vault is locked');
      const entries = await vault.entries();
      const added: string[] = [];
      for (const key of ssh.keys()) {
        if (!key.privatePath || key.hardware || !key.fingerprint) continue;
        if (ssh.agent.has(key.fingerprint) || !findKeyEntry(entries, key.fingerprint)) continue;
        load(ssh, key, lifetimeSecs);
        added.push(key.name);
      }
      return { added, failed: [] };
    },
    run_vault_audit: () => audit(ssh),
  };
}
