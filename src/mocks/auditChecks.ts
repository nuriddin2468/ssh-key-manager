// Mocks of the audit's config rules, their fixes and the breach check, for
// `pnpm dev` (see backend.ts). The rules are a short version of
// `crates/sshkm-core/src/audit/config_risks.rs`; the breach check pretends to
// ask Have I Been Pwned, one password every 400 ms.

import type { BreachStatus } from '@/bindings/BreachStatus';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { Finding } from '@/bindings/Finding';
import type { FixAction } from '@/bindings/FixAction';
import type { HostOption } from '@/bindings/HostOption';
import type { VaultAudit } from '@/bindings/VaultAudit';
import type { VaultFinding } from '@/bindings/VaultFinding';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { vaultHandlers } from './vault';

type Handler = (args: Record<string, unknown>) => unknown;
type HostSpec = { patterns: string[]; options: HostOption[] };

/** Most keys ssh-agent can hold before ssh may run out of attempts. */
const AGENT_KEYS_LIMIT = 5;
/** The mock agent also holds a password manager's keys, which the Keys page doesn't list. */
const OTHER_AGENT_KEYS = 5;
/** How often the mock passwords were seen in breaches. */
const BREACHED: Record<string, number> = {
  password123: 2_590_000,
  'correct-horse-battery-staple': 389,
};
const SEVERITY_ORDER = { critical: 0, warning: 1, info: 2 } as const;

const first = (spec: HostSpec, key: string) =>
  spec.options.find((o) => o.key.toLowerCase() === key.toLowerCase());
const isWild = (pattern: string) => /[*?]/.test(pattern) && !pattern.startsWith('!');
const isYes = (value: string | undefined) => /^(yes|true)$/i.test(value ?? '');

/** Blocks with an IdentityFile whose hosts get every agent key offered. */
function lackingIdentitiesOnly(specs: HostSpec[]): number[] {
  const star = specs.find((s) => s.patterns.join(' ') === '*');
  if (star && isYes(first(star, 'IdentitiesOnly')?.value)) return [];
  return specs.flatMap((spec, id) =>
    spec.patterns.includes('*') ||
    !spec.options.some((o) => o.key === 'IdentityFile' && o.value !== 'none') ||
    first(spec, 'IdentitiesOnly')
      ? []
      : [id],
  );
}

/** The config rules' findings for the mock config. */
export function configSettingsFindings(
  specs: HostSpec[],
  agentKeys: number,
  path: string,
): Finding[] {
  const findings: Finding[] = [];
  specs.forEach((spec, hostId) => {
    const block = `host:${spec.patterns.join(' ')}`;
    const subject = { keyId: null, hostId, path };
    const removal = (option: HostOption): FixAction => ({
      kind: 'removeConfigOption',
      hostId,
      key: option.key,
      value: option.value,
    });
    const known = first(spec, 'UserKnownHostsFile');
    const discarded = known?.value === '/dev/null';
    const strict = first(spec, 'StrictHostKeyChecking');
    if (strict && /^(no|off|false)$/i.test(strict.value)) {
      findings.push({
        id: `strictHostKeyCheckingOff:${block}`,
        severity: discarded ? 'critical' : 'warning',
        kind: {
          kind: 'strictHostKeyCheckingOff',
          value: strict.value,
          patterns: spec.patterns,
          knownHostsDiscarded: discarded,
        },
        subject,
        fix: removal(strict),
      });
    }
    if (known && discarded) {
      findings.push({
        id: `knownHostsDiscarded:${block}`,
        severity: 'warning',
        kind: { kind: 'knownHostsDiscarded', value: known.value, patterns: spec.patterns },
        subject,
        fix: removal(known),
      });
    }
    const forward = first(spec, 'ForwardAgent');
    if (forward && !/^(no|false)$/i.test(forward.value)) {
      const wildcard = spec.patterns.some(isWild);
      findings.push({
        id: `agentForwarding:${block}`,
        severity: wildcard ? 'critical' : 'info',
        kind: { kind: 'agentForwarding', value: forward.value, patterns: spec.patterns, wildcard },
        subject,
        fix: removal(forward),
      });
    }
  });
  const count = agentKeys + OTHER_AGENT_KEYS;
  const lacking = lackingIdentitiesOnly(specs);
  if (count > AGENT_KEYS_LIMIT && lacking.length > 0) {
    findings.push({
      id: 'tooManyAgentKeys',
      severity: 'warning',
      kind: {
        kind: 'tooManyAgentKeys',
        agentKeys: count,
        hosts: lacking.map((id) => specs[id]?.patterns.join(' ') ?? ''),
      },
      subject: { keyId: null, hostId: null, path },
      fix: { kind: 'addIdentitiesOnly', hostIds: lacking },
    });
  }
  return findings;
}

function applyFix(specs: HostSpec[], fix: FixAction): boolean {
  if (fix.kind === 'removeConfigOption') {
    const spec = fix.hostId === null ? undefined : specs[fix.hostId];
    if (!spec) return false;
    spec.options = spec.options.filter(
      (o) => !(o.key.toLowerCase() === fix.key.toLowerCase() && o.value === fix.value),
    );
    return true;
  }
  if (fix.kind === 'addIdentitiesOnly') {
    const lacking = lackingIdentitiesOnly(specs);
    if (fix.hostIds.length === 0 || fix.hostIds.some((id) => !lacking.includes(id))) return false;
    for (const id of fix.hostIds) specs[id]?.options.push({ key: 'IdentitiesOnly', value: 'yes' });
    return true;
  }
  return false;
}

// The breach check: off by default, results dropped when the vault locks.
let enabled = false;
let running: ReturnType<typeof setInterval> | null = null;
let done = 0;
let total = 0;
let checkedAt: string | null = null;

const vaultUnlocked = () =>
  (vaultHandlers.vault_status?.({}) as VaultStatus | undefined)?.state === 'unlocked';

function forget() {
  if (running) clearInterval(running);
  running = null;
  done = 0;
  total = 0;
  checkedAt = null;
}

function status(): BreachStatus {
  if (!vaultUnlocked() && (running || checkedAt)) forget();
  return { enabled, running: running !== null, done, total, checkedAt, error: null };
}

async function passwordCount(): Promise<number> {
  const entries = (await vaultHandlers.vault_entries?.({})) as {
    inTrash: boolean;
    hasPassword: boolean;
  }[];
  return entries.filter((e) => !e.inTrash && e.hasPassword).length;
}

async function start() {
  if (running || !vaultUnlocked()) return;
  done = 0;
  total = await passwordCount();
  running = setInterval(() => {
    done += 1;
    if (done >= total && running) {
      clearInterval(running);
      running = null;
      checkedAt = new Date().toISOString();
    }
  }, 400);
}

/** Breached passwords among the vault's entries, once a check has finished. */
async function breachedFindings(): Promise<VaultFinding[]> {
  if (!enabled || !checkedAt) return [];
  const entries = (await vaultHandlers.vault_entries?.({})) as {
    id: string;
    inTrash: boolean;
    hasPassword: boolean;
  }[];
  const findings: VaultFinding[] = [];
  for (const entry of entries.filter((e) => !e.inTrash && e.hasPassword)) {
    const password = (await vaultHandlers.vault_reveal?.({ id: entry.id, field: 'password' })) as
      | string
      | undefined;
    const count = password ? BREACHED[password] : undefined;
    if (count) {
      findings.push({
        id: `breachedPassword:${entry.id}`,
        severity: 'critical',
        kind: { kind: 'breachedPassword', count },
        entryId: entry.id,
        keyId: null,
        hostId: null,
      });
    }
  }
  return findings;
}

export interface MockAuditChecks {
  /** The mock config's `Host` blocks, edited in place by fixes. */
  specs: () => HostSpec[];
  configFile: () => ConfigFile;
  /** The vault audit without breached passwords. */
  vaultAudit: () => Promise<VaultAudit>;
}

/** Handlers for backend.ts. */
export function auditChecksHandlers(mock: MockAuditChecks): Record<string, Handler> {
  return {
    fix_config: ({ fix, revision }) => {
      if (revision !== mock.configFile().view.revision) {
        return Promise.reject({ code: 'conflict', message: 'config changed' });
      }
      if (!applyFix(mock.specs(), fix as FixAction)) {
        return Promise.reject({ code: 'invalid_input', message: 'no finding offers this fix' });
      }
      return mock.configFile();
    },
    breach_status: status,
    breach_set_enabled: async ({ enabled: on }) => {
      enabled = Boolean(on);
      if (enabled) await start();
      else forget();
      return status();
    },
    breach_check: async () => {
      if (!enabled) return Promise.reject({ code: 'invalid_input', message: 'the check is off' });
      if (!vaultUnlocked()) return Promise.reject({ code: 'vault_locked', message: 'locked' });
      await start();
      return status();
    },
    run_vault_audit: async (): Promise<VaultAudit> => {
      const audit = await mock.vaultAudit();
      if (audit.state !== 'unlocked') {
        forget();
        return audit;
      }
      if (enabled && !checkedAt) await start();
      const findings = [...audit.findings, ...(await breachedFindings())];
      findings.sort(
        (a, b) =>
          SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || a.id.localeCompare(b.id),
      );
      return { ...audit, findings };
    },
  };
}
