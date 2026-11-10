// The leak scanner for `pnpm dev` (see backend.ts). The app searches files
// in Rust; this pretends to: a scan takes a few seconds, finds a few of the
// mock vault's secrets in made-up AI sessions, a repository, a stray `.env`
// and the shell history, and Redact removes a finding. Like the app, it needs
// the vault unlocked and drops its results when the vault locks.

import type { AiTool } from '@/bindings/AiTool';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { LeakFinding } from '@/bindings/LeakFinding';
import type { LeakPlace } from '@/bindings/LeakPlace';
import type { LeakRedaction } from '@/bindings/LeakRedaction';
import type { LeakSecret } from '@/bindings/LeakSecret';
import type { LeakSettings } from '@/bindings/LeakSettings';
import type { LeakStatus } from '@/bindings/LeakStatus';
import type { LeakStop } from '@/bindings/LeakStop';
import type { Severity } from '@/bindings/Severity';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { envsHandlers } from './envs';
import { vaultHandlers } from './vault';

type Handler = (args: Record<string, unknown>) => unknown;

const HOME = '/Users/dev';
const LISTING_MS = 700;
const READING_MS = 3200;
const FILES = 1284;
const BYTES = 412_000_000;
/** Folders the dialog "picks", one per click. */
const PICKS = [`${HOME}/code`, `${HOME}/work/shop-api`, `${HOME}/Downloads`];

const TOOLS: { tool: AiTool; found: boolean }[] = [
  { tool: 'claudeCode', found: true },
  { tool: 'codex', found: true },
  { tool: 'geminiCli', found: false },
  { tool: 'continue', found: false },
  { tool: 'cline', found: true },
  { tool: 'rooCode', found: false },
];

let settings: LeakSettings = { ai: true, history: true, folders: [`${HOME}/code`] };
let picked = 1;
let running: { started: number } | null = null;
let last: { findings: LeakFinding[]; at: string } | null = null;
let stopped: LeakStop | null = null;
let timer: ReturnType<typeof setTimeout> | undefined;

const vaultUnlocked = () =>
  (vaultHandlers.vault_status?.({}) as VaultStatus | undefined)?.state === 'unlocked';

const fail = (code: string, message: string) => Promise.reject({ code, message });

function severity(place: LeakPlace): Severity {
  if (place.kind === 'aiSession') return 'critical';
  if (place.kind === 'shellHistory') return 'warning';
  if (place.git === 'tracked' || place.git === 'untracked') return 'critical';
  return place.git === 'ignored' ? 'info' : 'warning';
}

let nextId = 0;
function finding(
  secret: LeakSecret,
  place: LeakPlace,
  path: string,
  line: number,
  extra: Partial<LeakFinding> = {},
): LeakFinding {
  nextId += 1;
  return {
    id: `leak:${nextId.toString(16).padStart(32, '0')}`,
    severity: severity(place),
    secret,
    place,
    path,
    line,
    occurrences: 1,
    encodings: [],
    redactable: place.kind === 'aiSession',
    modified: new Date(Date.now() - nextId * 36 * 3600 * 1000).toISOString(),
    ...extra,
  };
}

/** Made-up findings for the mock vault's secrets. */
async function findings(): Promise<LeakFinding[]> {
  const envs = ((await envsHandlers.envs_list?.({})) ?? []) as EnvSummary[];
  const entries = ((await vaultHandlers.vault_entries?.({})) ?? []) as EntrySummary[];
  const variable = (project: string, environment: string, name: string): LeakSecret | null => {
    const env = envs.find((e) => e.project === project && e.name === environment && !e.inTrash);
    return env ? { kind: 'variable', envId: env.id, project, environment, name } : null;
  };
  const password = (title: string): LeakSecret | null => {
    const entry = entries.find((e) => e.title === title && !e.inTrash);
    return entry ? { kind: 'password', entryId: entry.id, title, entryKind: entry.kind } : null;
  };
  const claude = (session: string): string =>
    `${HOME}/.claude/projects/-Users-dev-work-shop-api/${session}.jsonl`;
  const out: LeakFinding[] = [];
  const add = (
    secret: LeakSecret | null,
    place: LeakPlace,
    path: string,
    line: number,
    extra: Partial<LeakFinding> = {},
  ) => {
    if (secret) out.push(finding(secret, place, path, line, extra));
  };
  const stripe = variable('shop-api', 'prod', 'STRIPE_SECRET_KEY');
  const ai = (tool: AiTool): LeakPlace => ({ kind: 'aiSession', tool });
  add(stripe, ai('claudeCode'), claude('3f9c1a7e-5b2d-4c8e-9a10-6d7e8f9a0b1c'), 214, {
    occurrences: 3,
  });
  add(stripe, ai('claudeCode'), claude('9b2e4d6f-1a3c-4e5f-8a7b-0c1d2e3f4a5b'), 57);
  add(
    stripe,
    ai('codex'),
    `${HOME}/.codex/sessions/2026/11/08/rollout-2026-11-08T10-14-03-1f2e.jsonl`,
    1022,
  );
  add(
    stripe,
    ai('claudeCode'),
    `${HOME}/.claude/projects/-Users-dev-work-shop-api/3f9c1a7e/tool-results/toolu_01.txt`,
    4,
  );
  add(
    variable('shop-api', 'staging', 'DATABASE_URL'),
    { kind: 'file', git: 'tracked', repository: `${HOME}/work/shop-api` },
    `${HOME}/work/shop-api/docker-compose.yml`,
    18,
  );
  add(
    variable('shop-api', 'staging', 'DATABASE_URL'),
    { kind: 'file', git: 'untracked', repository: `${HOME}/work/shop-api` },
    `${HOME}/work/shop-api/scripts/seed.sh`,
    3,
    { encodings: ['url'] },
  );
  add(
    variable('marketing-site', 'prod', 'CMS_TOKEN'),
    { kind: 'file', git: 'ignored', repository: `${HOME}/code/marketing-site` },
    `${HOME}/code/marketing-site/.env.local`,
    2,
  );
  add(
    variable('marketing-site', 'prod', 'CMS_TOKEN'),
    { kind: 'file', git: 'outside', repository: null },
    `${HOME}/Downloads/marketing.env`,
    5,
  );
  add(password('GitHub'), { kind: 'shellHistory', shell: 'zsh' }, `${HOME}/.zsh_history`, 8812, {
    encodings: ['base64'],
  });
  const order: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
  return out.sort((a, b) => order[a.severity] - order[b.severity]);
}

function forget() {
  if (timer) clearTimeout(timer);
  if (running) stopped = 'locked';
  running = null;
  last = null;
}

function status(): LeakStatus {
  if (!vaultUnlocked() && (running || last)) forget();
  const now = Date.now();
  const reading = running && now - running.started >= LISTING_MS;
  const share = running ? Math.min(1, (now - running.started - LISTING_MS) / READING_MS) : 0;
  return {
    settings,
    tools: TOOLS,
    phase: running ? (reading ? 'reading' : 'listing') : null,
    filesDone: reading ? Math.floor(FILES * share) : 0,
    filesTotal: reading ? FILES : 0,
    bytesDone: reading ? Math.floor(BYTES * share) : 0,
    bytesTotal: reading ? BYTES : 0,
    secrets: 9,
    scannedAt: last?.at ?? null,
    filesScanned: last ? FILES : 0,
    findings: last?.findings.length ?? 0,
    leaked: new Set(last?.findings.map((f) => JSON.stringify(f.secret)) ?? []).size,
    unreadable: last ? 2 : 0,
    truncated: false,
    stopped,
  };
}

export const leaksHandlers: Record<string, Handler> = {
  leaks_status: status,
  leaks_set_sources: ({ ai, history }) => {
    settings = { ...settings, ai: Boolean(ai), history: Boolean(history) };
    return status();
  },
  leaks_add_folders: () => {
    const next = PICKS[picked % PICKS.length] as string;
    picked += 1;
    if (!settings.folders.includes(next))
      settings = { ...settings, folders: [...settings.folders, next] };
    return status();
  },
  leaks_remove_folder: ({ folder }) => {
    settings = { ...settings, folders: settings.folders.filter((f) => f !== folder) };
    return status();
  },
  leaks_start: () => {
    if (!vaultUnlocked()) return fail('vault_locked', 'locked');
    if (running) return status();
    if (!settings.ai && !settings.history && settings.folders.length === 0) {
      stopped = 'noSources';
      return status();
    }
    stopped = null;
    const started = Date.now();
    running = { started };
    timer = setTimeout(async () => {
      const found = await findings();
      if (!running || running.started !== started) return;
      running = null;
      last = { findings: found, at: new Date().toISOString() };
    }, LISTING_MS + READING_MS);
    return status();
  },
  leaks_cancel: () => {
    if (!running) return;
    if (timer) clearTimeout(timer);
    running = null;
    stopped = 'cancelled';
  },
  leaks_findings: () => (vaultUnlocked() ? (last?.findings ?? []) : []),
  leaks_redact: ({ ids }): LeakRedaction | Promise<never> => {
    if (!vaultUnlocked()) return fail('vault_locked', 'locked');
    if (running) return fail('conflict', 'wait for the scan to finish');
    const wanted = new Set(ids as string[]);
    const done = (last?.findings ?? []).filter((f) => f.redactable && wanted.has(f.id));
    if (last) last.findings = last.findings.filter((f) => !done.includes(f));
    return {
      files: done.length,
      replaced: done.reduce((sum, f) => sum + f.occurrences, 0),
      left: 0,
      stale: 0,
    };
  },
};
