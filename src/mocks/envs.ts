// Secret environments for `pnpm dev` (see backend.ts): a few projects with
// dev / staging / prod, a `.env` file to import (with lines that can't be
// read), exports (a `.env` lands in a Git working tree, to show the
// warning) and a local shell that knows the variables. Values never leave
// this file except through reveal and copy, as with the real backend.
// The files environments are written to live in envFiles.ts.

import type { CopyResult } from '@/bindings/CopyResult';
import type { EnvComparison } from '@/bindings/EnvComparison';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvExport } from '@/bindings/EnvExport';
import type { EnvFile } from '@/bindings/EnvFile';
import type { EnvFormat } from '@/bindings/EnvFormat';
import type { EnvImported } from '@/bindings/EnvImported';
import type { EnvImportPick } from '@/bindings/EnvImportPick';
import type { EnvInput } from '@/bindings/EnvInput';
import type { EnvKind } from '@/bindings/EnvKind';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { EnvVarInput } from '@/bindings/EnvVarInput';
import type { ImportChoice } from '@/bindings/ImportChoice';
import type { ImportTarget } from '@/bindings/ImportTarget';
import type { ItemSummary } from '@/bindings/ItemSummary';
import type { ParseProblem } from '@/bindings/ParseProblem';
import type { TerminalEvent } from '@/bindings/TerminalEvent';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { isVariableName, looksSecretName } from '@/features/envs/model';
import { findShell, openLocalShell } from './terminal';
import { vaultHandlers } from './vault';

type Handler = (args: Record<string, unknown>) => unknown;

export interface Variable {
  name: string;
  value: string;
  secret: boolean;
  note: string;
}

export interface Env {
  id: string;
  project: string;
  name: string;
  notes: string;
  inTrash: boolean;
  modified: string;
  vars: Variable[];
  /** Set by the user; otherwise from the name, as the backend does. */
  kind: EnvKind | null;
  files: EnvFile[];
}

const fail = (code: string, message: string) => Promise.reject({ code, message });

let nextId = 0;
const v = (name: string, value: string, secret = false, note = ''): Variable => ({
  name,
  value,
  secret,
  note,
});
const daysAgo = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();

function env(project: string, name: string, vars: Variable[], extra: Partial<Env> = {}): Env {
  nextId += 1;
  return {
    id: `env-${nextId}`,
    project,
    name,
    notes: '',
    inTrash: false,
    modified: daysAgo(nextId),
    vars,
    kind: null,
    files: [],
    ...extra,
  };
}

const envs: Env[] = [
  env(
    'shop-api',
    'dev',
    [
      v('NODE_ENV', 'development'),
      v('PORT', '3000', false, 'API server'),
      v('DATABASE_URL', 'postgres://shop:dev-pass@localhost:5432/shop', true),
      v('REDIS_URL', 'redis://localhost:6379/0'),
      v('STRIPE_SECRET_KEY', 'sk_test_51Hx0dev', true),
      v('LOG_LEVEL', 'debug'),
      v('FEATURE_FLAGS', 'checkout-v2,search'),
    ],
    {
      kind: 'local',
      files: [
        { folder: '~/code/shop-api', path: '.env' },
        { folder: '~/code/shop-api', path: 'apps/worker/.env.local' },
      ],
    },
  ),
  env('shop-api', 'staging', [
    v('NODE_ENV', 'production'),
    v('PORT', '8080', false, 'API server'),
    v('DATABASE_URL', 'postgres://shop:st4ging@db.staging.internal:5432/shop', true),
    v('REDIS_URL', 'redis://cache.staging.internal:6379/0'),
    v('STRIPE_SECRET_KEY', 'sk_test_51Hx0staging', true),
    v('SENTRY_DSN', 'https://4f0c@o12.ingest.sentry.io/77', true),
    v('LOG_LEVEL', 'info'),
  ]),
  env(
    'shop-api',
    'prod',
    [
      v('NODE_ENV', 'production'),
      v('PORT', '8080', false, 'API server'),
      v(
        'DATABASE_URL',
        'postgres://shop:Pr0d-9f2k@db.internal:5432/shop',
        true,
        'Primary, eu-central',
      ),
      v('REDIS_URL', 'redis://cache.internal:6379/0'),
      v('STRIPE_SECRET_KEY', 'sk_live_51Hx0prod', true),
      v('SENTRY_DSN', 'https://4f0c@o12.ingest.sentry.io/77', true),
      v('LOG_LEVEL', 'warn'),
      v(
        'JWT_PRIVATE_KEY',
        '-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIK3x\n-----END PRIVATE KEY-----',
        true,
      ),
    ],
    { notes: 'Hetzner, eu-central. Rotate the Stripe key with the payments team.' },
  ),
  env(
    'marketing-site',
    'dev',
    [v('NEXT_PUBLIC_API_URL', 'http://localhost:3000'), v('CMS_TOKEN', 'cms-dev-0a9f', true)],
    { kind: 'local', files: [{ folder: '~/code/marketing-site', path: '.env.local' }] },
  ),
  env('marketing-site', 'prod', [
    v('NEXT_PUBLIC_API_URL', 'https://api.shop.example'),
    v('CMS_TOKEN', 'cms-prod-77c1', true),
    v('PLAUSIBLE_DOMAIN', 'shop.example'),
  ]),
  env('shop-api', 'qa-old', [v('NODE_ENV', 'test')], { inTrash: true }),
];

/** The sample file the import's "file dialog" picks. */
const SAMPLE_PATH = '/Users/dev/Projects/billing-worker/.env.staging';
const SAMPLE = `# Billing worker, staging
NODE_ENV=production
export QUEUE_URL=amqp://queue.staging.internal:5672
DATABASE_URL="postgres://billing:b1ll-st@db.staging.internal/billing"
STRIPE_WEBHOOK_SECRET=whsec_9f8e7d6c5b4a39281706f5e4d3c2b1a0
BATCH_SIZE=200 # invoices per run
GREETING='Hello, \${CUSTOMER_NAME}!'
RETRY_POLICY=
this line has no equals sign
2FA_ISSUER=Shop
`;

function find(id: unknown): Env | undefined {
  return envs.find((item) => item.id === id);
}

/** The kind the backend gives: as set, else `local` for local / dev / development. */
export function kindOf(item: Env): EnvKind {
  return (
    item.kind ??
    (['local', 'dev', 'development'].includes(item.name.toLowerCase()) ? 'local' : 'remote')
  );
}

/** The sample environments, for envFiles.ts. */
export const mockEnvs = () => envs;
export const mockEnv = (id: unknown) => find(id);
/** An environment's detail as `envs_get` gives it. */
export const mockEnvDetail = (item: Env) => detail(item);
/** Adds an environment as `envs_create` does, for taking a file under management. */
export function addMockEnv(project: string, name: string, vars: Variable[]): Env {
  const item = env(project, name, vars, { modified: new Date().toISOString(), kind: 'local' });
  envs.push(item);
  return item;
}
export const mockVariable = v;
export const touchMockEnv = (item: Env) => touch(item);

function requireUnlocked(): Promise<never> | undefined {
  const state = (vaultHandlers.vault_status?.({}) as VaultStatus | undefined)?.state;
  if (state !== 'unlocked') return fail('vault_locked', 'the vault is locked');
  vaultHandlers.vault_activity?.({});
  return undefined;
}

function summary(item: Env): EnvSummary {
  return {
    id: item.id,
    project: item.project,
    name: item.name,
    kind: kindOf(item),
    variableCount: item.vars.length,
    secretCount: item.vars.filter((variable) => variable.secret).length,
    inTrash: item.inTrash,
    modified: item.modified,
  };
}

function detail(item: Env): EnvDetail {
  return {
    ...summary(item),
    notes: item.notes,
    variables: item.vars.map(({ name, secret, note, value }) => ({
      name,
      secret,
      note,
      empty: value === '',
    })),
    files: item.files.map((file) => ({ ...file })),
  };
}

const STAGES = ['local', 'dev', 'test', 'staging', 'prod'];
const stage = (name: string) => {
  const index = STAGES.indexOf(name.toLowerCase());
  return index === -1 ? STAGES.length : index;
};

function sorted(): Env[] {
  return [...envs].sort(
    (a, b) =>
      Number(a.inTrash) - Number(b.inTrash) ||
      a.project.localeCompare(b.project) ||
      stage(a.name) - stage(b.name) ||
      a.name.localeCompare(b.name),
  );
}

function checkName(project: string, name: string, except?: string): Promise<never> | undefined {
  if (!project.trim() || !name.trim()) return fail('invalid_input', 'a name is missing');
  const taken = envs.some(
    (item) =>
      !item.inTrash &&
      item.id !== except &&
      item.project === project.trim() &&
      item.name.toLowerCase() === name.trim().toLowerCase(),
  );
  return taken ? fail('already_exists', `${project} / ${name}`) : undefined;
}

function touch(item: Env) {
  item.modified = new Date().toISOString();
}

/** A small `.env` reader: enough for the sample, not the backend's rules. */
function parse(text: string) {
  const vars: { name: string; value: string; line: number }[] = [];
  const problems: ParseProblem[] = [];
  text.split('\n').forEach((raw, index) => {
    const line = index + 1;
    const trimmed = raw.trim().replace(/^export\s+/, '');
    if (!trimmed || trimmed.startsWith('#')) return;
    const equals = trimmed.indexOf('=');
    if (equals === -1) {
      problems.push({ line, kind: 'noEquals', name: null });
      return;
    }
    const name = trimmed.slice(0, equals).trim();
    if (!isVariableName(name)) {
      problems.push({ line, kind: 'badName', name: null });
      return;
    }
    let value = trimmed.slice(equals + 1).trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'") && value.endsWith(quote)) value = value.slice(1, -1);
    else value = value.replace(/\s+#.*$/, '');
    vars.push({ name, value, line });
  });
  return { vars, problems };
}

const looksSecret = (name: string, value: string) =>
  looksSecretName(name) || /^(whsec_|sk_live_|sk_test_)|:\/\/[^/@]*:[^/@]+@/.test(value);

/** The sample `.env` reader and secret guess, for envFiles.ts. */
export const parseMockDotenv = parse;
export const mockLooksSecret = looksSecret;

const FILE_NAMES: Record<EnvFormat, (item: Env) => string> = {
  dotenv: () => '.env',
  json: (item) => `${item.project}.${item.name}.json`,
  yaml: (item) => `${item.project}.${item.name}.yaml`,
  shell: (item) => `${item.project}.${item.name}.sh`,
  docker: (item) => `${item.project}.${item.name}.env`,
  kubernetes: (item) => `${item.project}-${item.name}-secret.yaml`,
};

let picked = false;
let pending: { id: string; format: EnvFormat; path: string } | null = null;

/** What Nearby offers when an environment is sent (mocks/nearby.ts). */
export function envSummary(id: string): ItemSummary {
  const item = find(id) ?? envs[0];
  return {
    type: 'environment',
    project: item?.project ?? '',
    name: item?.name ?? '',
    variables: item?.vars.length ?? 0,
    secrets: item?.vars.filter((variable) => variable.secret).length ?? 0,
    names: item?.vars.slice(0, 3).map((variable) => variable.name) ?? [],
  };
}

export const envsHandlers: Record<string, Handler> = {
  envs_list: async (): Promise<EnvSummary[]> => {
    await requireUnlocked();
    return sorted().map(summary);
  },
  envs_get: async ({ id }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    return detail(item);
  },
  envs_create: async ({ input }): Promise<EnvDetail> => {
    await requireUnlocked();
    const { project, name, notes } = input as EnvInput;
    await checkName(project, name);
    const item = env(project.trim(), name.trim(), [], {
      notes,
      modified: new Date().toISOString(),
    });
    envs.push(item);
    return detail(item);
  },
  envs_update: async ({ id, input }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    const { project, name, notes } = input as EnvInput;
    await checkName(project, name, item.id);
    Object.assign(item, { project: project.trim(), name: name.trim(), notes: notes.trimEnd() });
    touch(item);
    return detail(item);
  },
  envs_set_var: async ({ id, previous, input }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    const change = input as EnvVarInput;
    if (!isVariableName(change.name)) return fail('invalid_input', 'not a variable name');
    if (item.vars.some((x) => x.name === change.name && x.name !== previous)) {
      return fail('already_exists', change.name);
    }
    const index = item.vars.findIndex((x) => x.name === previous);
    const value = change.value ?? item.vars[index]?.value ?? '';
    const next = v(change.name, value, change.secret, change.note);
    if (index === -1) item.vars.push(next);
    else item.vars[index] = next;
    touch(item);
    return detail(item);
  },
  envs_set_kind: async ({ id, kind }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    if (kind === 'remote' && item.files.length > 0) {
      return fail('invalid_input', 'a remote environment has no files: remove its files first');
    }
    item.kind = kind as EnvKind;
    touch(item);
    return detail(item);
  },
  envs_remove_var: async ({ id, name }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    item.vars = item.vars.filter((x) => x.name !== name);
    touch(item);
    return detail(item);
  },
  envs_reveal: async ({ id, name }): Promise<string> => {
    await requireUnlocked();
    const variable = find(id)?.vars.find((x) => x.name === name);
    if (!variable) return fail('not_found', `variable ${name}`);
    return variable.value;
  },
  envs_copy: async ({ id, name }): Promise<CopyResult> => {
    await requireUnlocked();
    const variable = find(id)?.vars.find((x) => x.name === name);
    if (!variable?.value) return fail('not_found', 'nothing to copy');
    await navigator.clipboard.writeText(variable.value).catch(() => undefined);
    return { clearsInSecs: variable.secret ? 30 : null };
  },
  envs_trash: async ({ id }) => {
    await requireUnlocked();
    const item = find(id);
    if (item) item.inTrash = true;
  },
  envs_restore: async ({ id }) => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    await checkName(item.project, item.name, item.id);
    item.inTrash = false;
  },
  envs_delete: async ({ id }) => {
    await requireUnlocked();
    const index = envs.findIndex((item) => item.id === id && item.inTrash);
    if (index === -1) return fail('invalid_input', 'only environments in the recycle bin');
    envs.splice(index, 1);
  },
  envs_compare: async ({ left, right }): Promise<EnvComparison> => {
    await requireUnlocked();
    const a = find(left)?.vars ?? [];
    const b = find(right)?.vars ?? [];
    const other = (name: string) => b.find((x) => x.name === name);
    return {
      onlyLeft: a.filter((x) => !other(x.name)).map((x) => x.name),
      onlyRight: b.filter((x) => !a.some((y) => y.name === x.name)).map((x) => x.name),
      changed: a
        .filter((x) => other(x.name) && other(x.name)?.value !== x.value)
        .map((x) => x.name),
      same: a.filter((x) => other(x.name)?.value === x.value).map((x) => x.name),
    };
  },
  envs_import_pick: async (): Promise<EnvImportPick> => {
    await requireUnlocked();
    const { vars, problems } = parse(SAMPLE);
    picked = true;
    return {
      path: SAMPLE_PATH,
      preview: {
        suggestedProject: 'billing-worker',
        suggestedName: 'staging',
        variables: vars.map(({ name, value, line }) => ({
          name,
          line,
          secret: looksSecret(name, value),
          empty: value === '',
          multiline: value.includes('\n'),
        })),
        problems,
      },
    };
  },
  envs_import: async ({ target, choices }): Promise<EnvImported> => {
    await requireUnlocked();
    if (!picked) return fail('invalid_input', 'choose the file to import again');
    const to = target as ImportTarget;
    let item: Env | undefined;
    if (to.type === 'new') {
      await checkName(to.project, to.name);
      item = env(to.project, to.name, [], { modified: new Date().toISOString() });
      envs.push(item);
    } else {
      item = find(to.id);
    }
    if (!item) return fail('not_found', 'environment');
    let added = 0;
    let replaced = 0;
    const { vars } = parse(SAMPLE);
    for (const choice of choices as ImportChoice[]) {
      const read = vars.find((x) => x.name === choice.name);
      if (!read) continue;
      const known = item.vars.find((x) => x.name === choice.name);
      if (known) {
        Object.assign(known, { value: read.value, secret: choice.secret });
        replaced += 1;
      } else {
        item.vars.push(v(choice.name, read.value, choice.secret));
        added += 1;
      }
    }
    picked = false;
    touch(item);
    return { id: item.id, added, replaced };
  },
  envs_export: async ({ id, format }): Promise<EnvExport> => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    const kind = format as EnvFormat;
    if (kind === 'docker' && item.vars.some((x) => x.value.includes('\n'))) {
      const name = item.vars.find((x) => x.value.includes('\n'))?.name;
      return fail('invalid_input', `${name} has a line break, which a Docker env file can't hold`);
    }
    // A `.env` goes next to the project's code, which Git doesn't ignore yet.
    if (kind === 'dotenv') {
      const repository = `/Users/dev/Projects/${item.project}`;
      const path = `${repository}/.env`;
      pending = { id: item.id, format: kind, path };
      return { path, written: false, count: 0, repository };
    }
    const path = `/Users/dev/Documents/${FILE_NAMES[kind](item)}`;
    return { path, written: true, count: item.vars.length, repository: null };
  },
  envs_export_anyway: async (): Promise<EnvExport> => {
    await requireUnlocked();
    if (!pending) return fail('invalid_input', 'choose where to save again');
    const item = find(pending.id);
    const result = {
      path: pending.path,
      written: true,
      count: item?.vars.length ?? 0,
      repository: pending.path.replace(/\/[^/]*$/, ''),
    };
    pending = null;
    return result;
  },
  envs_run: async ({ id, shell, events }) => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    const found = findShell(shell);
    if (!found) return fail('not_found', 'this shell isn’t on this computer anymore');
    return openLocalShell(
      `${item.project} · ${item.name}`,
      found,
      item.vars.map((x) => [x.name, x.value]),
      events as (message: ArrayBuffer | TerminalEvent) => void,
    );
  },
};
