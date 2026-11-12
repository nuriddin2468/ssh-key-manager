// Secret environments for `pnpm dev` (see backend.ts): a few projects with
// dev / staging / prod, a `.env` file to import (with lines that can't be
// read), exports (a `.env` lands in a Git working tree, to show the
// warning) and a local shell that knows the variables. Values never leave
// this file except through reveal and copy, as with the real backend.
// The files environments are written to live in envFiles.ts. shop-api's
// local and dev share STRIPE_SECRET_KEY: a shared value keeps its value
// here, and each variable that uses it a copy, changed with it.

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
import type { PartFolderChoice } from '@/bindings/PartFolderChoice';
import type { PartRename } from '@/bindings/PartRename';
import type { SharedValue } from '@/bindings/SharedValue';
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
  /** The shared value it uses, by id. */
  shared?: string;
}

/** Shared values by id: the name they were shared under, and whether in the recycle bin. */
const sharedValues = new Map<string, { name: string; inTrash: boolean }>([
  ['shared-0', { name: 'STRIPE_SECRET_KEY', inTrash: false }],
]);
let nextShared = 0;

export interface Env {
  id: string;
  /** Its KeePass group: what older versions call its project. */
  group: string;
  /** Kept on the entry; `null` from before parts: its group's name. */
  part: string | null;
  name: string;
  notes: string;
  inTrash: boolean;
  modified: string;
  vars: Variable[];
  /** Set by the user; otherwise from the name, as the backend does. */
  kind: EnvKind | null;
  files: EnvFile[];
  /** Those of `files` written only while the vault is unlocked (level 2). */
  whileUnlocked: EnvFile[];
  /** Those of `files` that are virtual (level 3). */
  virtualFiles: EnvFile[];
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

function env(group: string, name: string, vars: Variable[], extra: Partial<Env> = {}): Env {
  nextId += 1;
  return {
    id: `env-${nextId}`,
    group,
    part: null,
    name,
    notes: '',
    inTrash: false,
    modified: daysAgo(nextId),
    vars,
    kind: null,
    files: [],
    whileUnlocked: [],
    virtualFiles: [],
    ...extra,
  };
}

const envs: Env[] = [
  env('shop-api', 'local', [
    v('NODE_ENV', 'development'),
    v('PORT', '3000'),
    v('DATABASE_URL', 'postgres://shop:local-pass@localhost:5432/shop', true),
    { ...v('STRIPE_SECRET_KEY', 'sk_test_51Hx0dev', true), shared: 'shared-0' },
  ]),
  env(
    'shop-api',
    'dev',
    [
      v('NODE_ENV', 'development'),
      v('PORT', '3000', false, 'API server'),
      v('DATABASE_URL', 'postgres://shop:dev-pass@localhost:5432/shop', true),
      v('REDIS_URL', 'redis://localhost:6379/0'),
      { ...v('STRIPE_SECRET_KEY', 'sk_test_51Hx0dev', true), shared: 'shared-0' },
      v('LOG_LEVEL', 'debug'),
      v('FEATURE_FLAGS', 'checkout-v2,search'),
    ],
    {
      kind: 'local',
      files: [
        { folder: '~/code/shop-api', path: '.env' },
        { folder: '~/code/shop-api', path: 'apps/worker/.env.local' },
        { folder: '~/code/shop-api', path: '.env.development.local' },
      ],
      // A virtual file: the app serves it while it runs.
      virtualFiles: [{ folder: '~/code/shop-api', path: '.env.development.local' }],
    },
  ),
  env(
    'shop-api',
    'staging',
    [
      v('NODE_ENV', 'production'),
      v('PORT', '8080', false, 'API server'),
      v('DATABASE_URL', 'postgres://shop:st4ging@db.staging.internal:5432/shop', true),
      v('REDIS_URL', 'redis://cache.staging.internal:6379/0'),
      v('STRIPE_SECRET_KEY', 'sk_test_51Hx0staging', true),
      v('SENTRY_DSN', 'https://4f0c@o12.ingest.sentry.io/77', true),
      v('LOG_LEVEL', 'info'),
    ],
    {
      // Remote, with a file only while the vault is unlocked.
      files: [{ folder: '~/code/shop-api', path: '.env.staging' }],
      whileUnlocked: [{ folder: '~/code/shop-api', path: '.env.staging' }],
    },
  ),
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
    {
      kind: 'local',
      files: [
        { folder: '~/code/marketing-site', path: '.env.local' },
        // Deleted after it was written, to try Write again.
        { folder: '~/code/marketing-site', path: 'apps/blog/.env' },
      ],
    },
  ),
  env('marketing-site', 'prod', [
    v('NEXT_PUBLIC_API_URL', 'https://api.shop.example'),
    v('CMS_TOKEN', 'cms-prod-77c1', true),
    v('PLAUSIBLE_DOMAIN', 'shop.example'),
  ]),
  env('shop-api', 'qa-old', [v('NODE_ENV', 'test')], { inTrash: true }),
  // Shop's storefront: a second group, which becomes its second part.
  env('shop-web', 'local', [
    v('NEXT_PUBLIC_API_URL', 'http://localhost:8080'),
    v('STRIPE_PUBLISHABLE_KEY', 'pk_test_51Hq'),
  ]),
  env('shop-web', 'prod', [
    v('NEXT_PUBLIC_API_URL', 'https://api.shop.example'),
    v('STRIPE_PUBLISHABLE_KEY', 'pk_live_51Hq', true),
  ]),
  // Shop's jobs: a part with one stage, which has nothing to compare with.
  env('shop-jobs', 'local', [v('QUEUE_URL', 'amqp://localhost:5672')]),
  // In no project: Personal's, its old group the part.
  env('scripts', 'local', [v('DEPLOY_TOKEN', 'example-deploy-token', true)]),
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
export function addMockEnv(
  project: string | null,
  part: string,
  name: string,
  vars: Variable[],
): Env {
  const item = env(part || 'Personal', name, vars, {
    part,
    modified: new Date().toISOString(),
    kind: 'local',
  });
  envs.push(item);
  setMockEnvOwner(item.id, project);
  return item;
}

/**
 * Which project has each environment, by id, as the projects' records say
 * (mocks/projects.ts moves them); one in none is Personal's.
 */
const owners = new Map<string, string>();
export const mockEnvOwner = (id: string): string | null => owners.get(id) ?? null;
export function setMockEnvOwner(id: string, project: string | null) {
  owners.delete(id);
  if (project) owners.set(id, project);
}
/** The environments a project has, outside the recycle bin, in the order it took them. */
export const mockOwnedEnvs = (project: string): string[] =>
  [...owners].filter(([id, owner]) => owner === project && !find(id)?.inTrash).map(([id]) => id);
/** The environments in a KeePass group, as projects held them before. */
export const mockEnvsInGroup = (group: string): string[] =>
  envs.filter((item) => item.group === group).map((item) => item.id);
/** Its part: kept on it, else its group's name. */
export const partOf = (item: Env): string => item.part ?? item.group;
/** `Shop · backend · prod`, with the project's name from `projectName`. */
export function mockEnvLabel(item: Env, projectName?: (id: string) => string | undefined): string {
  const owner = mockEnvOwner(item.id);
  return [owner ? projectName?.(owner) : undefined, partOf(item), item.name]
    .filter(Boolean)
    .join(' · ');
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
    project: mockEnvOwner(item.id),
    part: partOf(item),
    group: item.group,
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
    variables: item.vars.map(({ name, secret, note, value, shared }) => ({
      name,
      secret,
      note,
      empty: value === '',
      shared: shared ?? null,
      unresolved: false,
    })),
    files: item.files.map((file) => ({ ...file })),
    whileUnlocked: item.whileUnlocked.map((file) => ({ ...file })),
    virtualFiles: item.virtualFiles.map((file) => ({ ...file })),
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
      (mockEnvOwner(a.id) ?? '').localeCompare(mockEnvOwner(b.id) ?? '') ||
      partOf(a).localeCompare(partOf(b)) ||
      stage(a.name) - stage(b.name) ||
      a.name.localeCompare(b.name),
  );
}

function checkName(
  project: string | null,
  part: string,
  name: string,
  except?: string,
): Promise<never> | undefined {
  if (!name.trim()) return fail('invalid_input', 'a name is missing');
  if (part.includes('/')) return fail('invalid_input', 'a part can’t have /');
  const taken = envs.some(
    (item) =>
      !item.inTrash &&
      item.id !== except &&
      mockEnvOwner(item.id) === project &&
      partOf(item).toLowerCase() === part.trim().toLowerCase() &&
      item.name.toLowerCase() === name.trim().toLowerCase(),
  );
  return taken ? fail('already_exists', `${part} / ${name}`) : undefined;
}

function touch(item: Env) {
  item.modified = new Date().toISOString();
}

/**
 * Gives environments a part, as `set_environment_part` does: those in the
 * recycle bin too, unchecked; all are checked before any changes.
 */
function setPart(ids: readonly string[], part: string): Promise<never> | undefined {
  const name = part.trim();
  if (name.includes('/')) return fail('invalid_input', 'a part can’t have /');
  const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
  const changing: Env[] = [];
  for (const id of ids) {
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    if (partOf(item) === name) continue;
    const taken =
      !item.inTrash &&
      envs.some(
        (other) =>
          !other.inTrash &&
          other.id !== item.id &&
          mockEnvOwner(other.id) === mockEnvOwner(item.id) &&
          same(other.name, item.name) &&
          (same(partOf(other), name) || ids.includes(other.id)),
      );
    if (taken) return fail('already_exists', `${name} / ${item.name}`);
    changing.push(item);
  }
  const left = new Map<string, string>();
  for (const item of changing) {
    const owner = mockEnvOwner(item.id);
    if (owner) left.set(`${owner}\n${partOf(item)}`, owner);
    item.part = name;
  }
  // A part left without environments gives its folder to the new one.
  for (const [key, owner] of left) {
    const before = key.slice(owner.length + 1);
    const emptied = !envs.some((e) => mockEnvOwner(e.id) === owner && same(partOf(e), before));
    if (emptied) partMoved(owner, before, name);
  }
  return undefined;
}

/**
 * Names a project's first part (`rename`) and runs `change`, in one
 * change: a failure puts the parts back.
 */
async function withRename<T>(rename: unknown, change: () => Promise<T>): Promise<T> {
  if (!rename) return change();
  const { ids, part } = rename as PartRename;
  const before = ids.map((id) => [find(id), find(id)?.part ?? null] as const);
  await setPart(ids, part);
  try {
    return await change();
  } catch (error) {
    for (const [item, kept] of before) if (item) item.part = kept;
    throw error;
  }
}

/** For envFiles.ts: [`withRename`]. */
export const withMockRename = withRename;

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
  json: (item) => `${partOf(item)}.${item.name}.json`,
  yaml: (item) => `${partOf(item)}.${item.name}.yaml`,
  shell: (item) => `${partOf(item)}.${item.name}.sh`,
  docker: (item) => `${partOf(item)}.${item.name}.env`,
  kubernetes: (item) => `${partOf(item)}-${item.name}-secret.yaml`,
};

let picked = false;
let pending: { id: string; format: EnvFormat; path: string } | null = null;

/** What Nearby offers when an environment is sent (mocks/nearby.ts). */
export function envSummary(id: string): ItemSummary {
  const item = find(id) ?? envs[0];
  return {
    type: 'environment',
    project: item ? partOf(item) : '',
    name: item?.name ?? '',
    variables: item?.vars.length ?? 0,
    secrets: item?.vars.filter((variable) => variable.secret).length ?? 0,
    names: item?.vars.slice(0, 3).map((variable) => variable.name) ?? [],
  };
}

/** The variables of the environment `name` in `part`, outside the recycle bin, if any. */
export function mockEnvironment(part: string, name: string): [string, string][] | undefined {
  const item = envs.find(
    (e) => !e.inTrash && partOf(e) === part && e.name.toLowerCase() === name.toLowerCase(),
  );
  return item?.vars.map((x): [string, string] => [x.name, x.value]);
}

/** A project's environment as `projects_places` reads it. */
export interface ProjectEnv {
  id: string;
  part: string;
  name: string;
  kind: EnvKind;
  files: { folder: string; path: string }[];
}

/** A project's environments outside the recycle bin, in the order the list shows them. */
export function mockProjectEnvs(project: string): ProjectEnv[] {
  return sorted()
    .filter((e) => !e.inTrash && mockEnvOwner(e.id) === project)
    .map((e) => ({ id: e.id, part: partOf(e), name: e.name, kind: kindOf(e), files: e.files }));
}

/** An environment's variables, as a shell gets them. */
export const mockEnvVars = (id: string): [string, string][] | undefined =>
  find(id)?.vars.map((x): [string, string] => [x.name, x.value]);

/** Sets the folder of a project's part, as a dialog chose it (mocks/projects.ts does). */
let partFolder: (project: string, part: string, choice: PartFolderChoice) => unknown = () =>
  undefined;
export function onMockPartFolder(listener: typeof partFolder) {
  partFolder = listener;
}
/** The folder an environment's dialog chose for its part, if any. */
export async function applyMockFolderChoice(item: Env, choice: unknown) {
  if (!choice) return;
  const owner = mockEnvOwner(item.id);
  if (!owner) return fail('invalid_input', 'an environment in Personal has no folder');
  await partFolder(owner, partOf(item), choice as PartFolderChoice);
}

/** Told when a project's part is left without environments for another, as its folder moves. */
let partMoved: (project: string, from: string, to: string) => void = () => {};
export function onMockPartMoved(listener: typeof partMoved) {
  partMoved = listener;
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
  envs_create: async ({ input, rename, folder }): Promise<EnvDetail> => {
    await requireUnlocked();
    return withRename(rename, async () => {
      const { project, part, name, notes } = input as EnvInput;
      await checkName(project, part, name);
      const item = env(part.trim() || 'Personal', name.trim(), [], {
        part: part.trim(),
        notes,
        modified: new Date().toISOString(),
      });
      envs.push(item);
      setMockEnvOwner(item.id, project);
      try {
        await applyMockFolderChoice(item, folder);
      } catch (error) {
        envs.splice(envs.indexOf(item), 1);
        setMockEnvOwner(item.id, null);
        throw error;
      }
      return detail(item);
    });
  },
  envs_update: async ({ id, input, rename, folder }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    return withRename(rename, async () => {
      const { project, part, name, notes } = input as EnvInput;
      await checkName(project, part, name, item.id);
      const [owner, before] = [mockEnvOwner(item.id), partOf(item)];
      Object.assign(item, { part: part.trim(), name: name.trim(), notes: notes.trimEnd() });
      // The last of its part takes the part's folder along.
      const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
      const stays = project === owner;
      if (
        owner &&
        stays &&
        !envs.some((e) => mockEnvOwner(e.id) === owner && same(partOf(e), before))
      ) {
        partMoved(owner, before, part.trim());
      }
      // Into another project, or Personal: the project's record says so.
      if (project !== mockEnvOwner(item.id)) setMockEnvOwner(item.id, project);
      await applyMockFolderChoice(item, folder);
      touch(item);
      return detail(item);
    });
  },
  envs_set_part: async ({ ids, part }) => {
    await requireUnlocked();
    await setPart(ids as string[], String(part));
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
    const shared = item.vars[index]?.shared;
    if (shared) {
      // A shared value changes for every environment that uses it.
      next.shared = shared;
      for (const other of envs) {
        for (const x of other.vars) if (x.shared === shared) x.value = value;
      }
    }
    if (index === -1) item.vars.push(next);
    else item.vars[index] = next;
    touch(item);
    return detail(item);
  },
  envs_shared_list: async (): Promise<SharedValue[]> => {
    await requireUnlocked();
    return [...sharedValues].map(([id, value]) => ({
      id,
      name: value.name,
      empty: false,
      inTrash: value.inTrash,
      users: envs.flatMap((item) =>
        item.vars
          .filter((x) => x.shared === id)
          .map((x) => ({ envId: item.id, variable: x.name, inTrash: item.inTrash })),
      ),
    }));
  },
  envs_share_var: async ({ id, name, others }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    const source = item?.vars.find((x) => x.name === name);
    if (!item || !source) return fail('not_found', `variable ${name}`);
    if (!source.shared) {
      nextShared += 1;
      source.shared = `shared-${nextShared}`;
      sharedValues.set(source.shared, { name: String(name), inTrash: false });
    }
    for (const otherId of others as string[]) {
      const other = find(otherId);
      if (!other || other.id === item.id) continue;
      const known = other.vars.find((x) => x.name === name);
      if (known)
        Object.assign(known, { value: source.value, secret: source.secret, shared: source.shared });
      else
        other.vars.push({ ...v(String(name), source.value, source.secret), shared: source.shared });
      touch(other);
    }
    touch(item);
    return detail(item);
  },
  envs_unshare_var: async ({ id, name }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    const variable = item?.vars.find((x) => x.name === name);
    if (!item || !variable) return fail('not_found', `variable ${name}`);
    delete variable.shared;
    touch(item);
    return detail(item);
  },
  envs_shared_delete: async ({ id }) => {
    await requireUnlocked();
    const value = sharedValues.get(String(id));
    if (!value) return fail('not_found', `shared value ${id}`);
    for (const item of envs) for (const x of item.vars) if (x.shared === id) delete x.shared;
    value.inTrash = true;
  },
  envs_set_kind: async ({ id, kind }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    const same = (a: EnvFile, b: EnvFile) => a.folder === b.folder && a.path === b.path;
    const always = item.files.filter(
      (file) =>
        !item.whileUnlocked.some((x) => same(x, file)) &&
        !item.virtualFiles.some((x) => same(x, file)),
    );
    if (kind === 'remote' && always.length > 0) {
      return fail(
        'invalid_input',
        'a remote environment has files only while the vault is unlocked: remove its other files or make them so first',
      );
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
  envs_restore: async ({ id, rename }) => {
    await requireUnlocked();
    const item = find(id);
    if (!item) return fail('not_found', `environment ${id}`);
    await withRename(rename, async () => {
      await checkName(mockEnvOwner(item.id), partOf(item), item.name, item.id);
      item.inTrash = false;
    });
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
  envs_import: async ({ target, choices, rename }): Promise<EnvImported> => {
    await requireUnlocked();
    if (!picked) return fail('invalid_input', 'choose the file to import again');
    const to = target as ImportTarget;
    let item: Env | undefined;
    if (to.type === 'new') {
      await withRename(rename, async () => checkName(to.project, to.part, to.name));
      item = env(to.part || 'Personal', to.name, [], {
        part: to.part,
        modified: new Date().toISOString(),
      });
      envs.push(item);
      setMockEnvOwner(item.id, to.project);
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
      const repository = `/Users/dev/Projects/${partOf(item)}`;
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
      mockEnvLabel(item),
      found,
      item.vars.map((x) => [x.name, x.value]),
      events as (message: ArrayBuffer | TerminalEvent) => void,
    );
  },
};
