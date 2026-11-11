// Managed `.env` files for `pnpm dev` (see backend.ts), as
// src-tauri/src/commands/env_files.rs answers. The sample environments of
// envs.ts are written to files in the sample projects' folders (projects.ts):
// shop-api / dev to `.env`, which someone edited in an editor (the first
// round takes the edit to the vault, to show Undo), and to
// `apps/worker/.env.local`, which is in conflict with the vault;
// marketing-site / dev to `.env.local`, which Git doesn't ignore and which
// lacks a name its `.env.example` has, and to `apps/blog/.env`, which was
// deleted (Write again). Binding a file under shop-api finds a working tree
// that doesn't ignore it, to show the warning first; under shop-web, a
// folder that isn't on this computer, where Git can't be asked. Adding
// marketing-site's files to its `.gitignore` fails (it is a link), to show
// that failure. A few `.env` files in the projects'
// folders are unmanaged, to take under management. Files exist only here:
// their variables are kept with each binding.

import type { CloudService } from '@/bindings/CloudService';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvFile } from '@/bindings/EnvFile';
import type { EnvFileChange } from '@/bindings/EnvFileChange';
import type { EnvFileCheck } from '@/bindings/EnvFileCheck';
import type { EnvFileComparison } from '@/bindings/EnvFileComparison';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { EnvFileStatus } from '@/bindings/EnvFileStatus';
import type { EnvFilesOverview } from '@/bindings/EnvFilesOverview';
import type { EnvFilesSynced } from '@/bindings/EnvFilesSynced';
import type { EnvImported } from '@/bindings/EnvImported';
import type { EnvImportPreview } from '@/bindings/EnvImportPreview';
import type { EnvUndo } from '@/bindings/EnvUndo';
import type { ExampleCheck } from '@/bindings/ExampleCheck';
import type { FileState } from '@/bindings/FileState';
import type { GitInfo } from '@/bindings/GitInfo';
import type { ImportChoice } from '@/bindings/ImportChoice';
import type { ImportTarget } from '@/bindings/ImportTarget';
import type { KeepSide } from '@/bindings/KeepSide';
import type { Project } from '@/bindings/Project';
import {
  addMockEnv,
  type Env,
  kindOf,
  mockEnv,
  mockEnvDetail,
  mockEnvs,
  mockLooksSecret,
  mockVariable,
  parseMockDotenv,
  touchMockEnv,
  type Variable,
} from './envs';
import { projectsHandlers } from './projects';
import { isMockVaultUnlocked } from './vault';

type Handler = (args: Record<string, unknown>) => unknown;

const fail = (code: string, message: string) => Promise.reject({ code, message });
const HOME = '/Users/dev';
const TEMPLATE_WORDS = ['example', 'sample', 'template', 'dist', 'defaults', 'tmpl'];

/** The states a sample file can be in. */
type SimpleState = Extract<
  FileState,
  { type: 'inSync' | 'conflict' | 'missing' | 'folderMissing' }
>['type'];

/** What the mock knows of a file on "disk". */
interface MockFile {
  /** The file's variables; `null` while it isn't there. */
  vars: Record<string, string> | null;
  state: SimpleState;
  git: GitInfo | null;
  cloud: CloudService | null;
  example: ExampleCheck | null;
}

const key = (envId: string, file: EnvFile) => `${envId}\n${file.folder}\n${file.path}`;
const expand = (folder: string) =>
  folder === '~' ? HOME : folder.startsWith('~/') ? `${HOME}/${folder.slice(2)}` : folder;
const locate = (file: EnvFile) => `${expand(file.folder)}/${file.path}`;
const repository = (file: EnvFile): GitInfo => ({
  state: 'ignored',
  repository: expand(file.folder),
});

const disk = new Map<string, MockFile>();

/** The sample environment `group / name`. */
const sample = (group: string, name: string) =>
  mockEnvs().find((item) => item.project === group && item.name === name);

let seeded = false;
/** An edit made in an editor, which the next round takes to the vault. */
let pendingEdit: { envId: string; file: EnvFile; vars: Record<string, string> } | null = null;
/** The variables before each edit that went to the vault, by environment and revision. */
const undos = new Map<string, Variable[]>();

function varsOf(item: Env): Record<string, string> {
  return Object.fromEntries(item.vars.map((x) => [x.name, x.value]));
}

function seed() {
  if (seeded) return;
  seeded = true;
  const shop = sample('shop-api', 'dev');
  const marketing = sample('marketing-site', 'dev');
  if (shop) {
    const [root, worker] = shop.files;
    if (root) {
      disk.set(key(shop.id, root), {
        vars: varsOf(shop),
        state: 'inSync',
        git: repository(root),
        cloud: null,
        example: { file: '.env.example', missing: ['SENTRY_DSN'] },
      });
      pendingEdit = {
        envId: shop.id,
        file: root,
        vars: { ...varsOf(shop), PORT: '3001', DEBUG: 'shop:*' },
      };
    }
    if (worker) {
      disk.set(key(shop.id, worker), {
        vars: { ...varsOf(shop), LOG_LEVEL: 'info', QUEUE_CONCURRENCY: '4' },
        state: 'conflict',
        git: repository(worker),
        cloud: null,
        example: null,
      });
    }
  }
  const local = marketing?.files[0];
  if (marketing && local) {
    disk.set(key(marketing.id, local), {
      vars: varsOf(marketing),
      state: 'inSync',
      git: { state: 'untracked', repository: expand(local.folder) },
      // As if the code folder were kept in Dropbox.
      cloud: 'dropbox',
      example: { file: '.env.example', missing: ['PLAUSIBLE_DOMAIN'] },
    });
    const blog = marketing.files[1];
    if (blog) {
      disk.set(key(marketing.id, blog), {
        vars: null,
        state: 'missing',
        git: repository(blog),
        cloud: null,
        example: null,
      });
    }
  }
}

/** `.env` files in the sample projects' folders that no environment is written to. */
const UNMANAGED: { folder: string; path: string; text: string }[] = [
  {
    folder: '~/code/shop-web',
    path: '.env',
    text: 'NEXT_PUBLIC_API_URL=http://localhost:3000\nSESSION_SECRET=dev-session-7f3a\n',
  },
  {
    folder: '~/code/shop-web',
    path: 'apps/admin/.env.development.local',
    text: '# Admin, local only\nADMIN_TOKEN=adm-dev-11c2\nPORT=3100\n',
  },
  {
    folder: '~/code/marketing-site',
    path: '.env.production',
    text: 'NEXT_PUBLIC_API_URL=https://api.shop.example\nCMS_TOKEN=cms-prod-77c1\n',
  },
];
const adopted = new Set<string>();

async function projects(): Promise<Project[]> {
  return (await projectsHandlers.projects_list?.({})) as Project[];
}

function requireUnlocked(): Promise<never> | undefined {
  return isMockVaultUnlocked() ? undefined : fail('vault_locked', 'the vault is locked');
}

const isTemplate = (name: string) =>
  name
    .toLowerCase()
    .split('.')
    .some((part) => TEMPLATE_WORDS.includes(part));

/** The backend's checks of a binding's path, roughly. */
function checkFile(file: EnvFile): EnvFile | Promise<never> {
  const parts = file.path.split(/[/\\]/);
  const name = (parts.at(-1) ?? '').toLowerCase();
  const bad = parts.some((part) => !part || part === '.' || part === '..' || part === '.git');
  const envLike =
    name === '.env' || name.startsWith('.env.') || name.endsWith('.env') || name === '.dev.vars';
  if (bad || !envLike || isTemplate(name)) {
    return fail('invalid_input', `${file.path} isn't a .env file's name, or it is a template`);
  }
  return { folder: file.folder, path: parts.join('/') };
}

function holds(all: Project[], group: string, folder: string) {
  return all.some((p) => p.environments.includes(group) && p.folders.includes(folder));
}

async function statusOf(item: Env, file: EnvFile, all?: Project[]): Promise<EnvFileStatus> {
  seed();
  const base = { envId: item.id, group: item.project, envName: item.name, file: { ...file } };
  const inactive = item.inTrash
    ? 'inTrash'
    : kindOf(item) === 'remote'
      ? 'remote'
      : holds(all ?? (await projects()), item.project, file.folder)
        ? null
        : 'notInProject';
  if (inactive) {
    return { ...base, location: null, state: { type: 'inactive', reason: inactive } };
  }
  const found = disk.get(key(item.id, file));
  return { ...base, location: locate(file), state: { type: found?.state ?? 'missing' } };
}

async function statuses(): Promise<EnvFileStatus[]> {
  const all = await projects();
  const out: EnvFileStatus[] = [];
  for (const item of mockEnvs()) {
    for (const file of item.files) out.push(await statusOf(item, file, all));
  }
  return out;
}

/** Saves `vars` to the environment as a file's edit does, keeping the old ones for Undo. */
function takeFile(item: Env, file: EnvFile, vars: Record<string, string>): EnvFileChange {
  const before = item.vars.map((x) => ({ ...x }));
  const added = Object.keys(vars).filter((name) => !item.vars.some((x) => x.name === name));
  const removed = item.vars.filter((x) => !(x.name in vars)).map((x) => x.name);
  const changed = item.vars
    .filter((x) => x.name in vars && vars[x.name] !== x.value)
    .map((x) => x.name);
  item.vars = [
    ...item.vars
      .filter((x) => x.name in vars)
      .map((x) => ({ ...x, value: vars[x.name] ?? x.value })),
    ...added.map((name) =>
      mockVariable(name, vars[name] ?? '', mockLooksSecret(name, vars[name] ?? '')),
    ),
  ];
  touchMockEnv(item);
  const after = `rev-${Date.now()}`;
  undos.set(`${item.id}\n${after}`, before);
  return {
    envId: item.id,
    group: item.project,
    envName: item.name,
    file: { ...file },
    added,
    changed,
    removed,
    undo: { envId: item.id, before: `rev-before-${after}`, after },
  };
}

/** The vault's values go to every file of the environment that isn't in conflict. */
function writeFiles(item: Env, except?: EnvFile): EnvFile[] {
  const written: EnvFile[] = [];
  for (const file of item.files) {
    if (except && except.folder === file.folder && except.path === file.path) continue;
    const found = disk.get(key(item.id, file));
    if (!found || found.state === 'conflict' || found.state === 'missing') continue;
    found.vars = varsOf(item);
    found.state = 'inSync';
    written.push(file);
  }
  return written;
}

async function synced(
  changes: EnvFileChange[],
  written: { item: Env; file: EnvFile }[],
): Promise<EnvFilesSynced> {
  const all = await projects();
  return {
    changes,
    written: await Promise.all(written.map(({ item, file }) => statusOf(item, file, all))),
    files: await statuses(),
  };
}

function findEnv(id: unknown): Env | Promise<never> {
  return mockEnv(id) ?? fail('not_found', `environment ${id}`);
}

function boundFile(item: Env, file: EnvFile): EnvFile | Promise<never> {
  return (
    item.files.find((x) => x.folder === file.folder && x.path === file.path) ??
    fail('not_found', file.path)
  );
}

/** A made-up revision of a file's variables, as the backend's keyed hash stands for them. */
const revisionOf = (vars: Record<string, string>) =>
  `rev-${Object.entries(vars)
    .sort()
    .map(([name, value]) => `${name}=${value.length}`)
    .join(',')}`;

function compare(
  left: Record<string, string>,
  right: Record<string, string> | null,
): EnvFileComparison {
  const names = Object.keys(left);
  const file = right ?? {};
  return {
    revision: right ? revisionOf(right) : null,
    onlyLeft: names.filter((name) => !(name in file)),
    onlyRight: Object.keys(file).filter((name) => !(name in left)),
    changed: names.filter((name) => name in file && file[name] !== left[name]),
    same: names.filter((name) => file[name] === left[name]),
  };
}

function unmanagedFor(file: EnvFile) {
  return UNMANAGED.find(
    (x) =>
      x.folder === file.folder && x.path === file.path && !adopted.has(`${x.folder}\n${x.path}`),
  );
}

/** The files with Git and cloud folders, as the backend reports them. */
async function reports(project: unknown, all: Project[]): Promise<EnvFileReport[]> {
  const wanted = (ids: string[]) => project == null || ids.includes(String(project));
  const out: EnvFileReport[] = [];
  for (const status of await statuses()) {
    const ids = all
      .filter(
        (p) => p.environments.includes(status.group) && p.folders.includes(status.file.folder),
      )
      .map((p) => p.id);
    if (!wanted(ids)) continue;
    const found = disk.get(key(status.envId, status.file));
    out.push({
      ...status,
      projects: ids,
      cloud: status.location ? (found?.cloud ?? null) : null,
      example: status.location ? (found?.example ?? null) : null,
      git: status.location ? (found?.git ?? null) : null,
    });
  }
  return out;
}

export const envFilesHandlers: Record<string, Handler> = {
  envs_files_check: async ({ id, file }): Promise<EnvFileCheck> => {
    await requireUnlocked();
    seed();
    const item = await findEnv(id);
    const checked = await checkFile(file as EnvFile);
    if (kindOf(item) === 'remote') {
      return fail('invalid_input', 'a remote environment has no files: make it local first');
    }
    if (!holds(await projects(), item.project, checked.folder)) {
      return fail('invalid_input', "the folder isn't in a project that holds the environment");
    }
    if (item.files.some((x) => x.folder === checked.folder && x.path === checked.path)) {
      return fail('already_exists', checked.path);
    }
    // `~/code/shop-web` stands for a folder that isn't on this computer:
    // Git can't be asked there. Elsewhere a missing subfolder is asked from
    // the project's folder.
    const away = checked.folder === '~/code/shop-web';
    return {
      file: checked,
      location: away ? null : locate(checked),
      folderHere: !away && !checked.path.includes('/'),
      // shop-api's working tree doesn't ignore new files yet.
      git: away
        ? null
        : {
            state: checked.folder.includes('shop-api') ? 'untracked' : 'ignored',
            repository: expand(checked.folder),
          },
      cloud: null,
    };
  },
  envs_files_risks: async ({ id }): Promise<EnvFileReport[]> => {
    await requireUnlocked();
    seed();
    const all = await reports(null, await projects());
    return id == null ? all : all.filter((report) => report.envId === id);
  },
  envs_files_status: async (): Promise<EnvFileStatus[]> => {
    await requireUnlocked();
    return statuses();
  },
  envs_files_bind: async ({ id, file }): Promise<EnvFileStatus> => {
    await requireUnlocked();
    seed();
    const item = await findEnv(id);
    const checked = await checkFile(file as EnvFile);
    if (item.inTrash) return fail('invalid_input', 'restore the environment first');
    if (kindOf(item) === 'remote') {
      return fail('invalid_input', 'a remote environment has no files: make it local first');
    }
    if (!holds(await projects(), item.project, checked.folder)) {
      return fail('invalid_input', "the folder isn't in a project that holds the environment");
    }
    if (item.files.some((x) => x.folder === checked.folder && x.path === checked.path)) {
      return fail('already_exists', checked.path);
    }
    item.kind = 'local';
    item.files.push(checked);
    disk.set(key(item.id, checked), {
      vars: varsOf(item),
      state: checked.path.includes('/') ? 'folderMissing' : 'inSync',
      git: checked.folder.includes('shop-api')
        ? { state: 'untracked', repository: expand(checked.folder) }
        : repository(checked),
      cloud: null,
      example: null,
    });
    touchMockEnv(item);
    return statusOf(item, checked);
  },
  envs_files_unbind: async ({ id, file, deleteFile }): Promise<EnvDetail> => {
    await requireUnlocked();
    const item = await findEnv(id);
    const bound = await boundFile(item, file as EnvFile);
    const found = disk.get(key(item.id, bound));
    if (deleteFile && found && found.state !== 'inSync') {
      return fail('conflict', locate(bound));
    }
    item.files = item.files.filter((x) => x !== bound);
    disk.delete(key(item.id, bound));
    touchMockEnv(item);
    return mockEnvDetail(item);
  },
  envs_files_sync: async (): Promise<EnvFilesSynced> => {
    await requireUnlocked();
    seed();
    if (!pendingEdit) return synced([], []);
    const edit = pendingEdit;
    pendingEdit = null;
    const item = await findEnv(edit.envId);
    const change = takeFile(item, edit.file, edit.vars);
    const found = disk.get(key(item.id, edit.file));
    if (found) found.vars = edit.vars;
    const written = writeFiles(item, edit.file).map((file) => ({ item, file }));
    return synced([change], written);
  },
  envs_files_resolve: async ({ id, file, keep, seen }): Promise<EnvFilesSynced> => {
    await requireUnlocked();
    seed();
    const item = await findEnv(id);
    const bound = await boundFile(item, file as EnvFile);
    const found = disk.get(key(item.id, bound));
    if (!found) return fail('not_found', bound.path);
    if (found.vars && revisionOf(found.vars) !== seen) {
      return fail('conflict', 'the file changed since it was compared');
    }
    if ((keep as KeepSide) === 'file' && found.vars) {
      const change = takeFile(item, bound, found.vars);
      found.state = 'inSync';
      const written = writeFiles(item, bound).map((x) => ({ item, file: x }));
      return synced([change], written);
    }
    found.vars = varsOf(item);
    found.state = 'inSync';
    return synced([], [{ item, file: bound }]);
  },
  envs_files_compare: async ({ id, file }): Promise<EnvFileComparison> => {
    await requireUnlocked();
    seed();
    const item = await findEnv(id);
    const bound = await boundFile(item, file as EnvFile);
    return compare(varsOf(item), disk.get(key(item.id, bound))?.vars ?? null);
  },
  envs_files_undo: async ({ undo }): Promise<EnvDetail> => {
    await requireUnlocked();
    const { envId, after } = undo as EnvUndo;
    const item = await findEnv(envId);
    const before = undos.get(`${envId}\n${after}`);
    if (!before) return fail('conflict', 'the environment changed again since');
    undos.delete(`${envId}\n${after}`);
    item.vars = before;
    touchMockEnv(item);
    for (const file of item.files) {
      const found = disk.get(key(item.id, file));
      if (found && found.state !== 'conflict') {
        found.vars = varsOf(item);
        found.state = 'inSync';
      }
    }
    return mockEnvDetail(item);
  },
  envs_files_overview: async ({ project }): Promise<EnvFilesOverview> => {
    await requireUnlocked();
    seed();
    const all = await projects();
    const wanted = (ids: string[]) => project == null || ids.includes(String(project));
    const files = await reports(project, all);
    const unmanaged = all
      .filter((p) => wanted([p.id]))
      .flatMap((p) =>
        UNMANAGED.filter(
          (x) => p.folders.includes(x.folder) && !adopted.has(`${x.folder}\n${x.path}`),
        ).map((x) => ({
          project: p.id,
          file: { folder: x.folder, path: x.path },
          location: locate(x),
          cloud: null,
          git: { state: 'ignored' as const, repository: expand(x.folder) },
        })),
      );
    return { files, unmanaged, truncated: false };
  },
  envs_files_ignore: async ({ id, file }): Promise<GitInfo> => {
    await requireUnlocked();
    seed();
    const item = await findEnv(id);
    const bound = await boundFile(item, file as EnvFile);
    // As the backend: a folder not made yet is placed by the nearest one
    // that is; a project folder that isn't on this computer has no working
    // tree to ask; marketing-site's `.gitignore` is a link, never written.
    if (bound.folder === '~/code/shop-web') {
      return fail('invalid_input', "the file's folder isn't on this computer");
    }
    if (bound.folder.endsWith('/marketing-site')) {
      return fail('invalid_input', '.gitignore is not a regular file');
    }
    const found = disk.get(key(item.id, bound));
    const git: GitInfo = { state: 'ignored', repository: expand(bound.folder) };
    if (found) found.git = git;
    return git;
  },
  envs_files_adopt_preview: async ({ file }): Promise<EnvImportPreview> => {
    await requireUnlocked();
    const found = unmanagedFor(file as EnvFile);
    if (!found) return fail('not_found', (file as EnvFile).path);
    const { vars, problems } = parseMockDotenv(found.text);
    const name = found.path.split('/').at(-1) ?? '';
    return {
      suggestedProject: found.folder.split('/').at(-1) ?? '',
      suggestedName: name.startsWith('.env.') ? name.slice(5) : '',
      variables: vars.map(({ name: variable, value, line }) => ({
        name: variable,
        line,
        secret: mockLooksSecret(variable, value),
        empty: value === '',
        multiline: false,
      })),
      problems,
    };
  },
  envs_files_adopt: async ({ project, file, target, choices }): Promise<EnvImported> => {
    await requireUnlocked();
    seed();
    const found = unmanagedFor(file as EnvFile);
    if (!found) return fail('not_found', (file as EnvFile).path);
    const { vars } = parseMockDotenv(found.text);
    const secret = (name: string, value: string) =>
      (choices as ImportChoice[]).find((choice) => choice.name === name)?.secret ??
      mockLooksSecret(name, value);
    const to = target as ImportTarget;
    let item: Env;
    if (to.type === 'new') {
      item = addMockEnv(to.project, to.name, []);
    } else {
      item = await findEnv(to.id);
      if (kindOf(item) === 'remote') {
        return fail('invalid_input', 'a remote environment has no files: make it local first');
      }
    }
    let added = 0;
    let replaced = 0;
    for (const read of vars) {
      const known = item.vars.find((x) => x.name === read.name);
      if (known) {
        Object.assign(known, { value: read.value, secret: secret(read.name, read.value) });
        replaced += 1;
      } else {
        item.vars.push(mockVariable(read.name, read.value, secret(read.name, read.value)));
        added += 1;
      }
    }
    // The project holds the environment's group from now on.
    await projectsHandlers.projects_set_member?.({
      id: project,
      member: { type: 'environment', group: item.project },
      included: true,
    });
    const bound = { folder: found.folder, path: found.path };
    item.files.push(bound);
    adopted.add(`${found.folder}\n${found.path}`);
    disk.set(key(item.id, bound), {
      vars: varsOf(item),
      state: 'inSync',
      git: repository(bound),
      cloud: null,
      example: null,
    });
    touchMockEnv(item);
    return { id: item.id, added, replaced };
  },
};
