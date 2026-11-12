// The Environments page's model: environments by project and part,
// searching, the names a variable may have and the import's starting
// choices. No React here.

import type { EnvImportPreview } from '@/bindings/EnvImportPreview';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { ImportChoice } from '@/bindings/ImportChoice';

/** Project names by id, to show where an environment is. */
export type ProjectNames = ReadonlyMap<string, string>;

/** A project (or Personal, `null`) and its environments, part by part. */
export interface ProjectSection {
  project: string | null;
  parts: PartGroup[];
}

/** One part of a project and its stages; `part` is empty for none. */
export interface PartGroup {
  part: string;
  envs: EnvSummary[];
}

/**
 * The environments outside the recycle bin that match `query` (a project,
 * a part, a stage, or several as `shop back prod`): Personal first, then
 * the projects by name, each by part. The backend sorts the stages from
 * development to production already.
 */
export function sectionsOf(
  envs: readonly EnvSummary[],
  names: ProjectNames,
  query = '',
): ProjectSection[] {
  const sections = new Map<string, ProjectSection>();
  for (const env of envs) {
    if (env.inTrash || !matches(env, names, query)) continue;
    const key = env.project ?? '';
    let section = sections.get(key);
    if (!section) {
      section = { project: env.project, parts: [] };
      sections.set(key, section);
    }
    const part = section.parts.find((p) => same(p.part, env.part));
    if (part) part.envs.push(env);
    else section.parts.push({ part: env.part, envs: [env] });
  }
  const order = (section: ProjectSection) =>
    section.project === null ? '' : `1${(names.get(section.project) ?? '').toLowerCase()}`;
  return [...sections.values()]
    .map((section) => ({
      ...section,
      parts: [...section.parts].sort((a, b) => a.part.localeCompare(b.part)),
    }))
    .sort((a, b) => order(a).localeCompare(order(b)));
}

/** Every word of `query` is in the environment's project, part or stage. */
export function matches(env: EnvSummary, names: ProjectNames, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const project = env.project ? (names.get(env.project) ?? '') : '';
  const text = `${project} ${env.part} ${env.name}`.toLowerCase();
  return words.every((word) => text.includes(word));
}

/** The environments in the recycle bin. */
export function trashed(envs: readonly EnvSummary[]): EnvSummary[] {
  return envs.filter((env) => env.inTrash);
}

/** The parts a project (or Personal, `null`) has, for suggestions. */
export function partsOf(envs: readonly EnvSummary[], project: string | null): string[] {
  const parts: string[] = [];
  for (const env of envs) {
    if (env.inTrash || env.project !== project || env.part === '') continue;
    if (!parts.some((part) => same(part, env.part))) parts.push(env.part);
  }
  return parts;
}

/**
 * The KeePass folder a new Personal environment without a part goes into
 * (`Environments/Personal`), as the backend names it in every language.
 */
export const KEEPASS_PERSONAL = 'Personal';

/** Where an environment is: `Shop · backend`, `Shop`, `backend`, or nothing. */
export function whereLabel(project: string | null | undefined, part: string): string {
  return [project ?? '', part].filter(Boolean).join(' · ');
}

/**
 * `Shop · backend · prod`; without the part when the project has one
 * (`shown` false), as it then shows none.
 */
export function envLabel(
  env: Pick<EnvSummary, 'project' | 'part' | 'name'>,
  names: ProjectNames,
  shown = true,
): string {
  const project = env.project ? names.get(env.project) : undefined;
  return whereLabel(whereLabel(project, shown ? env.part : '') || null, env.name);
}

/** The part a project's environments share, to name when it gets a second. */
export interface FirstPart {
  /** Its name so far. */
  part: string;
  /**
   * Whether that is the name of their folder in KeePassXC (from before
   * projects, the old group's), not one given since.
   */
  fromFolder: boolean;
  /** The environments in it, those in the recycle bin too. */
  ids: string[];
  /** The parts coming, which it can't be called. */
  coming: string[];
}

/**
 * Whether environments coming into `project` (or Personal) in `parts` give
 * it a second part: it has one now, counting the ones `moving` that are in
 * it already, and more after. Then that part is named first, for every
 * environment in it but the ones moving, those in the recycle bin too, so
 * that a restore doesn't bring the old name back.
 */
export function secondPart(
  envs: readonly EnvSummary[],
  project: string | null,
  parts: readonly string[],
  moving: readonly string[] = [],
): FirstPart | null {
  const live = envs.filter((env) => !env.inTrash && env.project === project);
  const before = distinct(live.map((env) => env.part));
  const part = before[0];
  if (before.length !== 1 || part === undefined) return null;
  const staying = live.filter((env) => !moving.includes(env.id));
  const coming = distinct(parts.map((item) => item.trim()));
  const after = distinct([...staying.map((env) => env.part), ...coming]);
  if (staying.length === 0 || after.length < 2) return null;
  const kept = envs.filter(
    (env) => env.project === project && same(env.part, part) && !moving.includes(env.id),
  );
  return {
    part,
    fromFolder: part !== '' && kept.some((env) => env.part === env.group),
    ids: kept.map((env) => env.id),
    coming: coming.filter((item) => !same(item, part)),
  };
}

function distinct(parts: readonly string[]): string[] {
  const out: string[] = [];
  for (const part of parts) if (!out.some((item) => same(item, part))) out.push(part);
  return out;
}

/**
 * Names a part could have, from a project's folders: the folder that has
 * a `.env` file (`apps/backend/.env` → `backend`), without the parts it
 * has. A file at the project folder's top names none.
 */
export function folderParts(paths: readonly string[], taken: readonly string[]): string[] {
  const out: string[] = [];
  for (const path of paths) {
    const folder = path.split('/').slice(0, -1).pop();
    if (!folder || folder.startsWith('.')) continue;
    if (taken.some((part) => same(part, folder)) || out.some((part) => same(part, folder))) {
      continue;
    }
    out.push(folder);
  }
  return out;
}

/**
 * The stages of `ids` that a part `part` of `project` (or Personal) has
 * already, outside the recycle bin: renaming them into it would make two.
 */
export function stagesTaken(
  envs: readonly EnvSummary[],
  project: string | null,
  ids: readonly string[],
  part: string,
): string[] {
  const moving = envs.filter((env) => ids.includes(env.id) && !env.inTrash);
  return moving
    .filter((env) =>
      envs.some(
        (other) =>
          !other.inTrash &&
          !ids.includes(other.id) &&
          other.project === project &&
          same(other.part, part.trim()) &&
          same(other.name, env.name),
      ),
    )
    .map((env) => env.name);
}

/** The stages `env` compares with: the others of its project and part. */
export function compareWith(envs: readonly EnvSummary[], env: EnvSummary): EnvSummary[] {
  return envs.filter(
    (other) =>
      !other.inTrash &&
      other.id !== env.id &&
      other.project === env.project &&
      same(other.part, env.part),
  );
}

/** Whether a project (or Personal) has more than one part: only then are parts shown. */
export function showsParts(envs: readonly EnvSummary[], project: string | null): boolean {
  const parts = new Set(
    envs
      .filter((env) => !env.inTrash && env.project === project)
      .map((env) => env.part.toLowerCase()),
  );
  return parts.size > 1;
}

function same(a: string, b: string): boolean {
  return a.toLowerCase() === b.toLowerCase();
}

/** Production environments get a warning colour, so they are hard to mistake. */
export function isProduction(name: string): boolean {
  return /^(prod|production|live)$/i.test(name.trim());
}

/** Letters, digits and `_`, not starting with a digit: as a shell takes it. */
export function isVariableName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name) && name.length <= 255;
}

/** What a project's or an environment's name may be (the backend checks the same). */
export function labelProblem(text: string): 'empty' | 'slash' | 'long' | null {
  const trimmed = text.trim();
  if (trimmed === '') return 'empty';
  if (trimmed.includes('/')) return 'slash';
  if ([...trimmed].length > 64) return 'long';
  return null;
}

/** An import starts with every variable taken, secret where it looks secret. */
export function initialChoices(preview: EnvImportPreview): ImportChoice[] {
  return preview.variables.map((variable) => ({ name: variable.name, secret: variable.secret }));
}

/**
 * Whether `project` (or Personal, `null`) has the stage `name` in `part`
 * (ignoring case) outside the recycle bin, other than `except`; the backend
 * refuses it too.
 */
export function nameTaken(
  envs: readonly EnvSummary[],
  project: string | null,
  part: string,
  name: string,
  except?: string,
): boolean {
  return envs.some(
    (env) =>
      !env.inTrash &&
      env.id !== except &&
      env.project === project &&
      same(env.part, part.trim()) &&
      same(env.name, name.trim()),
  );
}

/**
 * Whether a name says the variable is a secret, as the backend's import
 * guesses (`*_KEY`, `*_SECRET`, `*_TOKEN`, `*PASSWORD*`, `DATABASE_URL`…):
 * a new variable starts secret then, until the user says otherwise.
 */
export function looksSecretName(name: string): boolean {
  const upper = name.toUpperCase();
  if (upper.includes('PUBLIC') || upper.includes('PUBLISHABLE')) return false;
  if (['KEY', 'SECRET', 'TOKEN', 'PASSWORD'].includes(upper)) return true;
  if (upper.endsWith('_URL')) return upper.endsWith('DATABASE_URL');
  return (
    /_(KEY|SECRET|TOKEN|PASS|PWD|DSN)$/.test(upper) ||
    /PASSWORD|PASSWD|SECRET_|PRIVATE_KEY|CREDENTIALS/.test(upper)
  );
}
