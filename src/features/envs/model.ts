// The Environments page's model: grouping by project, searching, the names
// a variable may have and the import's starting choices. No React here.

import type { EnvImportPreview } from '@/bindings/EnvImportPreview';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { ImportChoice } from '@/bindings/ImportChoice';

/** A project and its environments, in the backend's order. */
export interface ProjectGroup {
  project: string;
  envs: EnvSummary[];
}

/**
 * The environments outside the recycle bin that match `query` (a project,
 * an environment's name, or both as `project dev`), grouped by project. The
 * backend sorts them already: by project, then from development to
 * production.
 */
export function groupByProject(envs: readonly EnvSummary[], query = ''): ProjectGroup[] {
  const groups: ProjectGroup[] = [];
  for (const env of envs) {
    if (env.inTrash || !matches(env, query)) continue;
    const last = groups.at(-1);
    if (last && last.project === env.project) last.envs.push(env);
    else groups.push({ project: env.project, envs: [env] });
  }
  return groups;
}

/** Every word of `query` is in the project's or the environment's name. */
export function matches(env: EnvSummary, query: string): boolean {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  const text = `${env.project} ${env.name}`.toLowerCase();
  return words.every((word) => text.includes(word));
}

/** The environments in the recycle bin. */
export function trashed(envs: readonly EnvSummary[]): EnvSummary[] {
  return envs.filter((env) => env.inTrash);
}

/** The projects there are, for suggestions. */
export function projects(envs: readonly EnvSummary[]): string[] {
  return [...new Set(envs.filter((env) => !env.inTrash).map((env) => env.project))];
}

/** `shop-api / prod`. */
export function envLabel(env: Pick<EnvSummary, 'project' | 'name'>): string {
  return `${env.project} / ${env.name}`;
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
 * Whether `project` has an environment named `name` (ignoring case) outside
 * the recycle bin, other than `except`; the backend refuses it too.
 */
export function nameTaken(
  envs: readonly EnvSummary[],
  project: string,
  name: string,
  except?: string,
): boolean {
  const wanted = name.trim().toLowerCase();
  return envs.some(
    (env) =>
      !env.inTrash &&
      env.id !== except &&
      env.project === project.trim() &&
      env.name.toLowerCase() === wanted,
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
