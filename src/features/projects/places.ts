// Where a project's parts work (src-tauri `projects_places`): the folder
// tree on the project page, the folder of an environment, and the folders a
// part may be given.

import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import type { EnvFilesOverview } from '@/bindings/EnvFilesOverview';
import type { FolderPlace } from '@/bindings/FolderPlace';
import type { PartFolderChoice } from '@/bindings/PartFolderChoice';
import type { PartPlace } from '@/bindings/PartPlace';
import type { ProjectFolder } from '@/bindings/ProjectFolder';
import { projectKeys } from './queries';

/**
 * The project's places: each of its folders, then the folders in it where
 * parts work. Keyed by the vault's state: while locked only the folders set
 * for parts are known, without environments.
 */
export function usePlaces(project: string | null | undefined) {
  const state = useVaultStatus().data?.state;
  return useQuery({
    queryKey: [...projectKeys.all, 'places', project ?? '', state ?? 'unknown'],
    queryFn: () => api.projectsPlaces(project ?? ''),
    enabled: Boolean(project) && state !== undefined,
    // Each look checks the folders on disk: not on every focus.
    staleTime: 30_000,
    refetchOnWindowFocus: false,
  });
}

/** `~/code/shop` → `shop`. */
export function lastName(path: string): string {
  return path.split(/[\\/]/).filter(Boolean).pop() ?? path;
}

/** The text a place shows: a folder as the project keeps it, or the path in it. */
export function placeText(place: ProjectFolder, folders: readonly string[]): string {
  if (!place.path) return place.folder;
  // With several folders, which one: `shop-api/apps/api`.
  return folders.length > 1 ? `${lastName(place.folder)}/${place.path}` : place.path;
}

/**
 * Where an environment works, as its row says it: the folder in the
 * project's (`apps/web`); in a project folder itself, which one, when
 * there are several (`shop-web`); else nothing.
 */
export function envFolderText(place: ProjectFolder, folders: readonly string[]): string | null {
  if (place.path) return placeText(place, folders);
  return folders.length > 1 ? lastName(place.folder) : null;
}

export const placeKey = (place: ProjectFolder): string => `${place.folder}\n${place.path}`;

export const samePlace = (a: ProjectFolder, b: ProjectFolder): boolean =>
  a.folder === b.folder && a.path === b.path;

/** Where the environment `env` works: its place and its part there. */
export function placeOfEnv(
  places: readonly FolderPlace[] | undefined,
  env: string,
): { place: FolderPlace; part: PartPlace } | undefined {
  for (const place of places ?? []) {
    const part = place.parts.find((item) => item.environments.includes(env));
    if (part) return { place, part };
  }
  return undefined;
}

/** A part of the project by its name, compared as parts are (without case). */
export function placeOfPart(
  places: readonly FolderPlace[] | undefined,
  part: string,
): { place: FolderPlace; part: PartPlace } | undefined {
  const name = part.trim().toLowerCase();
  for (const place of places ?? []) {
    const found = place.parts.find((item) => item.part.toLowerCase() === name);
    if (found) return { place, part: found };
  }
  return undefined;
}

/** The folder a file of a project's folder is in. */
export function fileFolder(file: { folder: string; path: string }): ProjectFolder {
  const at = file.path.lastIndexOf('/');
  return { folder: file.folder, path: at < 0 ? '' : file.path.slice(0, at) };
}

/** Why a folder is offered, for its hint. */
export type FolderHint = 'automatic' | 'current' | 'files' | 'project' | 'picked';

export interface FolderOption {
  /** `auto`, or [`placeKey`]. */
  value: string;
  /** `null` for automatic. */
  place: ProjectFolder | null;
  hint: FolderHint;
}

/** Most folders with `.env` files offered, besides the part's own. */
const MAX_FOUND = 8;

/**
 * The folders a part may get, in order: automatic, the folder set for it,
 * the folders its environments' files are in, other folders of the project
 * with `.env` files, the project's folders, and one the user picked.
 */
export function folderOptions({
  part,
  folders,
  overview,
  picked,
}: {
  /** The part, if it exists. */
  part: { place: FolderPlace; part: PartPlace } | undefined;
  folders: readonly string[];
  /** The project's `.env` files, managed and not. */
  overview?: EnvFilesOverview;
  picked?: ProjectFolder | null;
}): FolderOption[] {
  const out: FolderOption[] = [{ value: 'auto', place: null, hint: 'automatic' }];
  const add = (place: ProjectFolder, hint: FolderHint) => {
    if (!folders.includes(place.folder)) return;
    const value = placeKey(place);
    if (!out.some((option) => option.value === value)) out.push({ value, place, hint });
  };
  if (part?.part.source === 'set') add(part.place, 'current');
  for (const place of part?.part.suggested ?? []) add(place, 'files');
  const found = [
    ...(overview?.files ?? []).map((report) => fileFolder(report.file)),
    ...(overview?.unmanaged ?? []).map((item) => fileFolder(item.file)),
  ];
  let count = 0;
  for (const place of found) {
    if (count >= MAX_FOUND) break;
    const before = out.length;
    add(place, 'files');
    if (out.length > before) count += 1;
  }
  for (const folder of folders) add({ folder, path: '' }, 'project');
  if (picked) add(picked, 'picked');
  return out;
}

/** The option a part starts on: its folder when the user set one, else automatic. */
export function startOption(part: { place: FolderPlace; part: PartPlace } | undefined): string {
  return part?.part.source === 'set' ? placeKey(part.place) : 'auto';
}

/** What saving the option `value` changes: `null` when it is where the part starts. */
export function folderChange(
  options: readonly FolderOption[],
  value: string,
  start: string,
): PartFolderChoice | null {
  if (value === start) return null;
  const place = options.find((option) => option.value === value)?.place;
  return place ? { type: 'folder', folder: place.folder, path: place.path } : { type: 'automatic' };
}

/** Where automatic leads a new part: the project's first folder. */
export function automaticOf(
  part: { place: FolderPlace; part: PartPlace } | undefined,
  folders: readonly string[],
): { place: ProjectFolder | null; fromFile: boolean } {
  if (part) return { place: part.part.automatic, fromFile: part.part.automaticFromFile };
  const first = folders[0];
  return { place: first === undefined ? null : { folder: first, path: '' }, fromFile: false };
}

/** The `.env` files found in `place` that no environment is written to. */
export function unmanagedIn(
  overview: EnvFilesOverview | undefined,
  place: ProjectFolder | null,
): EnvFilesOverview['unmanaged'] {
  if (!place) return [];
  return (overview?.unmanaged ?? []).filter((item) => samePlace(fileFolder(item.file), place));
}

/**
 * Of the unmanaged files in a folder, the one a new local stage would use:
 * only a file for local use (`.env`, `.env.local`, `.env.development…`, or
 * named for the stage), never another stage's (`.env.production`,
 * `.env.production.local`). The stage's own first, then `.env.local`, then
 * the rest, `.env` last.
 */
export function fileForStage<T extends { file: { path: string } }>(
  files: readonly T[],
  stage: string,
): T | undefined {
  const name = stage.trim().toLowerCase();
  const own = name === 'dev' ? ['dev', 'development'] : [name];
  const allowed = new Set(['local', 'dev', 'development', ...own]);
  const words = (item: T) =>
    lastName(item.file.path)
      .toLowerCase()
      .split('.')
      .filter((word) => word !== '' && word !== 'env');
  const fits = files.filter((item) => words(item).every((word) => allowed.has(word)));
  return (
    fits.find((item) => words(item).some((word) => own.includes(word))) ??
    fits.find((item) => words(item).join('.') === 'local') ??
    fits.find((item) => words(item).length > 0) ??
    fits[0]
  );
}
