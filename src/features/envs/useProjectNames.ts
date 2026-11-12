import { useCallback, useMemo } from 'react';
import type { EnvSummary } from '@/bindings/EnvSummary';
import { useProjects } from '@/features/projects/queries';
import { envLabel, type ProjectNames, showsParts } from './model';
import { useEnvs } from './queries';

/** The projects' names by id, to say where environments are. */
export function useProjectNames(): ProjectNames {
  const projects = useProjects().data;
  return useMemo(
    () => new Map((projects ?? []).map((project) => [project.id, project.name])),
    [projects],
  );
}

/**
 * `Shop · backend · prod`: an environment's label with where it is, its
 * part only when its project has more than one.
 */
export function useEnvLabel(): (env: Pick<EnvSummary, 'project' | 'part' | 'name'>) => string {
  const names = useProjectNames();
  const envs = useEnvs().data;
  return useCallback(
    (env) => envLabel(env, names, showsParts(envs ?? [], env.project)),
    [names, envs],
  );
}
