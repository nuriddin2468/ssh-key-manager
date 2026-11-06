import { describe, expect, it } from 'vitest';
import type { EnvSummary } from '@/bindings/EnvSummary';
import {
  envLabel,
  groupByProject,
  initialChoices,
  isProduction,
  isVariableName,
  labelProblem,
  looksSecretName,
  nameTaken,
  projects,
  trashed,
} from './model';

function env(id: string, project: string, name: string, inTrash = false): EnvSummary {
  return {
    id,
    project,
    name,
    variableCount: 2,
    secretCount: 1,
    inTrash,
    modified: null,
  };
}

const ALL = [
  env('1', 'shop-api', 'dev'),
  env('2', 'shop-api', 'prod'),
  env('3', 'site', 'dev'),
  env('4', 'shop-api', 'old', true),
];

describe('envs model', () => {
  it('groups environments by project, leaving the recycle bin out', () => {
    expect(groupByProject(ALL).map((g) => [g.project, g.envs.map((e) => e.id)])).toEqual([
      ['shop-api', ['1', '2']],
      ['site', ['3']],
    ]);
    expect(trashed(ALL).map((e) => e.id)).toEqual(['4']);
    expect(projects(ALL)).toEqual(['shop-api', 'site']);
  });

  it('searches projects and environments by every word', () => {
    expect(groupByProject(ALL, 'SHOP prod').flatMap((g) => g.envs.map((e) => e.id))).toEqual(['2']);
    expect(groupByProject(ALL, 'dev').flatMap((g) => g.envs.map((e) => e.id))).toEqual(['1', '3']);
    expect(groupByProject(ALL, 'nothing')).toEqual([]);
  });

  it('checks names as the backend does', () => {
    for (const name of ['PORT', '_x', 'a1_B']) expect(isVariableName(name)).toBe(true);
    for (const name of ['', '1A', 'A-B', 'A B', 'é']) expect(isVariableName(name)).toBe(false);
    expect(labelProblem('  ')).toBe('empty');
    expect(labelProblem('a/b')).toBe('slash');
    expect(labelProblem('x'.repeat(65))).toBe('long');
    expect(labelProblem(' dev ')).toBe(null);
    expect(nameTaken(ALL, 'shop-api', ' DEV ')).toBe(true);
    expect(nameTaken(ALL, 'shop-api', 'dev', '1')).toBe(false);
    // One in the recycle bin doesn't hold its name.
    expect(nameTaken(ALL, 'shop-api', 'old')).toBe(false);
    expect(nameTaken(ALL, 'site', 'prod')).toBe(false);
  });

  it('guesses secrets from names', () => {
    for (const name of ['API_KEY', 'DB_PASSWORD', 'DATABASE_URL', 'JWT_SECRET', 'GH_TOKEN']) {
      expect(looksSecretName(name), name).toBe(true);
    }
    for (const name of ['PORT', 'API_URL', 'NEXT_PUBLIC_API_KEY', 'AWS_ACCESS_KEY_ID']) {
      expect(looksSecretName(name), name).toBe(false);
    }
  });

  it('labels environments', () => {
    expect(envLabel(ALL[1] as EnvSummary)).toBe('shop-api / prod');
    expect(isProduction(' Production ')).toBe(true);
    expect(isProduction('preprod')).toBe(false);
    expect(
      initialChoices({
        suggestedProject: '',
        suggestedName: '',
        variables: [{ name: 'A', line: 1, secret: true, empty: false, multiline: false }],
        problems: [],
      }),
    ).toEqual([{ name: 'A', secret: true }]);
  });
});
