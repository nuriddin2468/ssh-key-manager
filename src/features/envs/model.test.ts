import { describe, expect, it } from 'vitest';
import type { EnvSummary } from '@/bindings/EnvSummary';
import {
  envLabel,
  folderParts,
  initialChoices,
  isProduction,
  isVariableName,
  labelProblem,
  looksSecretName,
  nameTaken,
  partsOf,
  secondPart,
  sectionsOf,
  showsParts,
  trashed,
} from './model';

function env(
  id: string,
  project: string | null,
  part: string,
  name: string,
  inTrash = false,
): EnvSummary {
  return {
    id,
    project,
    part,
    group: part,
    name,
    kind: name === 'dev' ? 'local' : 'remote',
    variableCount: 2,
    secretCount: 1,
    inTrash,
    modified: null,
  };
}

const NAMES = new Map([
  ['p-shop', 'Shop'],
  ['p-blog', 'Blog'],
]);

const ALL = [
  env('1', 'p-shop', 'backend', 'dev'),
  env('2', 'p-shop', 'backend', 'prod'),
  env('5', 'p-shop', 'frontend', 'dev'),
  env('3', 'p-blog', '', 'dev'),
  env('6', null, 'scripts', 'local'),
  env('4', 'p-shop', 'backend', 'old', true),
];

const ids = (sections: ReturnType<typeof sectionsOf>) =>
  sections.flatMap((s) => s.parts.flatMap((p) => p.envs.map((e) => e.id)));

describe('envs model', () => {
  it('lists Personal first, then projects by name, each by part, leaving the recycle bin out', () => {
    const sections = sectionsOf(ALL, NAMES);
    expect(sections.map((s) => [s.project, s.parts.map((p) => p.part)])).toEqual([
      [null, ['scripts']],
      ['p-blog', ['']],
      ['p-shop', ['backend', 'frontend']],
    ]);
    expect(ids(sections)).toEqual(['6', '3', '1', '2', '5']);
    expect(trashed(ALL).map((e) => e.id)).toEqual(['4']);
    expect(partsOf(ALL, 'p-shop')).toEqual(['backend', 'frontend']);
    expect(partsOf(ALL, 'p-blog')).toEqual([]);
  });

  it('searches projects, parts and stages by every word', () => {
    expect(ids(sectionsOf(ALL, NAMES, 'SHOP back prod'))).toEqual(['2']);
    expect(ids(sectionsOf(ALL, NAMES, 'dev'))).toEqual(['3', '1', '5']);
    expect(sectionsOf(ALL, NAMES, 'nothing')).toEqual([]);
  });

  it('checks names as the backend does', () => {
    for (const name of ['PORT', '_x', 'a1_B']) expect(isVariableName(name)).toBe(true);
    for (const name of ['', '1A', 'A-B', 'A B', 'é']) expect(isVariableName(name)).toBe(false);
    expect(labelProblem('  ')).toBe('empty');
    expect(labelProblem('a/b')).toBe('slash');
    expect(labelProblem('x'.repeat(65))).toBe('long');
    expect(labelProblem(' dev ')).toBe(null);
    expect(nameTaken(ALL, 'p-shop', 'Backend', ' DEV ')).toBe(true);
    expect(nameTaken(ALL, 'p-shop', 'backend', 'dev', '1')).toBe(false);
    // Another part, project or Personal may have it.
    expect(nameTaken(ALL, 'p-shop', 'web', 'dev')).toBe(false);
    expect(nameTaken(ALL, null, 'backend', 'dev')).toBe(false);
    // One in the recycle bin doesn't hold its name.
    expect(nameTaken(ALL, 'p-shop', 'backend', 'old')).toBe(false);
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
    expect(envLabel(ALL[1] as EnvSummary, NAMES)).toBe('Shop · backend · prod');
    expect(envLabel(ALL[3] as EnvSummary, NAMES)).toBe('Blog · dev');
    expect(envLabel(ALL[4] as EnvSummary, NAMES)).toBe('scripts · local');
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

describe('a project’s parts', () => {
  it('ask for a name when a project with one part gets a second', () => {
    // Blog has one part (none); Shop has two already.
    expect(secondPart(ALL, 'p-blog', 'web')).toEqual({ part: '', ids: ['3'] });
    expect(secondPart(ALL, 'p-blog', '')).toBeNull();
    expect(secondPart(ALL, 'p-shop', 'admin')).toBeNull();
    // Moving its only environment leaves nothing to name.
    expect(secondPart(ALL, 'p-blog', 'web', '3')).toBeNull();
    expect(secondPart(ALL, null, 'tools')).toEqual({ part: 'scripts', ids: ['6'] });
  });

  it('are offered from the project’s folders, without those it has', () => {
    expect(
      folderParts(
        ['.env', 'backend/.env', 'frontend/.env.local', 'backend/api/.env', '.config/.env'],
        ['Frontend'],
      ),
    ).toEqual(['backend']);
  });

  it('show only when a project has more than one', () => {
    expect(showsParts(ALL, 'p-shop')).toBe(true);
    expect(showsParts(ALL, 'p-blog')).toBe(false);
    expect(envLabel(ALL[0] as EnvSummary, NAMES, false)).toBe('Shop · dev');
  });
});
