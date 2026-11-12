import type { TFunction } from 'i18next';
import { describe, expect, it } from 'vitest';
import type { EnvFileChange } from '@/bindings/EnvFileChange';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { FileState } from '@/bindings/FileState';
import { changeSummary } from './announce';
import {
  bindingPath,
  fileName,
  matchesFilter,
  needsAction,
  needsAttention,
  stateLabel,
  stateText,
} from './model';

/** Echoes the key and its values, as a stand-in for i18next. */
const t = ((key: string, values?: Record<string, unknown>) =>
  values ? `${key} ${JSON.stringify(values)}` : key) as unknown as TFunction;

function report(state: FileState, extra: Partial<EnvFileReport> = {}): EnvFileReport {
  return {
    envId: 'env-1',
    label: 'shop-api',
    envName: 'dev',
    file: { folder: '~/code/shop', path: 'apps/web/.env.local' },
    level: 'always',
    location: '/Users/dev/code/shop/apps/web/.env.local',
    state,
    projects: ['p1'],
    cloud: null,
    example: null,
    git: null,
    ...extra,
  };
}

describe('managed files model', () => {
  it('names files by their binding', () => {
    const file = { folder: '~/code/shop/', path: 'apps/web/.env.local' };
    expect(bindingPath(file)).toBe('~/code/shop/apps/web/.env.local');
    expect(bindingPath({ folder: 'C:\\code\\shop', path: '.env' })).toBe('C:\\code\\shop\\.env');
    expect(fileName(file)).toBe('.env.local');
  });

  it('says what each state is, without values', () => {
    expect(stateLabel(t, { type: 'inSync' })).toBe('envs.files.state.inSync');
    expect(stateLabel(t, { type: 'inactive', reason: 'remote' })).toBe(
      'envs.files.state.inactive.remote',
    );
    expect(stateLabel(t, { type: 'refused', reason: 'link' })).toBe(
      'envs.files.state.refused.link',
    );
    const invalid: FileState = {
      type: 'invalid',
      problems: [
        { line: 3, kind: 'unterminated', name: null },
        { line: 7, kind: 'noEquals', name: null },
      ],
    };
    expect(stateText(t, invalid)).toBe('envs.files.explain.invalid {"count":2,"lines":"3, 7"}');
    // The backend's English message goes to `title`; the text is localized.
    expect(stateText(t, { type: 'failed', message: 'disk full' })).toBe(
      'envs.files.explain.failed',
    );
    expect(stateText(t, { type: 'inactive', reason: 'notInProject' })).toBe(
      'envs.files.explain.inactive.notInProject',
    );
    expect(stateText(t, { type: 'refused', reason: 'protected' })).toBe(
      'envs.files.explain.refused.protected',
    );
  });

  it('asks for the user only where something needs them', () => {
    expect(needsAction({ type: 'inSync' })).toBe(false);
    expect(needsAction({ type: 'folderMissing' })).toBe(false);
    expect(needsAction({ type: 'inactive', reason: 'inTrash' })).toBe(false);
    expect(needsAction({ type: 'inactive', reason: 'notInProject' })).toBe(true);
    expect(needsAction({ type: 'conflict' })).toBe(true);
    expect(needsAction({ type: 'missing' })).toBe(true);

    const calm = report({ type: 'inSync' }, { git: { state: 'ignored', repository: '/r' } });
    expect(needsAttention(calm)).toBe(false);
    const untracked = report({ type: 'inSync' }, { git: { state: 'untracked', repository: '/r' } });
    expect(needsAttention(untracked)).toBe(true);
    expect(matchesFilter(untracked, 'git')).toBe(true);
    expect(matchesFilter(untracked, 'cloud')).toBe(false);
    const cloudy = report({ type: 'inSync' }, { cloud: 'dropbox' });
    expect(matchesFilter(cloudy, 'cloud')).toBe(true);
    const lacking = report(
      { type: 'inSync' },
      { example: { file: '.env.example', missing: ['SENTRY_DSN'] } },
    );
    expect(matchesFilter(lacking, 'example')).toBe(true);
    expect(matchesFilter(calm, 'all')).toBe(true);
    expect(matchesFilter(calm, 'attention')).toBe(false);
  });

  it('sums up an edit by names, a few at a time', () => {
    const change: EnvFileChange = {
      envId: 'env-1',
      label: 'shop-api',
      envName: 'dev',
      file: { folder: '~/code/shop', path: '.env' },
      added: ['A', 'B', 'C', 'D', 'E'],
      changed: ['PORT'],
      removed: [],
      undo: { envId: 'env-1', before: 'x', after: 'y' },
    };
    expect(changeSummary(t, change)).toBe(
      'envs.files.savedChanged {"names":"PORT"} · envs.files.savedAdded {"names":"A, B, C, D, …"}',
    );
  });
});
