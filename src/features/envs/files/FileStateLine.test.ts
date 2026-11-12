import type { TFunction } from 'i18next';
import { describe, expect, it } from 'vitest';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { EnvFileStatus } from '@/bindings/EnvFileStatus';
import type { FileState } from '@/bindings/FileState';
import { fileLine } from './FileStateLine';
import { projectFilesNeedingAttention } from './model';

const t = ((key: string, values?: Record<string, unknown>) =>
  values ? `${key} ${JSON.stringify(values)}` : key) as unknown as TFunction;

function status(path: string, state: FileState, envId = 'env-1'): EnvFileStatus {
  return {
    envId,
    label: 'shop-api',
    envName: 'dev',
    file: { folder: '~/code/shop', path },
    level: 'always',
    location: `/code/shop/${path}`,
    state,
  };
}

const report = (from: EnvFileStatus, extra: Partial<EnvFileReport>): EnvFileReport => ({
  ...from,
  projects: [],
  cloud: null,
  example: null,
  git: null,
  ...extra,
});

describe('the file-state line', () => {
  it('says nothing for an environment without files', () => {
    expect(fileLine(t, 'env-1', [status('.env', { type: 'inSync' }, 'env-2')], [])).toBe(null);
    expect(fileLine(t, 'env-1', undefined, undefined)).toBe(null);
  });

  it('counts files in sync, and what needs the user first', () => {
    const synced = [status('.env', { type: 'inSync' }), status('.env.local', { type: 'inSync' })];
    expect(fileLine(t, 'env-1', synced, [])).toEqual({
      text: 'envs.files.line.inSync {"count":2}',
      tone: 'ok',
      attention: false,
    });
    const conflict = [...synced, status('apps/.env', { type: 'conflict' })];
    expect(fileLine(t, 'env-1', conflict, [])).toEqual({
      text: 'envs.files.line.attention {"count":1}',
      tone: 'warning',
      attention: true,
    });
  });

  it('counts Git and cloud folders as needing attention, as the Files view does', () => {
    const synced = status('.env', { type: 'inSync' });
    const untracked = report(synced, { git: { state: 'untracked', repository: '/code/shop' } });
    expect(fileLine(t, 'env-1', [synced], [untracked])?.attention).toBe(true);
    const ignored = report(synced, { git: { state: 'ignored', repository: '/code/shop' } });
    expect(fileLine(t, 'env-1', [synced], [ignored])?.attention).toBe(false);
  });

  it('doesn’t say all clear while Git and cloud folders are unknown', () => {
    const synced = [status('.env', { type: 'inSync' })];
    expect(fileLine(t, 'env-1', synced, undefined)).toEqual({
      text: 'envs.files.line.inSync {"count":1}',
      tone: 'neutral',
      attention: false,
    });
    expect(fileLine(t, 'env-1', [status('.env', { type: 'conflict' })], undefined)?.attention).toBe(
      true,
    );
  });

  it('says when files sync or their folder is away', () => {
    expect(fileLine(t, 'env-1', [status('.env', { type: 'fileChanged' })], [])?.text).toBe(
      'envs.files.line.syncing',
    );
    expect(fileLine(t, 'env-1', [status('.env', { type: 'folderMissing' })], [])?.text).toBe(
      'envs.files.line.away',
    );
  });
});

describe('a project’s files that need the user', () => {
  const synced = status('.env', { type: 'inSync' });
  const worker = status('apps/worker/.env', { type: 'inSync' });
  const shop = (from: EnvFileStatus, extra: Partial<EnvFileReport> = {}) =>
    report(from, { projects: ['p1'], ...extra });

  it('takes the files whose folder the project holds', () => {
    const reports = [
      shop(synced, { cloud: 'dropbox' }),
      report(worker, { projects: ['p2'], cloud: 'dropbox' }),
    ];
    expect(projectFilesNeedingAttention('p1', [synced, worker], reports)).toHaveLength(1);
    expect(projectFilesNeedingAttention('p2', [synced, worker], reports)).toHaveLength(1);
    expect(projectFilesNeedingAttention('p3', [synced, worker], reports)).toEqual([]);
  });

  it('goes by each file’s state now, and drops files no longer written', () => {
    // The report is older: the file came into conflict since.
    const reports = [shop(synced), shop(worker)];
    const now = [status('.env', { type: 'conflict' }), worker];
    expect(projectFilesNeedingAttention('p1', now, reports).map((r) => r.file.path)).toEqual([
      '.env',
    ]);
    // Settled since the report said so.
    const settled = [shop(status('.env', { type: 'conflict' }))];
    expect(projectFilesNeedingAttention('p1', [synced], settled)).toEqual([]);
    // Unbound since: no state for it.
    expect(projectFilesNeedingAttention('p1', [], settled)).toEqual([]);
    // States not known yet: the reports alone.
    expect(projectFilesNeedingAttention('p1', undefined, settled)).toHaveLength(1);
  });
});
