import type { TFunction } from 'i18next';
import { describe, expect, it } from 'vitest';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { EnvFileStatus } from '@/bindings/EnvFileStatus';
import type { FileState } from '@/bindings/FileState';
import { fileLine } from './FileStateLine';

const t = ((key: string, values?: Record<string, unknown>) =>
  values ? `${key} ${JSON.stringify(values)}` : key) as unknown as TFunction;

function status(path: string, state: FileState, envId = 'env-1'): EnvFileStatus {
  return {
    envId,
    group: 'shop-api',
    envName: 'dev',
    file: { folder: '~/code/shop', path },
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

  it('says when files sync or their folder is away', () => {
    expect(fileLine(t, 'env-1', [status('.env', { type: 'fileChanged' })], [])?.text).toBe(
      'envs.files.line.syncing',
    );
    expect(fileLine(t, 'env-1', [status('.env', { type: 'folderMissing' })], [])?.text).toBe(
      'envs.files.line.away',
    );
  });
});
