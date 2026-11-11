import type { TFunction } from 'i18next';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { EnvFileChange } from '@/bindings/EnvFileChange';
import type { EnvFileStatus } from '@/bindings/EnvFileStatus';
import type { EnvFilesSynced } from '@/bindings/EnvFilesSynced';

const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }));
const envsFilesUndo = vi.hoisted(() => vi.fn());
vi.mock('sonner', () => ({ toast }));
vi.mock('@/api/commands', () => ({ api: { envsFilesUndo } }));
vi.mock('@/api/queries', () => ({
  invalidateAll: vi.fn(() => Promise.resolve()),
  queryClient: { invalidateQueries: vi.fn() },
}));

const { announceSynced, markConflictTold, SAME_ROUND_MS, undoChange } = await import('./announce');
const { bindRefusal, isEnvNameClash, isFileConflict, isVaultConflict } = await import('./errors');

const t = ((key: string, values?: Record<string, unknown>) =>
  values ? `${key} ${JSON.stringify(values)}` : key) as unknown as TFunction;
const navigate = vi.fn();

function change(after: string): EnvFileChange {
  return {
    envId: 'env-1',
    group: 'shop-api',
    envName: 'dev',
    file: { folder: '~/code/shop', path: '.env' },
    added: ['DEBUG'],
    changed: [],
    removed: [],
    undo: { envId: 'env-1', before: 'rev-0', after },
  };
}

function conflict(path: string): EnvFileStatus {
  return {
    envId: 'env-1',
    group: 'shop-api',
    envName: 'dev',
    file: { folder: '~/code/shop', path },
    location: null,
    state: { type: 'conflict' },
  };
}

const round = (changes: EnvFileChange[], files: EnvFileStatus[] = []): EnvFilesSynced => ({
  changes,
  written: [],
  files,
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('announcing rounds', () => {
  it('tells of each edit once, however many times it arrives', () => {
    // The event and the command's own result carry the same round.
    const synced = round([change('rev-a')]);
    announceSynced(t, synced, navigate);
    announceSynced(t, synced, navigate);
    expect(toast.success).toHaveBeenCalledTimes(1);
    const [, options] = toast.success.mock.calls[0] ?? [];
    expect(options.id).toBe('env-file-edit:rev-a');
    announceSynced(t, round([change('rev-b')]), navigate);
    expect(toast.success).toHaveBeenCalledTimes(2);
  });

  it('tells again of a later edit that lands on the same values', () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(new Date('2026-11-11T10:00:00Z'));
      const synced = round([change('rev-same')]);
      announceSynced(t, synced, navigate);
      vi.setSystemTime(new Date(Date.now() + SAME_ROUND_MS / 2));
      announceSynced(t, synced, navigate);
      expect(toast.success).toHaveBeenCalledTimes(1);
      // Minutes later the user changed it back and forth: a new edit.
      vi.setSystemTime(new Date(Date.now() + 3 * SAME_ROUND_MS));
      announceSynced(t, synced, navigate);
      expect(toast.success).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('tells of a conflict once while it lasts, and not after a dialog did', () => {
    const files = [conflict('apps/api/.env')];
    announceSynced(t, round([], files), navigate);
    announceSynced(t, round([], files), navigate);
    expect(toast.warning).toHaveBeenCalledTimes(1);
    // Settled, then back: told again.
    announceSynced(t, round([], []), navigate);
    announceSynced(t, round([], files), navigate);
    expect(toast.warning).toHaveBeenCalledTimes(2);
    // The bind dialog told of this one itself.
    markConflictTold('env-1', { folder: '~/code/shop', path: '.env.local' });
    announceSynced(t, round([], [...files, conflict('.env.local')]), navigate);
    expect(toast.warning).toHaveBeenCalledTimes(2);
  });

  it('undoes with the revisions the edit came with, and says why it can’t', async () => {
    envsFilesUndo.mockResolvedValueOnce({});
    await undoChange(t, change('rev-c'));
    expect(envsFilesUndo).toHaveBeenCalledWith({ envId: 'env-1', before: 'rev-0', after: 'rev-c' });
    expect(toast.success).toHaveBeenCalledWith('envs.files.undone {"env":"shop-api / dev"}');

    envsFilesUndo.mockRejectedValueOnce({
      code: 'conflict',
      message: 'the environment changed again since',
    });
    await undoChange(t, change('rev-d'));
    expect(toast.error).toHaveBeenLastCalledWith(
      'envs.files.errors.undoChanged {"env":"shop-api / dev"}',
    );

    envsFilesUndo.mockRejectedValueOnce({
      code: 'not_found',
      message: "the earlier version isn't in the entry's history",
    });
    await undoChange(t, change('rev-e'));
    expect(toast.error).toHaveBeenLastCalledWith('envs.files.errors.undoGone');
  });
});

describe('telling file errors from the vault’s', () => {
  it('leaves the vault’s own conflicts to the vault', () => {
    const copy = {
      code: 'conflict',
      message: 'the vault changed on disk: /backups/vault-conflict-1.kdbx',
    };
    expect(isVaultConflict(copy)).toBe(true);
    expect(isFileConflict(copy)).toBe(false);
    expect(isVaultConflict({ code: 'conflict', message: '/sync/vault.keys' })).toBe(true);
    const file = { code: 'conflict', message: 'the file changed since it was compared' };
    expect(isFileConflict(file)).toBe(true);
    expect(isFileConflict({ code: 'not_found', message: 'x' })).toBe(false);
  });

  it('says why a binding was refused', () => {
    const refusal = (code: string, message: string) => bindRefusal(t, { code, message });
    expect(
      refusal(
        'invalid_input',
        `".env.example" isn't a .env file's name, or it is a template to commit`,
      ),
    ).toBe('envs.files.errors.template');
    expect(
      refusal(
        'invalid_input',
        `"package.json" isn't a .env file's name, or it is a template to commit`,
      ),
    ).toBe('envs.files.errors.notEnvName');
    expect(refusal('invalid_input', 'the file is a symbolic link')).toBe('envs.files.errors.link');
    expect(
      refusal('invalid_input', "the folder isn't in a project that holds the environment"),
    ).toBe('envs.files.errors.notInProject');
    expect(
      refusal('already_exists', "/code/shop/.env is written by another environment's file"),
    ).toBe('envs.files.errors.otherEnv');
    expect(refusal('already_exists', '.env')).toBe('envs.files.bind.taken');
    expect(refusal('io', 'disk full')).toBe(null);
  });

  it('tells a name taken in the group from a file taken', () => {
    expect(isEnvNameClash({ code: 'already_exists', message: 'shop-api / dev' })).toBe(true);
    expect(isEnvNameClash({ code: 'already_exists', message: '.env' })).toBe(false);
    expect(
      isEnvNameClash({
        code: 'already_exists',
        message: "/code/shop / web/.env is written by another environment's file",
      }),
    ).toBe(false);
  });
});
