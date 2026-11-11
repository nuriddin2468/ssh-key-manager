import { renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { EnvFilesSynced } from '@/bindings/EnvFilesSynced';

const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
const refreshFileReports = vi.hoisted(() => vi.fn(() => Promise.resolve()));
const invalidateQueries = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({ isTauri: () => true }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: (name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => listeners.delete(name));
  },
}));
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }));
vi.mock('@/api/commands', () => ({ api: {} }));
vi.mock('@/api/queries', () => ({ invalidateAll: vi.fn(), queryClient: { invalidateQueries } }));
vi.mock('@/app/router', () => ({ useRouter: () => ({ navigate: vi.fn() }) }));
vi.mock('react-i18next', () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock('./queries', () => ({ refreshFileReports }));

const { useEnvFilesEvents } = await import('./announce');

const written = {
  envId: 'env-1',
  label: 'shop-api',
  envName: 'dev',
  file: { folder: '~/code/shop', path: 'apps/web/.env' },
  location: '/code/shop/apps/web/.env',
  state: { type: 'inSync' },
} as const;

afterEach(() => vi.clearAllMocks());

describe('the backend’s rounds', () => {
  it('ask Git and cloud folders again when a file was written', () => {
    renderHook(() => useEnvFilesEvents());
    const handler = listeners.get('env-files-changed');
    expect(handler).toBeDefined();
    const round = (payload: EnvFilesSynced) => handler?.({ payload });
    round({ changes: [], written: [], files: [written] });
    expect(invalidateQueries).toHaveBeenCalledWith({ queryKey: ['vault', 'envs'] });
    expect(refreshFileReports).not.toHaveBeenCalled();
    // A file whose folder was made since is written now.
    round({ changes: [], written: [written], files: [written] });
    expect(refreshFileReports).toHaveBeenCalledTimes(1);
  });
});
