import { renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

const listeners = vi.hoisted(() => new Map<string, (event: { payload: unknown }) => void>());
vi.mock('@tauri-apps/api/core', () => ({ isTauri: () => true }));
vi.mock('@tauri-apps/api/event', () => ({
  listen: (name: string, handler: (event: { payload: unknown }) => void) => {
    listeners.set(name, handler);
    return Promise.resolve(() => listeners.delete(name));
  },
}));
vi.mock('@/api/commands', () => ({ api: {} }));
vi.mock('@/api/queries', () => ({ queryClient: { invalidateQueries: vi.fn() } }));

const { OUTDATED_EVENT, useBrowserEvents } = await import('./queries');

afterEach(() => listeners.clear());

describe('the bridge’s events', () => {
  it('name the browser whose extension is too old to pair', () => {
    const onOutdated = vi.fn();
    renderHook(() => useBrowserEvents({ onPairing: vi.fn(), onUnlock: vi.fn(), onOutdated }));
    listeners.get(OUTDATED_EVENT)?.({ payload: 'Firefox' });
    expect(onOutdated).toHaveBeenCalledWith('Firefox');
  });
});
