import { QueryClientProvider } from '@tanstack/react-query';
import { act, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { queryClient } from '@/api/queries';
import type { Project } from '@/bindings/Project';
import { useJoinMade } from './actions';

const api = vi.hoisted(() => ({ projectsSetMember: vi.fn() }));
vi.mock('@/api/commands', () => ({ api }));
const dialogs = vi.hoisted(() => ({ unlockVault: vi.fn() }));
vi.mock('@/app/dialogs', () => ({ useDialogs: () => dialogs }));

const shop = { id: 'p1', name: 'Shop' } as Project;
const wrapper = ({ children }: { children: ReactNode }) => (
  <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
);

afterEach(() => {
  vi.clearAllMocks();
  queryClient.clear();
});

describe('what a project’s Add menu made', () => {
  it('joins the project it was made from, the key’s host too', async () => {
    api.projectsSetMember.mockResolvedValue(undefined);
    const { result } = renderHook(() => useJoinMade(), { wrapper });
    act(() =>
      result.current.mutate({
        into: shop,
        name: 'id_shop',
        members: [
          { type: 'key', fingerprint: 'SHA256:a' },
          { type: 'host', alias: 'shop-api' },
        ],
      }),
    );
    await vi.waitFor(() => expect(api.projectsSetMember).toHaveBeenCalledTimes(2));
    expect(api.projectsSetMember).toHaveBeenNthCalledWith(
      1,
      'p1',
      { type: 'key', fingerprint: 'SHA256:a' },
      true,
    );
    expect(api.projectsSetMember).toHaveBeenNthCalledWith(
      2,
      'p1',
      { type: 'host', alias: 'shop-api' },
      true,
    );
  });

  it('asks to unlock when the vault locked meanwhile, then joins', async () => {
    api.projectsSetMember
      .mockRejectedValueOnce({ code: 'vault_locked', message: 'locked' })
      .mockResolvedValue(undefined);
    dialogs.unlockVault.mockImplementation(({ onUnlocked }) => onUnlocked());
    const { result } = renderHook(() => useJoinMade(), { wrapper });
    act(() =>
      result.current.mutate({
        into: shop,
        name: 'shop-api',
        members: [{ type: 'host', alias: 'shop-api' }],
      }),
    );
    await vi.waitFor(() => expect(api.projectsSetMember).toHaveBeenCalledTimes(2));
    expect(dialogs.unlockVault).toHaveBeenCalledWith(
      expect.objectContaining({
        description: 'shop-api is saved. Unlock the vault to add it to Shop.',
      }),
    );
    expect(api.projectsSetMember).toHaveBeenLastCalledWith(
      'p1',
      { type: 'host', alias: 'shop-api' },
      true,
    );
  });
});
