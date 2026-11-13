import { QueryClientProvider } from '@tanstack/react-query';
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { keys, queryClient } from '@/api/queries';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { NewRecoveryKeyDialog } from './SecurityDialogs';
import { markLocked, setPendingRecoveryKey, usePendingRecoveryKey } from './vault';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  vaultNewRecoveryKey: vi.fn(),
  vaultCopyRecoveryKey: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const KEY = '7K3M-ABCD-EFGH-JKMN-PQRS-TVWX-YZ23-4567';

let state: VaultStatus['state'] = 'unlocked';

function status(): VaultStatus {
  return {
    state,
    files: {
      exists: true,
      hasMasterPassword: true,
      hasDeviceUnlock: false,
      deviceSlots: [],
      vaultId: 'id',
    },
    paths: { database: '/data/vault.kdbx', keys: '/data/vault.keys' },
    settings: {
      database: null,
      autoLockMinutes: 5,
      clipboardSeconds: 30,
      lockOnSleep: true,
      lockOnScreenLock: true,
      lockOnMinimize: false,
      unlockKeysOnOpen: false,
    },
    device: { kind: null, unavailableReason: null, enabled: false },
  };
}

describe('a new recovery key', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    queryClient.clear();
    state = 'unlocked';
    api.vaultStatus.mockImplementation(async () => status());
    api.vaultNewRecoveryKey.mockResolvedValue(KEY);
  });

  it('leaves the screen when the vault locks', () => {
    const { result } = renderHook(() => usePendingRecoveryKey());
    act(() => setPendingRecoveryKey(KEY));
    expect(result.current).toBe(KEY);
    act(() => markLocked());
    expect(result.current).toBeNull();
  });

  it('closes the Settings dialog that shows it when the vault locks', async () => {
    queryClient.setQueryData(keys.vaultStatus, status());
    const onDone = vi.fn();
    render(
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <Dialog open>
            <NewRecoveryKeyDialog onDone={onDone} />
          </Dialog>
        </TooltipProvider>
      </QueryClientProvider>,
    );
    await userEvent.type(screen.getByLabelText('Master password'), 'master{Enter}');
    expect(await screen.findByTestId('recovery-key')).toBeInTheDocument();
    expect(api.vaultNewRecoveryKey).toHaveBeenCalledWith('master');

    state = 'locked';
    act(() => markLocked());
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(screen.queryByTestId('recovery-key')).not.toBeInTheDocument();
  });
});
