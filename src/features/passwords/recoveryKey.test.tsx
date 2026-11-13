import { QueryClientProvider } from '@tanstack/react-query';
import { act, render, renderHook, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { keys, queryClient } from '@/api/queries';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { RecoveryKeyScreen } from './CreateVault';
import { NewRecoveryKeyDialog } from './SecurityDialogs';
import {
  markLocked,
  restoreUnsavedRecoveryKey,
  setPendingRecoveryKey,
  usePendingRecoveryKey,
} from './vault';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  vaultNewRecoveryKey: vi.fn(),
  vaultCopyRecoveryKey: vi.fn(),
  vaultUnsavedRecoveryKey: vi.fn(),
  vaultRecoveryKeySaved: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const KEY = '7K3M-ABCD-EFGH-JKMN-PQRS-TVWX-YZ23-4567';
const OLD_KEY = '0000-ABCD-EFGH-JKMN-PQRS-TVWX-YZ23-4567';

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

function wrap(children: ReactNode) {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>{children}</TooltipProvider>
    </QueryClientProvider>
  );
}

describe('a new recovery key', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    queryClient.clear();
    setPendingRecoveryKey(null);
    state = 'unlocked';
    api.vaultStatus.mockImplementation(async () => status());
    api.vaultNewRecoveryKey.mockResolvedValue(KEY);
    api.vaultUnsavedRecoveryKey.mockResolvedValue(KEY);
    api.vaultRecoveryKeySaved.mockResolvedValue(undefined);
  });

  it('leaves the screen when the vault locks', () => {
    const { result } = renderHook(() => usePendingRecoveryKey());
    act(() => setPendingRecoveryKey(KEY));
    expect(result.current).toBe(KEY);
    act(() => markLocked());
    expect(result.current).toBeNull();
  });

  it('comes back after an unlock until it is confirmed as saved', async () => {
    const { result } = renderHook(() => usePendingRecoveryKey());
    await act(async () => {
      expect(await restoreUnsavedRecoveryKey()).toBe(true);
    });
    expect(result.current).toBe(KEY);

    // Nothing to fetch while one is on screen.
    expect(await restoreUnsavedRecoveryKey()).toBe(false);
    expect(api.vaultUnsavedRecoveryKey).toHaveBeenCalledTimes(1);

    render(wrap(<RecoveryKeyScreen recoveryKey={KEY} />));
    await userEvent.click(screen.getByLabelText('I’ve saved my recovery key'));
    await userEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(api.vaultRecoveryKeySaved).toHaveBeenCalled();
    expect(result.current).toBeNull();

    // Confirmed: the backend has none to give back.
    api.vaultUnsavedRecoveryKey.mockResolvedValue(null);
    expect(await restoreUnsavedRecoveryKey()).toBe(false);
    expect(result.current).toBeNull();
  });

  it('closes the Settings dialog that shows it when the vault locks', async () => {
    queryClient.setQueryData(keys.vaultStatus, status());
    const onDone = vi.fn();
    render(
      wrap(
        <Dialog open>
          <NewRecoveryKeyDialog onDone={onDone} />
        </Dialog>,
      ),
    );
    await userEvent.type(screen.getByLabelText('Master password'), 'master{Enter}');
    expect(await screen.findByTestId('recovery-key')).toBeInTheDocument();
    expect(api.vaultNewRecoveryKey).toHaveBeenCalledWith('master');

    state = 'locked';
    act(() => markLocked());
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(screen.queryByTestId('recovery-key')).not.toBeInTheDocument();
    // Not confirmed: it comes back after the next unlock.
    expect(api.vaultRecoveryKeySaved).not.toHaveBeenCalled();
  });

  it('made in Settings replaces one not yet saved, and is confirmed with Done', async () => {
    queryClient.setQueryData(keys.vaultStatus, status());
    const { result } = renderHook(() => usePendingRecoveryKey());
    act(() => setPendingRecoveryKey(OLD_KEY));
    const onDone = vi.fn();
    render(
      wrap(
        <Dialog open>
          <NewRecoveryKeyDialog onDone={onDone} />
        </Dialog>,
      ),
    );
    await userEvent.type(screen.getByLabelText('Master password'), 'master{Enter}');
    expect(await screen.findByTestId('recovery-key')).toBeInTheDocument();
    expect(result.current).toBeNull();

    await userEvent.click(screen.getByLabelText('I’ve saved my recovery key'));
    await userEvent.click(screen.getByRole('button', { name: 'Done' }));
    expect(api.vaultRecoveryKeySaved).toHaveBeenCalled();
    expect(onDone).toHaveBeenCalled();
  });
});
