import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { KeyView } from '@/bindings/KeyView';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import type { VaultKey } from '@/features/keys/vaultKey';
import { KeyCheckDialog } from './KeyCheckDialog';

// Radix measures the checkbox; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  vaultEntries: vi.fn(),
  vaultUnlock: vi.fn(),
  vaultUnlockDevice: vi.fn(),
  vaultAdd: vi.fn(),
  testConnection: vi.fn(),
  vaultTestConnection: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));
const vaultKey = vi.hoisted(() => ({ current: { vault: 'unknown' } as VaultKey }));
vi.mock('@/features/keys/vaultKey', async (original) => ({
  ...(await original<typeof import('@/features/keys/vaultKey')>()),
  useVaultKey: () => vaultKey.current,
}));

const work: KeyView = {
  id: 'SHA256:work#id_work',
  name: 'id_work',
  privatePath: '/home/dev/.ssh/id_work',
  publicPath: '/home/dev/.ssh/id_work.pub',
  algorithm: 'ed25519',
  keyType: 'ssh-ed25519',
  bits: 256,
  fingerprint: 'SHA256:work',
  comment: 'work',
  encrypted: true,
  hardware: false,
  format: 'openssh',
  publicKey: 'ssh-ed25519 AAAAwork work',
  modified: null,
  pairMismatch: false,
  permissions: { ok: true, mode: '600', problem: null },
  inAgent: false,
  usedBy: [],
};

const signedIn: ConnectionTest = { ok: true, output: '', prompts: [] };

function show(state: 'locked' | 'unlocked') {
  api.vaultStatus.mockResolvedValue({
    state,
    files: { hasMasterPassword: true },
    device: { kind: null, unavailableReason: null, enabled: false },
  });
  const onChecked = vi.fn();
  const onDone = vi.fn();
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <Dialog open>
          <KeyCheckDialog alias="prod" keyView={work} onChecked={onChecked} onDone={onDone} />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
  return { onChecked, onDone };
}

beforeEach(() => {
  vi.clearAllMocks();
  api.vaultEntries.mockResolvedValue([]);
});

describe('KeyCheckDialog', () => {
  it('opens the vault that holds the passphrase, then checks with it', async () => {
    vaultKey.current = { vault: 'locked', saved: true };
    api.vaultUnlock.mockResolvedValue(undefined);
    api.vaultTestConnection.mockResolvedValue(signedIn);
    const { onChecked, onDone } = show('locked');

    expect(
      await screen.findByRole('heading', { name: 'Unlock the vault to check prod' }),
    ).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Master password'), 'hunter2{Enter}');

    await vi.waitFor(() => expect(onChecked).toHaveBeenCalledWith(signedIn));
    expect(api.vaultUnlock.mock.calls[0]?.[0]).toBe('hunter2');
    expect(api.vaultTestConnection).toHaveBeenCalledWith('prod');
    expect(api.testConnection).not.toHaveBeenCalled();
    expect(onDone).toHaveBeenCalled();
  });

  it('asks for a passphrase that is not saved, and says when it is wrong', async () => {
    vaultKey.current = { vault: 'locked', saved: false };
    api.testConnection
      .mockRejectedValueOnce({ code: 'wrong_passphrase', message: 'wrong passphrase' })
      .mockResolvedValueOnce(signedIn);
    const { onChecked } = show('locked');

    const field = await screen.findByLabelText('Passphrase');
    expect(screen.getByText('Unlock the vault to save it.')).toBeInTheDocument();
    await userEvent.type(field, 'nope{Enter}');
    expect(await screen.findByText('Wrong passphrase.')).toBeInTheDocument();
    expect(onChecked).not.toHaveBeenCalled();

    await userEvent.clear(field);
    await userEvent.type(field, 'right{Enter}');
    await vi.waitFor(() => expect(onChecked).toHaveBeenCalledWith(signedIn));
    expect(api.testConnection).toHaveBeenLastCalledWith('prod', {
      keyId: work.id,
      passphrase: 'right',
    });
    expect(api.vaultAdd).not.toHaveBeenCalled();
  });

  it('checks with the open vault and saves the typed passphrase there', async () => {
    vaultKey.current = { vault: 'unlocked', entry: undefined };
    api.vaultTestConnection.mockResolvedValue(signedIn);
    api.vaultAdd.mockResolvedValue({});
    const { onChecked } = show('unlocked');

    expect(await screen.findByRole('checkbox', { name: 'Save in the vault' })).toBeChecked();
    await userEvent.type(screen.getByLabelText('Passphrase'), 'right{Enter}');

    await vi.waitFor(() => expect(onChecked).toHaveBeenCalledWith(signedIn));
    expect(api.vaultTestConnection).toHaveBeenCalledWith('prod', {
      keyId: work.id,
      passphrase: 'right',
    });
    expect(api.vaultAdd).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'key', keyFingerprint: 'SHA256:work', password: 'right' }),
    );
  });
});
