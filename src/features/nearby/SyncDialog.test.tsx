import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RouterProvider } from '@/app/router';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import type { Pairing } from '@/bindings/Pairing';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { SyncDialog } from './SyncDialog';

const api = vi.hoisted(() => ({
  nearbyStatus: vi.fn(),
  nearbyDecide: vi.fn(),
  nearbyClose: vi.fn(),
  nearbySyncValue: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

function status(pairing: Pairing | null): NearbyStatus {
  return {
    name: 'macbook',
    visibleUntil: null,
    address: null,
    joining: false,
    hiddenAfterAttempts: false,
    reachable: true,
    present: true,
    ownFound: [],
    devices: [],
    pairing,
  };
}

const deciding: Pairing = {
  id: 7,
  peer: 'iMac',
  outgoing: true,
  kind: 'sync',
  phase: {
    type: 'decide',
    review: {
      conflicts: [
        {
          id: 'prod',
          mine: { id: 'prod', fields: [{ key: 'HostName', values: ['10.0.0.1'] }] },
          theirs: { id: 'prod', fields: [{ key: 'HostName', values: ['10.0.0.2'] }] },
        },
      ],
      risky: [{ id: 'lab', lines: [{ key: 'ProxyCommand', value: 'ssh -W %h:%p gw' }] }],
      deletions: ['a', 'b', 'c', 'd', 'e', 'f'],
      vault: { conflicts: [], risky: [], deletions: [] },
    },
  },
};

const noVault = {
  logins: { added: 0, changed: 0, removed: 0 },
  environments: { added: 0, changed: 0, removed: 0 },
  shared: { added: 0, changed: 0, removed: 0 },
  folders: { added: 0, changed: 0, removed: 0 },
};

const decidingVault: Pairing = {
  ...deciding,
  id: 9,
  phase: {
    type: 'decide',
    review: {
      conflicts: [],
      risky: [],
      deletions: ['old-ci'],
      vault: {
        conflicts: [
          {
            id: 'mail',
            kind: 'login',
            label: 'Mail',
            here: 'changed',
            there: 'changed',
            fields: ['s:Password', 's:otp'],
            risky: [],
            toBin: false,
          },
          {
            id: 'stage',
            kind: 'environment',
            label: 'Shop · staging',
            here: 'deleted',
            there: 'changed',
            fields: [],
            risky: [],
            toBin: false,
          },
        ],
        risky: [
          {
            id: 'dev',
            kind: 'environment',
            label: 'Shop · dev',
            op: 'update',
            fields: ['s:NODE_OPTIONS'],
            removal: false,
            fromBin: false,
            risky: ['NODE_OPTIONS'],
            version: 'v',
          },
        ],
        deletions: ['a', 'b', 'c', 'd', 'e'].map((label, n) => ({
          id: label,
          kind: 'login' as const,
          label: label.toUpperCase(),
          op: 'delete' as const,
          fields: [],
          removal: true,
          fromBin: n === 0,
          risky: [],
          version: '',
        })),
      },
    },
  },
};

function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <RouterProvider>
        <TooltipProvider>
          <SyncDialog />
        </TooltipProvider>
      </RouterProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.nearbyDecide.mockResolvedValue(undefined);
  api.nearbyClose.mockResolvedValue(undefined);
});

describe('SyncDialog', () => {
  it('sends what the user chose and leaves the rest for later', async () => {
    api.nearbyStatus.mockResolvedValue(status(deciding));
    show();

    const dialog = await screen.findByRole('dialog', { name: 'Sync with iMac' });
    expect(within(dialog).getByText('10.0.0.1')).toBeInTheDocument();
    expect(within(dialog).getByText('10.0.0.2')).toBeInTheDocument();
    expect(within(dialog).getByText('ProxyCommand ssh -W %h:%p gw')).toBeInTheDocument();

    await userEvent.click(within(dialog).getByRole('radio', { name: 'Take iMac’s' }));
    await userEvent.click(within(dialog).getByRole('checkbox', { name: 'Delete them here too' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue' }));

    expect(api.nearbyDecide).toHaveBeenCalledExactlyOnceWith(7, {
      mine: [],
      theirs: ['prod'],
      apply: [],
      decline: [],
      delete: true,
      vaultMine: [],
      vaultTheirs: [],
      vaultApply: [],
      vaultDecline: [],
    });
  });

  it('shows the vault’s conflicts by field, values only when asked', async () => {
    api.nearbyStatus.mockResolvedValue(status(decidingVault));
    api.nearbySyncValue.mockImplementation(
      (_id: number, _item: string, _field: string, theirs: boolean) =>
        Promise.resolve(theirs ? 'new-secret' : 'old-secret'),
    );
    show();

    const dialog = await screen.findByRole('dialog', { name: 'Sync with iMac' });
    expect(within(dialog).getByText('Changed here and on iMac')).toBeInTheDocument();
    expect(within(dialog).getByText('Deleted here, changed on iMac')).toBeInTheDocument();
    expect(within(dialog).getByText('Password')).toBeInTheDocument();
    expect(within(dialog).queryByText('old-secret')).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Show values' }));
    // The 2FA secret differs, but is never offered to show.
    expect(within(dialog).queryByRole('button', { name: 'Show: 2FA' })).not.toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Show: Password' }));
    expect(await within(dialog).findByText('old-secret')).toBeInTheDocument();
    expect(within(dialog).getByText('new-secret')).toBeInTheDocument();
    expect(api.nearbySyncValue).toHaveBeenCalledWith(9, 'mail', 's:Password', true);

    expect(within(dialog).getByText('NODE_OPTIONS')).toBeInTheDocument();
    expect(within(dialog).getByText('Deleted on iMac: 6')).toBeInTheDocument();
    expect(within(dialog).getByText('A (from the recycle bin), B, C, D, E')).toBeInTheDocument();

    const mail = within(dialog).getByRole('radiogroup', { name: 'Mail' });
    await userEvent.click(within(mail).getByRole('radio', { name: 'Take iMac’s' }));
    const stage = within(dialog).getByRole('radiogroup', { name: 'Shop · staging' });
    await userEvent.click(within(stage).getByRole('radio', { name: 'Keep this computer’s' }));
    const dev = within(dialog).getByRole('radiogroup', { name: 'Shop · dev' });
    await userEvent.click(within(dev).getByRole('radio', { name: 'Don’t add' }));
    await userEvent.click(within(dialog).getByRole('button', { name: 'Continue' }));
    expect(api.nearbyDecide).toHaveBeenCalledExactlyOnceWith(9, {
      mine: [],
      theirs: [],
      apply: [],
      decline: [],
      delete: false,
      vaultMine: ['stage'],
      vaultTheirs: ['mail'],
      vaultApply: [],
      vaultDecline: ['dev'],
    });
  });

  it('shows how a sync went, server keys that differ among it', async () => {
    api.nearbyStatus.mockResolvedValue(
      status({
        id: 8,
        peer: 'iMac',
        outgoing: true,
        kind: 'sync',
        phase: {
          type: 'synced',
          summary: {
            added: 2,
            changed: 1,
            removed: 0,
            devicesAdded: [],
            keysAdded: 0,
            keysDiffer: [{ host: 'nas', port: 22, here: ['SHA256:aaa'], there: ['SHA256:bbb'] }],
            deferred: 0,
            deferredThere: 3,
            conflicts: 0,
            failed: 0,
            vault: { ...noVault, logins: { added: 3, changed: 0, removed: 1 } },
            vaultOff: null,
          },
        },
      }),
    );
    show();

    const dialog = await screen.findByRole('dialog', { name: 'Synced with iMac' });
    expect(within(dialog).getByText('2 hosts added, 1 host changed')).toBeInTheDocument();
    expect(within(dialog).getByText('Passwords: 3 added, 1 deleted')).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        '3 changes wait for confirmation on iMac. Sync from there to review them.',
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByText('Different server keys')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));
    expect(api.nearbyClose).toHaveBeenCalledWith(8);
  });

  it('says why the vault didn’t sync', async () => {
    api.nearbyStatus.mockResolvedValue(
      status({
        id: 10,
        peer: 'iMac',
        outgoing: true,
        kind: 'sync',
        phase: {
          type: 'synced',
          summary: {
            added: 0,
            changed: 0,
            removed: 0,
            devicesAdded: [],
            keysAdded: 0,
            keysDiffer: [],
            deferred: 0,
            deferredThere: 0,
            conflicts: 0,
            failed: 0,
            vault: noVault,
            vaultOff: { type: 'cloud', service: 'dropbox', here: false },
          },
        },
      }),
    );
    show();
    const dialog = await screen.findByRole('dialog', { name: 'Synced with iMac' });
    expect(within(dialog).getByText('Nothing needed changing.')).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        'The vault wasn’t synced: on iMac it’s in Dropbox, which keeps it in step. Open the same file on this computer.',
      ),
    ).toBeInTheDocument();
  });

  it('stays out of syncs another device started', async () => {
    api.nearbyStatus.mockResolvedValue(status({ ...deciding, outgoing: false }));
    show();
    await waitFor(() => expect(api.nearbyStatus).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
