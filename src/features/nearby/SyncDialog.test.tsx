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
}));
vi.mock('@/api/commands', () => ({ api }));

function status(pairing: Pairing | null): NearbyStatus {
  return {
    name: 'macbook',
    visibleUntil: null,
    address: null,
    joining: false,
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
            keysAdded: 0,
            keysDiffer: [{ host: 'nas', port: 22, here: ['SHA256:aaa'], there: ['SHA256:bbb'] }],
            deferred: 0,
            deferredThere: 3,
            conflicts: 0,
            failed: 0,
          },
        },
      }),
    );
    show();

    const dialog = await screen.findByRole('dialog', { name: 'Synced with iMac' });
    expect(within(dialog).getByText('2 hosts added, 1 host changed')).toBeInTheDocument();
    expect(
      within(dialog).getByText(
        '3 changes wait for confirmation on iMac. Sync from there to review them.',
      ),
    ).toBeInTheDocument();
    expect(within(dialog).getByText('Different server keys')).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));
    expect(api.nearbyClose).toHaveBeenCalledWith(8);
  });

  it('stays out of syncs another device started', async () => {
    api.nearbyStatus.mockResolvedValue(status({ ...deciding, outgoing: false }));
    show();
    await waitFor(() => expect(api.nearbyStatus).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
