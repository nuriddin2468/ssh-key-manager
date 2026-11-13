import { QueryClientProvider } from '@tanstack/react-query';
import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { queryClient } from '@/api/queries';
import { RouterProvider } from '@/app/router';
import type { ItemSummary } from '@/bindings/ItemSummary';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import type { Pairing } from '@/bindings/Pairing';
import type { PairingPhase } from '@/bindings/PairingPhase';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { PairingDialog } from './PairingDialog';
import { setStatus } from './queries';

const api = vi.hoisted(() => ({
  nearbyStatus: vi.fn(),
  nearbyAnswer: vi.fn(),
  nearbyClose: vi.fn(),
  nearbySync: vi.fn(),
  listKeys: vi.fn(),
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

const login: ItemSummary = {
  type: 'password',
  title: 'Router',
  username: 'admin',
  url: '',
  otp: false,
  host: null,
  server: null,
};

function sending(phase: PairingPhase): Pairing {
  return { id: 3, peer: 'iMac', outgoing: true, kind: 'pair', phase };
}

/** The backend's `nearby-changed` event. */
function changed(pairing: Pairing | null) {
  act(() => setStatus(status(pairing)));
}

function show(pairing: Pairing | null) {
  queryClient.setQueryData(['nearby', 'status'], status(pairing));
  render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider>
        <TooltipProvider>
          <PairingDialog />
        </TooltipProvider>
      </RouterProvider>
    </QueryClientProvider>,
  );
}

/** The button in the dialog's footer, not the close button in its header. */
function footerButton(dialog: HTMLElement, name: string) {
  const buttons = within(dialog).getAllByRole('button', { name });
  return buttons[buttons.length - 1] as HTMLElement;
}

beforeEach(() => {
  vi.clearAllMocks();
  api.nearbyStatus.mockImplementation(() =>
    Promise.resolve(queryClient.getQueryData(['nearby', 'status'])),
  );
  api.nearbyClose.mockResolvedValue(undefined);
  api.nearbyAnswer.mockResolvedValue(undefined);
  api.listKeys.mockResolvedValue({ keys: [] });
});

afterEach(() => {
  queryClient.clear();
});

describe('PairingDialog', () => {
  it('closes after an item was sent, without waiting for the backend', async () => {
    show(sending({ type: 'sent', item: login }));
    const dialog = await screen.findByRole('dialog', { name: 'Sending to iMac' });
    expect(within(dialog).getByText('Saved on iMac.')).toBeInTheDocument();

    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));

    expect(api.nearbyClose).toHaveBeenCalledExactlyOnceWith(3);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('closes after an item was received, from the header too', async () => {
    show({
      ...sending({ type: 'received', item: login, name: 'Router', keysDiffer: false, leftOut: [] }),
      outgoing: false,
    });
    const dialog = await screen.findByRole('dialog', { name: 'From iMac' });

    await userEvent.click(within(dialog).getByRole('button', { name: 'Close' }));

    expect(api.nearbyClose).toHaveBeenCalledExactlyOnceWith(3);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it.each([
    ['refused', 'The other computer declined it.'],
    ['timedOut', 'Nobody answered in time.'],
  ] as const)('offers a Close that works after a failure (%s)', async (reason, text) => {
    show(sending({ type: 'failed', reason }));
    const dialog = await screen.findByRole('dialog');
    expect(within(dialog).getByText(text)).toBeInTheDocument();

    await userEvent.click(footerButton(dialog, 'Close'));

    expect(api.nearbyClose).toHaveBeenCalledWith(3);
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('cancels a send going on, then closes', async () => {
    show(sending({ type: 'offering', item: login }));
    const dialog = await screen.findByRole('dialog', { name: 'Sending to iMac' });
    // Going on: it can't be dismissed by accident.
    expect(within(dialog).queryByRole('button', { name: 'Close' })).not.toBeInTheDocument();

    await userEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
    expect(api.nearbyClose).toHaveBeenCalledExactlyOnceWith(3);
    // Still open until the backend says how it ended.
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    changed(sending({ type: 'failed', reason: 'cancelled' }));
    const ended = await screen.findByRole('dialog');
    expect(within(ended).getByText('You cancelled.')).toBeInTheDocument();
    await userEvent.click(footerButton(ended, 'Close'));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('shows where an offered server password leads before it is accepted', async () => {
    const server: ItemSummary = {
      ...login,
      host: 'prod',
      server: { user: 'deploy', hostName: '10.0.4.12', port: 2222, proxyJump: 'bastion' },
    };
    show({ ...sending({ type: 'offered', item: server }), outgoing: false });
    const dialog = await screen.findByRole('dialog', { name: 'From iMac' });
    expect(
      within(dialog).getByText('admin · for prod · deploy@10.0.4.12:2222 · via bastion'),
    ).toBeInTheDocument();
    expect(
      within(dialog).getByText(/used only for a host here that leads to the same server/),
    ).toBeInTheDocument();
  });

  it('names the variables of a received environment it left out', async () => {
    const environment: ItemSummary = {
      type: 'environment',
      project: 'Shop',
      name: 'dev',
      variables: 3,
      secrets: 1,
      names: ['PORT', 'NODE_OPTIONS', 'BASH_ENV'],
    };
    show({
      ...sending({
        type: 'received',
        item: environment,
        name: 'Shop · dev',
        keysDiffer: false,
        leftOut: ['NODE_OPTIONS', 'BASH_ENV'],
      }),
      outgoing: false,
    });
    const dialog = await screen.findByRole('dialog', { name: 'From iMac' });
    expect(
      within(dialog).getByText(
        'Left out, as they make programs run code: NODE_OPTIONS, BASH_ENV. Add them to the environment yourself if you trust them.',
      ),
    ).toBeInTheDocument();
  });

  it('closes when the backend lets the pairing go', async () => {
    show({ id: 4, peer: 'iMac', outgoing: true, kind: 'pair', phase: { type: 'paired' } });
    await screen.findByRole('dialog', { name: 'Pair with iMac' });

    changed(null);

    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  });

  it('shows the next pairing after one was closed', async () => {
    show(sending({ type: 'sent', item: login }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Done' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());

    changed({ ...sending({ type: 'connecting' }), id: 5 });

    expect(await screen.findByRole('dialog')).toBeInTheDocument();
  });
});
