import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { SavedSecret } from './SavedSecret';

const api = vi.hoisted(() => ({ vaultReveal: vi.fn(), vaultCopy: vi.fn() }));
vi.mock('@/api/commands', () => ({ api }));
const dialogs = vi.hoisted(() => ({ unlockVault: vi.fn() }));
vi.mock('@/app/dialogs', () => ({ useDialogs: () => dialogs }));

const labels = {
  show: 'Show passphrase',
  hide: 'Hide passphrase',
  copy: 'Copy passphrase',
  copied: 'Passphrase copied',
};

function wrap(children: ReactNode) {
  const client = new QueryClient();
  return (
    <QueryClientProvider client={client}>
      <TooltipProvider>{children}</TooltipProvider>
    </QueryClientProvider>
  );
}

const secret = (entryId: string | undefined, locked: boolean, id = 'key:one') => (
  <SavedSecret id={id} entryId={entryId} locked={locked} labels={labels} unlockReason="why" />
);

describe('SavedSecret', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.vaultReveal.mockResolvedValue('hunter2');
  });

  it('shows the secret of an open vault when clicked, and hides it again', async () => {
    render(wrap(secret('e1', false)));
    expect(screen.queryByText('hunter2')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Show passphrase' }));
    expect(await screen.findByText('hunter2')).toBeInTheDocument();
    expect(api.vaultReveal).toHaveBeenCalledWith('e1', 'password');
    expect(dialogs.unlockVault).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Hide passphrase' }));
    expect(screen.queryByText('hunter2')).not.toBeInTheDocument();
  });

  it('opens a locked vault first, then shows the secret once its entry is known', async () => {
    const { rerender } = render(wrap(secret(undefined, true)));
    fireEvent.click(screen.getByRole('button', { name: 'Show passphrase' }));
    expect(dialogs.unlockVault).toHaveBeenCalledWith(
      expect.objectContaining({ description: 'why' }),
    );
    expect(api.vaultReveal).not.toHaveBeenCalled();

    act(() => dialogs.unlockVault.mock.calls[0]?.[0].onUnlocked());
    // The entries load a moment after the unlock.
    rerender(wrap(secret(undefined, false)));
    expect(api.vaultReveal).not.toHaveBeenCalled();
    rerender(wrap(secret('e1', false)));
    expect(await screen.findByText('hunter2')).toBeInTheDocument();
  });

  it('does nothing after a cancelled unlock', () => {
    const { rerender } = render(wrap(secret(undefined, true, 'key:two')));
    fireEvent.click(screen.getByRole('button', { name: 'Show passphrase' }));
    // Unlocked some other way later, without `onUnlocked` from this request.
    rerender(wrap(secret('e2', false, 'key:two')));
    expect(api.vaultReveal).not.toHaveBeenCalled();
  });
});
