import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { EnvFileComparison } from '@/bindings/EnvFileComparison';
import type { EnvFilesSynced } from '@/bindings/EnvFilesSynced';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { FileCompareDialog } from './FileCompareDialog';

const api = vi.hoisted(() => ({ envsFilesCompare: vi.fn(), envsFilesResolve: vi.fn() }));
vi.mock('@/api/commands', () => ({ api }));
vi.mock('@/app/router', () => ({ useRouter: () => ({ navigate: vi.fn() }) }));
vi.mock('sonner', () => ({ toast: { success: vi.fn(), warning: vi.fn(), error: vi.fn() } }));

const file = { folder: '~/code/shop', path: 'apps/worker/.env.local' };
const comparison = (revision: string): EnvFileComparison => ({
  onlyLeft: [],
  onlyRight: ['QUEUE_CONCURRENCY'],
  changed: ['LOG_LEVEL'],
  same: ['NODE_ENV'],
  revision,
});
const nothing: EnvFilesSynced = { changes: [], written: [], files: [] };

function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onDone = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <Dialog open>
          <FileCompareDialog envId="env-1" file={file} onDone={onDone} />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
  // Another round, the window coming back: the comparison is fetched again.
  const refetch = () => act(() => client.invalidateQueries({ queryKey: ['vault', 'envs'] }));
  return { onDone, refetch };
}

const keepFile = () => screen.getByRole('button', { name: 'Keep the file’s values' });
const changedSince = () =>
  screen.queryByText('The file changed while this was open. Check the differences again.');

afterEach(() => vi.clearAllMocks());

describe('comparing a file with the vault', () => {
  it('says so when the file changed while it was open', async () => {
    api.envsFilesCompare
      .mockResolvedValueOnce(comparison('rev-1'))
      .mockResolvedValue(comparison('rev-2'));
    const { refetch } = show();
    await vi.waitFor(() => expect(keepFile()).toBeEnabled());
    expect(changedSince()).toBeNull();
    await refetch();
    await vi.waitFor(() => expect(changedSince()).not.toBeNull());
  });

  it('stays quiet when the file changes because a side is being kept', async () => {
    api.envsFilesCompare
      .mockResolvedValueOnce(comparison('rev-1'))
      .mockResolvedValue(comparison('rev-kept'));
    let settle: (synced: EnvFilesSynced) => void = () => {};
    api.envsFilesResolve.mockReturnValue(
      new Promise<EnvFilesSynced>((resolve) => {
        settle = resolve;
      }),
    );
    const { onDone, refetch } = show();
    await vi.waitFor(() => expect(keepFile()).toBeEnabled());
    fireEvent.click(keepFile());
    await vi.waitFor(() =>
      expect(api.envsFilesResolve).toHaveBeenCalledWith('env-1', file, 'file', 'rev-1'),
    );
    // Keeping rewrote the vault: the round that follows sees a new revision.
    await refetch();
    await vi.waitFor(() => expect(api.envsFilesCompare).toHaveBeenCalledTimes(2));
    await act(async () => settle(nothing));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(changedSince()).toBeNull();
  });

  it('speaks up again when keeping failed because the file changed', async () => {
    api.envsFilesCompare
      .mockResolvedValueOnce(comparison('rev-1'))
      .mockResolvedValue(comparison('rev-2'));
    api.envsFilesResolve.mockRejectedValue({
      code: 'conflict',
      message: 'the file changed since it was compared',
    });
    const { onDone } = show();
    await vi.waitFor(() => expect(keepFile()).toBeEnabled());
    fireEvent.click(keepFile());
    await vi.waitFor(() => expect(changedSince()).not.toBeNull());
    expect(onDone).not.toHaveBeenCalled();
    // Compared again, with the file as it is now.
    await vi.waitFor(() => expect(api.envsFilesCompare).toHaveBeenCalledTimes(2));
  });
});
