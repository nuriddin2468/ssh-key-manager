import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { ReviewDialog } from './ReviewDialog';

const api = vi.hoisted(() => ({ previewHostsChanges: vi.fn(), applyHostsChanges: vi.fn() }));
vi.mock('@/api/commands', () => ({ api }));

function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <Dialog open>
          <ReviewDialog
            revision="r1"
            changes={[]}
            conflict={false}
            onApplied={vi.fn()}
            onStale={vi.fn()}
            onDone={vi.fn()}
          />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

const save = () => screen.getByRole('button', { name: 'Save with password' });

afterEach(() => vi.clearAllMocks());

describe('reviewing a hosts file change', () => {
  it('says why when the change can’t be shown, and can’t be saved', async () => {
    api.previewHostsChanges.mockRejectedValue({
      code: 'invalid_input',
      message: 'localhost is reserved for the system',
    });
    show();
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Can’t show this change: Some of the values are not valid.');
    expect(alert).toHaveTextContent('localhost is reserved for the system');
    expect(save()).toBeDisabled();
  });

  it('asks for no password when the file already reads that way', async () => {
    api.previewHostsChanges.mockResolvedValue({
      stale: false,
      diff: [{ kind: 'same', oldLine: 1, newLine: 1, text: '10.0.0.3 api.test' }],
    });
    show();
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Nothing to change: the file already reads this way.',
    );
    expect(save()).toBeDisabled();
  });

  it('can be saved when lines change', async () => {
    api.previewHostsChanges.mockResolvedValue({
      stale: false,
      diff: [
        { kind: 'removed', oldLine: 1, newLine: null, text: '# 10.0.0.3 api.test' },
        { kind: 'added', oldLine: null, newLine: 1, text: '10.0.0.3 api.test' },
      ],
    });
    show();
    await vi.waitFor(() => expect(save()).toBeEnabled());
  });
});
