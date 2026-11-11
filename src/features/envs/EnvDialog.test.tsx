import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { Project } from '@/bindings/Project';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { EnvDialog } from './EnvDialog';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsList: vi.fn(),
  envsFilesOverview: vi.fn(),
  envsCreate: vi.fn(),
  envsSetPart: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const site = { id: 'p-site', name: 'Site', color: 'violet' } as Project;
const env = (id: string, name: string): EnvSummary =>
  ({
    id,
    project: 'p-site',
    part: 'marketing-site',
    group: 'marketing-site',
    name,
    kind: 'remote',
    variableCount: 0,
    secretCount: 0,
    inTrash: false,
    modified: null,
  }) as EnvSummary;
const ALL = [env('e1', 'dev'), env('e2', 'prod')];

function show() {
  api.vaultStatus.mockResolvedValue({ state: 'unlocked' });
  api.projectsList.mockResolvedValue([site]);
  api.envsList.mockResolvedValue(ALL);
  api.envsFilesOverview.mockResolvedValue({ files: [], unmanaged: [], truncated: false });
  api.envsCreate.mockResolvedValue({
    ...env('e3', 'dev'),
    part: 'blog',
    notes: '',
    variables: [],
    files: [],
  });
  api.envsSetPart.mockResolvedValue(undefined);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onDone = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <Dialog open>
          <EnvDialog env={null} all={ALL} defaultProject="p-site" onDone={onDone} />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
  return onDone;
}

const field = (name: string) => screen.getByRole('combobox', { name }) as HTMLInputElement;
const type = (input: HTMLElement, value: string) => fireEvent.change(input, { target: { value } });

afterEach(() => vi.clearAllMocks());

describe('a new environment', () => {
  it('starts in the project’s only part', async () => {
    show();
    expect(field('Part').value).toBe('marketing-site');
  });

  it('names the part a project had when it gets a second, then is made', async () => {
    const onDone = show();
    type(field('Part'), 'blog');
    type(screen.getByRole('textbox', { name: 'Stage' }), 'dev');
    fireEvent.click(screen.getByRole('button', { name: 'Create environment' }));

    // The project gets its second part: the first is named first.
    expect(await screen.findByText('Site gets a second part')).toBeInTheDocument();
    const first = screen.getByRole('textbox', { name: 'Part of its other environments' });
    expect(first).toHaveValue('marketing-site');
    type(first, 'blog');
    fireEvent.click(screen.getByRole('button', { name: 'Name it and continue' }));
    // Said as it appears.
    expect(await screen.findByRole('alert')).toHaveTextContent('Use a name other than blog.');
    expect(api.envsSetPart).not.toHaveBeenCalled();

    type(first, 'site');
    fireEvent.click(screen.getByRole('button', { name: 'Name it and continue' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalledWith('e3'));
    expect(api.envsSetPart).toHaveBeenCalledWith(['e1', 'e2'], 'site');
    expect(api.envsCreate).toHaveBeenCalledWith({
      project: 'p-site',
      part: 'blog',
      name: 'dev',
      notes: '',
    });
    expect(api.envsSetPart.mock.invocationCallOrder[0]).toBeLessThan(
      api.envsCreate.mock.invocationCallOrder[0] ?? 0,
    );
  });

  it('goes back to the form without naming anything', async () => {
    show();
    type(field('Part'), 'blog');
    type(screen.getByRole('textbox', { name: 'Stage' }), 'dev');
    fireEvent.click(screen.getByRole('button', { name: 'Create environment' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Back' }));
    expect(field('Part').value).toBe('blog');
    expect(api.envsSetPart).not.toHaveBeenCalled();
  });
});
