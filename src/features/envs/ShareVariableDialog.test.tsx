import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { EnvDetail } from '@/bindings/EnvDetail';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { EnvVarInfo } from '@/bindings/EnvVarInfo';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { ShareVariableDialog } from './ShareVariableDialog';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(() => Promise.resolve({ state: 'unlocked' })),
  envsList: vi.fn(),
  envsSharedList: vi.fn(),
  projectsList: vi.fn(() => Promise.resolve([])),
  envsShareVar: vi.fn(),
  envsUnshareVar: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }));
vi.mock('sonner', () => ({ toast }));

// Radix measures the checkbox; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const summary = (id: string, name: string, extra: Partial<EnvSummary> = {}): EnvSummary => ({
  id,
  project: null,
  part: '',
  group: '',
  name,
  kind: 'local',
  variableCount: 1,
  secretCount: 1,
  inTrash: false,
  modified: null,
  ...extra,
});
const here = summary('env-1', 'dev');
const env: EnvDetail = { ...here, notes: '', variables: [], files: [], whileUnlocked: [] };
const token = (shared: string | null): EnvVarInfo => ({
  name: 'API_TOKEN',
  secret: true,
  note: '',
  empty: false,
  shared,
  unresolved: false,
});

function show(variable: EnvVarInfo) {
  api.envsList.mockResolvedValue([
    here,
    summary('env-2', 'test'),
    summary('env-3', 'prod', { kind: 'remote' }),
    summary('env-4', 'old', { inTrash: true }),
  ]);
  api.envsSharedList.mockResolvedValue([
    {
      id: 's1',
      name: 'API_TOKEN',
      empty: false,
      inTrash: false,
      users: [
        { envId: 'env-1', variable: 'API_TOKEN' },
        { envId: 'env-2', variable: 'API_TOKEN' },
      ],
    },
  ]);
  const onDone = vi.fn();
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <TooltipProvider>
        <Dialog open>
          <ShareVariableDialog env={env} variable={variable} onDone={onDone} />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
  return onDone;
}

afterEach(() => vi.clearAllMocks());

describe('sharing a variable', () => {
  it('shares it with the environments chosen, not those in the recycle bin', async () => {
    api.envsShareVar.mockResolvedValue(env);
    const onDone = show(token(null));
    const prod = await screen.findByRole('checkbox', { name: /prod/ });
    expect(screen.getByText('Remote')).toBeInTheDocument();
    expect(screen.queryByRole('checkbox', { name: /old/ })).toBeNull();
    expect(screen.queryByRole('button', { name: 'Use its own value here' })).toBeNull();
    fireEvent.click(prod);
    fireEvent.click(screen.getByRole('button', { name: 'Share' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsShareVar).toHaveBeenCalledWith('env-1', 'API_TOKEN', ['env-3']);
  });

  it('shows who uses a shared one, and gives this environment its own value', async () => {
    api.envsUnshareVar.mockResolvedValue(env);
    const onDone = show(token('s1'));
    const test = await screen.findByRole('checkbox', { name: /test/ });
    await vi.waitFor(() => expect(test).toBeDisabled());
    expect(screen.getByText('Uses it already')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Use its own value here' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsUnshareVar).toHaveBeenCalledWith('env-1', 'API_TOKEN');
  });
});
