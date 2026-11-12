import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AgentRules } from '@/bindings/AgentRules';
import type { AgentRulesView } from '@/bindings/AgentRulesView';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { AgentRulesDialog } from './AgentRulesDialog';

const api = vi.hoisted(() => ({
  envsAgentsAdd: vi.fn(),
  envsAgentsDecline: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));
vi.mock('@/api/queries', () => ({
  invalidateAll: vi.fn(() => Promise.resolve()),
  queryClient: { invalidateQueries: vi.fn(() => Promise.resolve()) },
  useVaultStatus: () => ({ data: { state: 'unlocked' } }),
}));
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }));
vi.mock('sonner', () => ({ toast }));

// Radix measures the checkbox; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const rules = (tool: AgentRules['tool'], file: string, extra: Partial<AgentRules> = {}) => ({
  tool,
  file,
  exists: false,
  missing: ['/.env'],
  found: false,
  problem: null,
  ...extra,
});

const view: AgentRulesView = {
  folder: '~/code/shop',
  location: '/Users/dev/code/shop',
  files: ['.env'],
  tools: [
    rules('claudeCode', '.claude/settings.local.json', { found: true, missing: ['Read(/.env)'] }),
    rules('cursor', '.cursorignore', { found: true, exists: true, missing: [] }),
    rules('aider', '.aiderignore'),
    rules('geminiCli', '.geminiignore', { problem: 'link' }),
  ],
  choice: null,
};

function show(shown = view) {
  const onDone = vi.fn();
  const client = new QueryClient();
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <Dialog open>
          <AgentRulesDialog project="p1" view={shown} onDone={onDone} />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
  return onDone;
}

afterEach(() => vi.clearAllMocks());

describe('AI tools’ ignore rules for a folder', () => {
  it('offers the tools used here whose files lack lines, and adds only those chosen', async () => {
    api.envsAgentsAdd.mockResolvedValue(view);
    const onDone = show();
    const claude = screen.getByRole('checkbox', { name: /Claude Code/ });
    expect(claude).toBeChecked();
    expect(screen.getByText('Read(/.env)')).toBeInTheDocument();
    // Cursor ignores them already: nothing to choose.
    expect(screen.getByRole('checkbox', { name: /Cursor/ })).toBeDisabled();
    expect(screen.getByText('Ignores these files already')).toBeInTheDocument();
    // The others wait behind a button.
    expect(screen.queryByRole('checkbox', { name: /Aider/ })).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: '2 other tools' }));
    const aider = screen.getByRole('checkbox', { name: /Aider/ });
    expect(aider).not.toBeChecked();
    // One the app can't change says why.
    expect(screen.getByRole('checkbox', { name: /Gemini CLI/ })).toBeDisabled();
    expect(screen.getByText(/A symbolic link/)).toBeInTheDocument();
    fireEvent.click(aider);
    fireEvent.click(screen.getByRole('button', { name: 'Add lines' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsAgentsAdd).toHaveBeenCalledWith('p1', '~/code/shop', ['claudeCode', 'aider']);
  });

  it('remembers a no for the folder, and asks it only once', async () => {
    api.envsAgentsDecline.mockResolvedValue({ ...view, choice: { type: 'declined' } });
    const onDone = show();
    fireEvent.click(screen.getByRole('button', { name: 'Not for this folder' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsAgentsDecline).toHaveBeenCalledWith('p1', '~/code/shop');
  });

  it('doesn’t ask again where the user said already', () => {
    show({ ...view, choice: { type: 'added', tools: ['claudeCode'] } });
    expect(screen.queryByRole('button', { name: 'Not for this folder' })).toBeNull();
  });
});
