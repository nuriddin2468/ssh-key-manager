import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { EnvFileCheck } from '@/bindings/EnvFileCheck';
import type { EnvFileStatus } from '@/bindings/EnvFileStatus';
import type { EnvSummary } from '@/bindings/EnvSummary';
import type { Project } from '@/bindings/Project';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { BindFileDialog } from './BindFileDialog';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsFilesCheck: vi.fn(),
  envsFilesBind: vi.fn(),
  envsFilesIgnore: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));
const toast = vi.hoisted(() => ({ success: vi.fn(), warning: vi.fn(), error: vi.fn() }));
vi.mock('sonner', () => ({ toast }));

// Radix measures radio items; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const env = {
  id: 'env-1',
  // In Shop: its folders are the ones offered.
  project: 'p1',
  part: '',
  group: 'shop-api',
  name: 'dev',
  kind: 'local',
  variableCount: 2,
  secretCount: 1,
  inTrash: false,
} as EnvSummary;
const shop = {
  id: 'p1',
  name: 'Shop',
  folders: ['~/code/shop-api'],
  environments: ['env-1'],
} as Project;
// `apps/web` isn't made yet: Git was asked from the project's folder.
const file = { folder: '~/code/shop-api', path: 'apps/web/.env.local' };
const check: EnvFileCheck = {
  file,
  location: '/code/shop-api/apps/web/.env.local',
  folderHere: false,
  git: { state: 'untracked', repository: '/code/shop-api' },
  cloud: null,
};
const waiting: EnvFileStatus = {
  envId: 'env-1',
  label: 'shop-api',
  envName: 'dev',
  file,
  level: 'always',
  location: '/code/shop-api/apps/web/.env.local',
  state: { type: 'folderMissing' },
};

function show(shown: EnvSummary = env) {
  api.vaultStatus.mockResolvedValue({ state: 'unlocked' });
  api.projectsList.mockResolvedValue([shop]);
  api.envsFilesBind.mockResolvedValue(waiting);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onDone = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <Dialog open>
          <BindFileDialog env={shown} bound={[]} onDone={onDone} />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
  return onDone;
}

async function addFile() {
  const field = await screen.findByRole('textbox', { name: 'File' });
  fireEvent.change(field, { target: { value: file.path } });
  fireEvent.click(screen.getByRole('button', { name: 'Add file' }));
}

afterEach(() => vi.clearAllMocks());

describe('writing an environment to a file whose folder isn’t made yet', () => {
  it('says the file is added, to be written once its folder exists', async () => {
    api.envsFilesCheck.mockResolvedValue({
      ...check,
      git: { state: 'ignored', repository: '/code/shop-api' },
    });
    const onDone = show();
    await addFile();
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsFilesBind).toHaveBeenCalledWith('env-1', file, 'always');
    expect(toast.success).toHaveBeenCalledWith(
      '.env.local is added. It’s written once its folder exists.',
    );
  });

  it('adds it to .gitignore first when asked', async () => {
    api.envsFilesCheck.mockResolvedValue(check);
    api.envsFilesIgnore.mockResolvedValue({ state: 'ignored', repository: '/code/shop-api' });
    const onDone = show();
    await addFile();
    fireEvent.click(await screen.findByRole('button', { name: 'Add to .gitignore and write' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsFilesIgnore).toHaveBeenCalledWith('env-1', file);
    expect(toast.success).toHaveBeenCalledWith(
      '.env.local is added. It’s written once its folder exists.',
    );
    expect(toast.warning).not.toHaveBeenCalled();
  });

  it('says .gitignore wasn’t changed when that failed, not the error itself', async () => {
    api.envsFilesCheck.mockResolvedValue(check);
    api.envsFilesIgnore.mockRejectedValue({
      code: 'not_found',
      message: 'not found: /code/shop-api/apps/web',
    });
    const onDone = show();
    await addFile();
    fireEvent.click(await screen.findByRole('button', { name: 'Add to .gitignore and write' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(toast.warning).toHaveBeenCalledWith(
      '.env.local is added, but .gitignore couldn’t be changed. Add the file to it yourself before you commit.',
    );
    // Nothing that sounds like all is well, nor "the file no longer exists".
    expect(toast.success).not.toHaveBeenCalled();
    expect(toast.error).not.toHaveBeenCalled();
  });
});

describe('how long a file stays on disk', () => {
  it('is all the time unless the user picks only while the vault is unlocked', async () => {
    api.envsFilesCheck.mockResolvedValue({
      ...check,
      git: { state: 'ignored', repository: '/code/shop-api' },
    });
    const onDone = show();
    fireEvent.click(await screen.findByRole('radio', { name: 'Only while unlocked' }));
    await addFile();
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsFilesCheck).toHaveBeenCalledWith('env-1', file, 'whileUnlocked');
    expect(api.envsFilesBind).toHaveBeenCalledWith('env-1', file, 'whileUnlocked');
  });

  it('is only while the vault is unlocked for a remote environment, which says why', async () => {
    api.envsFilesCheck.mockResolvedValue({
      ...check,
      git: { state: 'ignored', repository: '/code/shop-api' },
    });
    const onDone = show({ ...env, name: 'staging', kind: 'remote' });
    expect(await screen.findByRole('radio', { name: 'All the time' })).toBeDisabled();
    expect(screen.getByRole('radio', { name: 'Only while unlocked' })).toBeChecked();
    expect(screen.getByText(/staging is remote$/)).toBeInTheDocument();
    await addFile();
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsFilesBind).toHaveBeenCalledWith('env-1', file, 'whileUnlocked');
  });
});
