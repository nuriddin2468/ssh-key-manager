import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RouterProvider } from '@/app/router';
import type { Project } from '@/bindings/Project';
import type { UnmanagedEnvFile } from '@/bindings/UnmanagedEnvFile';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { ProjectPage } from './ProjectPage';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  config: vi.fn(),
  listKeys: vi.fn(),
  envsList: vi.fn(),
  vaultEntries: vi.fn(),
  hostsFile: vi.fn(),
  audit: vi.fn(),
  vaultAudit: vi.fn(),
  leaksFindings: vi.fn(),
  projectsMissingFolders: vi.fn(),
  projectsPlaces: vi.fn(),
  projectsAddFolder: vi.fn(),
  projectsSuggestions: vi.fn(),
  envsFilesStatus: vi.fn(),
  envsFilesRisks: vi.fn(),
  envsFilesOverview: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));
vi.mock('@/app/dialogs', () => ({
  useDialogs: () => ({ unlockVault: vi.fn(), generateKey: vi.fn(), addHost: vi.fn() }),
}));
vi.mock('@/features/terminal/TerminalProvider', () => ({
  useTerminals: () => ({ open: vi.fn(), openLocal: vi.fn() }),
}));
// The dialog is the Files view's, tested there: here, which file it got.
vi.mock('@/features/envs/files/AdoptFileDialog', () => ({
  AdoptFileDialog: ({ found }: { found: UnmanagedEnvFile }) => <p>Adopting {found.file.path}</p>,
}));
const toast = vi.hoisted(() => ({
  info: vi.fn(),
  success: vi.fn(),
  error: vi.fn(),
  message: vi.fn(),
}));
vi.mock('sonner', () => ({ toast }));

const shop: Project = {
  id: 'p1',
  name: 'Shop',
  color: 'blue',
  folders: ['~/code/shop'],
  hosts: [],
  keys: [],
  environments: [],
  logins: [],
  hostsFile: [],
  parts: [],
  modified: '2026-11-10T10:00:00Z',
};

const found = (folder: string, path: string, git?: 'tracked'): UnmanagedEnvFile => ({
  project: 'p1',
  file: { folder, path },
  location: `${folder.replace('~', '/Users/me')}/${path}`,
  cloud: null,
  git: git ? { state: git, repository: '/Users/me/code/shop' } : null,
});

let client: QueryClient;

function show(project: Project, state: 'unlocked' | 'locked' = 'unlocked') {
  api.vaultStatus.mockResolvedValue({ state });
  api.projectsList.mockResolvedValue([project]);
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <RouterProvider initial={{ page: 'project', id: project.id }}>
          <ProjectPage id={project.id} />
        </RouterProvider>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

const environmentsCard = async () => {
  const heading = await screen.findByRole('heading', { name: 'Environments' });
  const card = heading.closest('section');
  if (!card) throw new Error('no card');
  return card;
};

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  api.config.mockResolvedValue({ view: { hosts: [], includes: [], revision: 'r' } });
  api.listKeys.mockResolvedValue({ keys: [] });
  api.envsList.mockResolvedValue([]);
  api.vaultEntries.mockResolvedValue([]);
  api.hostsFile.mockResolvedValue({ view: { entries: [] }, revision: 'r', readOnly: false });
  api.audit.mockResolvedValue({ findings: [] });
  api.vaultAudit.mockResolvedValue({ state: 'unlocked', findings: [] });
  api.leaksFindings.mockResolvedValue([]);
  api.projectsMissingFolders.mockResolvedValue([]);
  api.projectsPlaces.mockResolvedValue([]);
  api.envsFilesStatus.mockResolvedValue([]);
  api.envsFilesRisks.mockResolvedValue([]);
  api.envsFilesOverview.mockResolvedValue({ files: [], unmanaged: [], truncated: false });
});
afterEach(() => vi.clearAllMocks());

describe('the Environments card', () => {
  it('offers the .env files found in a project without environments', async () => {
    api.envsFilesOverview.mockResolvedValue({
      files: [],
      unmanaged: [found('~/code/shop', '.env', 'tracked')],
      truncated: false,
    });
    show(shop);
    const card = await environmentsCard();
    expect(within(card).getByText('.env')).toBeInTheDocument();
    expect(within(card).getByText('Not managed yet')).toBeInTheDocument();
    // Committed with its values: said on the row.
    expect(within(card).getByText('Committed to Git')).toBeInTheDocument();
    expect(api.envsFilesOverview).toHaveBeenCalledWith('p1');

    fireEvent.click(within(card).getByRole('button', { name: 'Take .env under management' }));
    expect(await screen.findByText('Adopting .env')).toBeInTheDocument();
  });

  it('names the folder of a found file when the project has several', async () => {
    api.envsFilesOverview.mockResolvedValue({
      files: [],
      unmanaged: [found('~/code/shop-web', 'apps/admin/.env.local')],
      truncated: false,
    });
    show({ ...shop, folders: ['~/code/shop', '~/code/shop-web'] });
    const card = await environmentsCard();
    expect(within(card).getByText('apps/admin/.env.local')).toBeInTheDocument();
    expect(within(card).getByText('In shop-web · not managed yet')).toBeInTheDocument();
  });

  it('looks for nothing while the vault is locked', async () => {
    show(shop, 'locked');
    expect(await screen.findByRole('heading', { name: 'Folders' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Environments' })).toBeNull();
    expect(api.envsFilesOverview).not.toHaveBeenCalled();
  });
});

describe('adding a folder', () => {
  it('says what .env files the new folder has, and takes a single one from the toast', async () => {
    // No folders and no hosts: the page offers Add folder as a button.
    const empty = { ...shop, folders: [], keys: ['SHA256:a'] };
    const saved = { ...shop, keys: ['SHA256:a'] };
    api.projectsAddFolder.mockResolvedValue(saved);
    api.envsFilesOverview.mockResolvedValue({
      files: [],
      unmanaged: [found('~/code/shop', '.env')],
      truncated: false,
    });
    show(empty);
    fireEvent.click(await screen.findByRole('button', { name: 'Folder…' }));
    await vi.waitFor(() => expect(toast.info).toHaveBeenCalled());
    const [text, options] = toast.info.mock.calls[0] ?? [];
    expect(text).toBe('Found a .env file in shop');
    expect(options.description).toBe(
      'It’s on the Environments card, ready to take under management.',
    );
    expect(options.action.label).toBe('Take under management…');
  });

  it('says nothing when the new folder has no .env files', async () => {
    const empty = { ...shop, folders: [], keys: ['SHA256:a'] };
    api.projectsAddFolder.mockResolvedValue({ ...shop, keys: ['SHA256:a'] });
    show(empty);
    fireEvent.click(await screen.findByRole('button', { name: 'Folder…' }));
    await vi.waitFor(() => expect(api.envsFilesOverview).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(toast.info).not.toHaveBeenCalled();
  });
});
