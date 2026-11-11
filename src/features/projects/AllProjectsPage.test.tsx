import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RouterProvider } from '@/app/router';
import type { EnvFileReport } from '@/bindings/EnvFileReport';
import type { KeyView } from '@/bindings/KeyView';
import type { Project } from '@/bindings/Project';
import type { ProjectSuggestion } from '@/bindings/ProjectSuggestion';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { AllProjectsPage } from './AllProjectsPage';
import { projectKeys } from './queries';

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
  projectsSuggestions: vi.fn(),
  envsFilesStatus: vi.fn(),
  envsFilesRisks: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));
vi.mock('@/app/dialogs', () => ({
  useDialogs: () => ({ unlockVault: vi.fn(), generateKey: vi.fn() }),
}));
vi.mock('@/features/terminal/TerminalProvider', () => ({
  useTerminals: () => ({ open: vi.fn(), openLocal: vi.fn() }),
}));

type State = 'unlocked' | 'locked' | 'missing';

const key = { id: 'id_ed25519', name: 'id_ed25519', fingerprint: 'SHA256:a' } as KeyView;
const shop: Project = {
  id: 'p1',
  name: 'Shop',
  color: 'blue',
  folders: [],
  hosts: ['prod-api'],
  keys: [],
  environments: ['shop'],
  logins: [],
  hostsFile: [],
  modified: '2026-11-10T10:00:00Z',
};
const host = {
  id: 1,
  kind: 'host',
  patterns: ['prod-api'],
  isWildcard: false,
  hostName: null,
  user: null,
  port: null,
  proxyJump: null,
};

let client: QueryClient;

function show({
  state = 'unlocked' as State,
  projects = [] as Project[],
  keys = [key],
  hosts = [] as unknown[],
  suggestions,
}: {
  state?: State;
  projects?: Project[];
  keys?: KeyView[];
  hosts?: unknown[];
  suggestions?: ProjectSuggestion[];
} = {}) {
  api.vaultStatus.mockResolvedValue({ state });
  api.projectsList.mockResolvedValue(projects);
  api.config.mockResolvedValue({ view: { hosts, includes: [], revision: 'r' } });
  api.listKeys.mockResolvedValue({ keys });
  api.vaultAudit.mockResolvedValue({ state, findings: [] });
  // Found earlier, on the Suggestions page: the home only reads them.
  if (suggestions) client.setQueryData(projectKeys.suggestions, suggestions);
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <RouterProvider initial={{ page: 'projects' }}>
          <AllProjectsPage />
        </RouterProvider>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

const button = (name: string) => screen.findByRole('button', { name });
const shopCard = (open: HTMLElement) => {
  const card = open.closest('li');
  if (!card) throw new Error('no card');
  return card;
};
const isPrimary = (element: HTMLElement) => element.className.includes('accent-fill');

beforeEach(() => {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  api.envsList.mockResolvedValue([]);
  api.vaultEntries.mockResolvedValue([]);
  api.hostsFile.mockResolvedValue({ view: { entries: [] }, revision: 'r', readOnly: false });
  api.audit.mockResolvedValue({ findings: [] });
  api.leaksFindings.mockResolvedValue([]);
  api.projectsMissingFolders.mockResolvedValue([]);
  api.envsFilesStatus.mockResolvedValue([]);
  api.envsFilesRisks.mockResolvedValue([]);
});
afterEach(() => vi.clearAllMocks());

describe('the first run', () => {
  it('leads with Generate key while there are no keys, and never looks for suggestions itself', async () => {
    show({ keys: [] });
    expect(await screen.findByRole('heading', { name: 'Group your work into projects' }));
    const generate = await button('Generate key');
    expect(isPrimary(generate)).toBe(true);
    expect(isPrimary(await button('New project'))).toBe(false);
    // Looking reads code folders: it waits for a click.
    expect(await button('Look for projects')).toBeInTheDocument();
    expect(api.projectsSuggestions).not.toHaveBeenCalled();
    // Personal holds nothing: no card, no wall of zeros.
    expect(screen.queryByRole('button', { name: 'Open Personal' })).toBeNull();
  });

  it('leads with New project once there is a key, and shows Personal when it holds something', async () => {
    show({ hosts: [host] });
    await screen.findByRole('heading', { name: 'Group your work into projects' });
    expect(screen.getAllByRole('button', { name: 'New project' })).toHaveLength(1);
    expect(isPrimary(await button('New project'))).toBe(true);
    expect(screen.queryByRole('button', { name: 'Generate key' })).toBeNull();
    expect(await button('Open Personal')).toBeInTheDocument();
  });

  it('offers suggestions already found, with what Review opens', async () => {
    show({ suggestions: [{} as ProjectSuggestion, {} as ProjectSuggestion] });
    expect(await screen.findByText('2 suggested projects')).toBeInTheDocument();
    expect(await button('Review 2 suggested projects')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Look for projects' })).toBeNull();
  });

  it('asks for a vault first without one', async () => {
    show({ state: 'missing' });
    expect(isPrimary(await button('Create vault'))).toBe(true);
    expect(screen.queryByRole('button', { name: 'New project' })).toBeNull();
  });
});

describe('a locked vault', () => {
  it('shows only Unlock when this device has no copy of the projects', async () => {
    show({ state: 'locked', hosts: [host] });
    expect(
      await screen.findByText('The vault is locked. Unlock it to see your projects.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Unlock' })).toBeInTheDocument();
    expect(screen.queryByText('Group your work into projects')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Open Personal' })).toBeNull();
  });

  it('counts no environments or logins until it is unlocked', async () => {
    show({ state: 'locked', projects: [shop], hosts: [host] });
    expect(await button('Open Shop')).toBeInTheDocument();
    expect(await screen.findByText('1 host')).toBeInTheDocument();
    expect(screen.queryByText(/environment group/)).toBeNull();
  });
});

describe('a card', () => {
  it('says "No problems" only once the audit has answered', async () => {
    let answer: (report: { findings: [] }) => void = () => {};
    api.audit.mockReturnValue(new Promise((resolve) => (answer = resolve)));
    show({ projects: [shop], hosts: [host] });
    expect(await button('Open Shop')).toBeInTheDocument();
    expect(await button('Connect to prod-api')).toBeInTheDocument();
    expect(screen.queryByText('No problems')).toBeNull();
    answer({ findings: [] });
    expect(await screen.findAllByText('No problems')).not.toHaveLength(0);
  });

  it('counts its .env files that need attention among its problems', async () => {
    const status = {
      envId: 'env-1',
      label: 'shop',
      envName: 'dev',
      file: { folder: '~/code/shop', path: '.env' },
      location: '/code/shop/.env',
      state: { type: 'inSync' },
    } as const;
    const report: EnvFileReport = {
      ...status,
      projects: ['p1'],
      cloud: null,
      example: null,
      git: { state: 'tracked', repository: '/code/shop' },
    };
    api.envsFilesStatus.mockResolvedValue([status]);
    api.envsFilesRisks.mockResolvedValue([report]);
    show({ projects: [shop], hosts: [host] });
    const card = shopCard(await button('Open Shop'));
    expect(await within(card).findByText('1 .env file needs attention')).toBeInTheDocument();
    // Committed to Git, values included: said as critical, to screen readers too.
    expect(within(card).getByText('Critical:')).toBeInTheDocument();
    expect(within(card).getByText('.env')).toBeInTheDocument();
    expect(within(card).queryByText('No problems')).toBeNull();
  });

  it('says nothing of its problems while its .env files can’t be checked', async () => {
    api.envsFilesRisks.mockRejectedValue({ code: 'io', message: 'git failed' });
    show({ projects: [shop], hosts: [host] });
    const card = shopCard(await button('Open Shop'));
    expect(await button('Connect to prod-api')).toBeInTheDocument();
    await vi.waitFor(() => expect(api.envsFilesRisks).toHaveBeenCalled());
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(within(card).queryByText('No problems')).toBeNull();
  });
});
