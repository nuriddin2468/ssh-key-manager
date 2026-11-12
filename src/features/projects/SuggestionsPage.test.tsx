import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { RouterProvider } from '@/app/router';
import type { ProjectSuggestion } from '@/bindings/ProjectSuggestion';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { ALL, SHOP, SITE, stubPointer } from '@/features/envs/testing';
import { SuggestionsPage } from './SuggestionsPage';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  projectsSuggestions: vi.fn(),
  projectsAcceptSuggestion: vi.fn(),
  listKeys: vi.fn(),
  vaultEntries: vi.fn(),
  envsList: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));
vi.mock('@/app/dialogs', () => ({ useDialogs: () => ({ unlockVault: vi.fn() }) }));

/** Site has one part, `marketing-site`; Personal's `scripts` would be its second. */
const toSite: ProjectSuggestion = {
  key: 'site',
  name: 'Site',
  color: 'violet',
  existing: SITE.id,
  reasons: [{ type: 'environments', group: 'scripts' }],
  folders: ['~/code/site'],
  hosts: [],
  keys: [],
  environments: ['m1'],
  logins: [],
  hostsFile: [],
};

beforeAll(stubPointer);
beforeEach(() => {
  api.vaultStatus.mockResolvedValue({ state: 'unlocked' });
  api.projectsList.mockResolvedValue([SITE, SHOP]);
  api.projectsSuggestions.mockResolvedValue([toSite]);
  api.listKeys.mockResolvedValue({ keys: [] });
  api.vaultEntries.mockResolvedValue([]);
  api.envsList.mockResolvedValue(ALL);
  api.projectsAcceptSuggestion.mockResolvedValue(SITE);
});
afterEach(() => vi.clearAllMocks());

function show() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <RouterProvider initial={{ page: 'suggestions' }}>
          <SuggestionsPage />
        </RouterProvider>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

const field = () => screen.getByRole('textbox', { name: 'Part of its other environments' });

describe('adding a suggestion’s environments to a project of one part', () => {
  it('names its part first, and sends the name with the rest', async () => {
    show();
    // Personal's environment, by its part and stage, not its id.
    await screen.findByText('scripts · local');
    fireEvent.click(await screen.findByRole('button', { name: 'Add to Site' }));

    expect(await screen.findByText('Site gets a second part')).toBeInTheDocument();
    expect(api.projectsAcceptSuggestion).not.toHaveBeenCalled();
    expect(field()).toHaveValue('marketing-site');
    // The part it brings can't be the name.
    fireEvent.change(field(), { target: { value: 'scripts' } });
    fireEvent.click(screen.getByRole('button', { name: 'Name it and continue' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Use a name other than scripts.');
    expect(api.projectsAcceptSuggestion).not.toHaveBeenCalled();

    // Enter in the field goes on, as the button does.
    fireEvent.change(field(), { target: { value: 'site' } });
    fireEvent.submit(field());
    await vi.waitFor(() => expect(api.projectsAcceptSuggestion).toHaveBeenCalled());
    expect(api.projectsAcceptSuggestion).toHaveBeenCalledWith(
      'site',
      { name: 'Site', color: 'violet' },
      [
        { type: 'folder', path: '~/code/site' },
        { type: 'environment', id: 'm1' },
      ],
      { ids: ['e1', 'e2', 'e9'], part: 'site' },
    );
  });

  it('goes back to the card, and adds at once without the environment', async () => {
    show();
    await screen.findByText('scripts · local');
    fireEvent.click(await screen.findByRole('button', { name: 'Add to Site' }));
    await screen.findByText('Site gets a second part');
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));

    fireEvent.click(screen.getByRole('checkbox', { name: 'scripts · local' }));
    fireEvent.click(screen.getByRole('button', { name: 'Add to Site' }));
    await vi.waitFor(() => expect(api.projectsAcceptSuggestion).toHaveBeenCalled());
    expect(screen.queryByText('Site gets a second part')).toBeNull();
    expect(api.projectsAcceptSuggestion).toHaveBeenCalledWith(
      'site',
      { name: 'Site', color: 'violet' },
      [{ type: 'folder', path: '~/code/site' }],
      null,
    );
  });
});
