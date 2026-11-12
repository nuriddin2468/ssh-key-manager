import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ImportEnvDialog } from './ImportEnvDialog';
import { ALL, answer, renderIn, stubPointer } from './testing';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsList: vi.fn(),
  envsFilesOverview: vi.fn(),
  envsImportPick: vi.fn(),
  envsImport: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const variable = { name: 'API_URL', line: 1, secret: false, empty: false, multiline: false };

beforeAll(stubPointer);
afterEach(() => vi.clearAllMocks());

describe('importing a .env into a new environment', () => {
  it('names the project’s part first when the new one brings a second', async () => {
    answer(api);
    api.envsImportPick.mockResolvedValue({
      path: '/code/site/blog/.env',
      preview: {
        suggestedProject: 'blog',
        suggestedName: 'dev',
        variables: [variable],
        problems: [],
      },
    });
    api.envsImport.mockResolvedValue({ id: 'e3', added: 1, replaced: 0 });
    const onDone = vi.fn();
    renderIn(<ImportEnvDialog all={ALL} onDone={onDone} />);
    fireEvent.click(screen.getByRole('button', { name: 'Choose file…' }));
    await screen.findByText(/1 variable found/);
    fireEvent.keyDown(screen.getByRole('combobox', { name: 'Project' }), { key: 'ArrowDown' });
    fireEvent.click(await screen.findByRole('option', { name: 'Site' }));
    fireEvent.click(screen.getByRole('button', { name: 'Import 1 variable' }));

    expect(await screen.findByText('Site gets a second part')).toBeInTheDocument();
    fireEvent.change(screen.getByRole('textbox', { name: 'Part of its other environments' }), {
      target: { value: 'site' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Name it and continue' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalledWith('e3'));
    expect(api.envsImport).toHaveBeenCalledWith(
      { type: 'new', project: 'p-site', part: 'blog', name: 'dev' },
      [{ name: 'API_URL', secret: false }],
      { ids: ['e1', 'e2', 'e9'], part: 'site' },
    );
  });
});
