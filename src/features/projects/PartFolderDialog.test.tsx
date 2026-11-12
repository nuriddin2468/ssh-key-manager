import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { Project } from '@/bindings/Project';
import { renderIn, stubPointer } from '@/features/envs/testing';
import { PartFolderDialog } from './PartFolderDialog';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  envsFilesOverview: vi.fn(),
  projectsPlaces: vi.fn(),
  projectsSetPartFolder: vi.fn(),
  projectsPickPartFolder: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const shop = {
  id: 'p-shop',
  name: 'Shop',
  color: 'blue',
  folders: ['~/code/shop'],
  parts: [],
} as unknown as Project;

function show() {
  api.vaultStatus.mockResolvedValue({ state: 'unlocked' });
  api.envsFilesOverview.mockResolvedValue({ files: [], unmanaged: [], truncated: false });
  api.projectsPlaces.mockResolvedValue([
    {
      folder: '~/code/shop',
      path: 'apps/web',
      parts: [
        {
          part: 'web',
          source: 'file',
          environments: ['w1'],
          local: 'w1',
          automatic: { folder: '~/code/shop', path: 'apps/web' },
          automaticFromFile: true,
          suggested: [{ folder: '~/code/shop', path: 'apps/web' }],
        },
      ],
      terminal: ['w1'],
      missing: false,
    },
  ]);
  api.projectsSetPartFolder.mockResolvedValue(shop);
  const onDone = vi.fn();
  renderIn(<PartFolderDialog project={shop} part="web" onDone={onDone} />);
  return onDone;
}

beforeAll(stubPointer);
afterEach(() => vi.clearAllMocks());

describe('a part’s folder', () => {
  it('says where automatic leads, and saves a folder chosen instead', async () => {
    const onDone = show();
    expect(await screen.findByRole('radio', { name: 'Automatic' })).toBeChecked();
    expect(screen.getByText('apps/web, where its .env file is')).toBeInTheDocument();
    // Nothing chosen yet: nothing to save.
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled();
    fireEvent.click(screen.getByRole('radio', { name: '~/code/shop' }));
    fireEvent.click(screen.getByRole('button', { name: 'Save changes' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.projectsSetPartFolder).toHaveBeenCalledWith('p-shop', 'web', {
      folder: '~/code/shop',
      path: '',
    });
  });

  it('says so when the folder picked isn’t in the project', async () => {
    show();
    api.projectsPickPartFolder.mockRejectedValue({ code: 'invalid_input', message: 'outside' });
    fireEvent.click(await screen.findByRole('button', { name: 'Choose another folder…' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Choose a folder inside one of the project’s folders.',
    );
  });
});
