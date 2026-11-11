import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EnvList } from './EnvList';
import { sectionsOf, showsParts, trashed } from './model';
import { ALL, answer, renderIn } from './testing';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsFilesStatus: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const NAMES = new Map([
  ['p-site', 'Site'],
  ['p-shop', 'Shop'],
]);

function show() {
  answer(api);
  // Shop's `api` writes to one file.
  api.envsFilesStatus.mockResolvedValue([
    {
      envId: 's1',
      label: 'Shop · api',
      envName: 'dev',
      file: { folder: '~/code/shop/', path: 'api/.env' },
      location: '/code/shop/api/.env',
      state: { type: 'inSync' },
    },
  ]);
  const onNew = vi.fn();
  renderIn(
    <EnvList
      sections={sectionsOf(ALL, NAMES)}
      names={NAMES}
      trash={trashed(ALL)}
      selectedId="s1"
      query=""
      showsParts={(project) => showsParts(ALL, project)}
      onSelect={() => {}}
      onNew={onNew}
    />,
    false,
  );
  return onNew;
}

afterEach(() => vi.clearAllMocks());

describe('the environments list', () => {
  it('lists Personal, then projects, with parts as headings only where there are two', async () => {
    show();
    const sections = screen.getAllByRole('region');
    expect(sections.map((section) => section.getAttribute('aria-label'))).toEqual([
      'Personal',
      'Shop',
      'Site',
    ]);
    const shop = screen.getByRole('region', { name: 'Shop' });
    expect(
      within(shop)
        .getAllByRole('heading', { level: 3 })
        .map((heading) => heading.textContent),
    ).toEqual([expect.stringMatching(/^api/), 'web']);
    // The file a part's stages share.
    expect(await within(shop).findByText('~/code/shop/api/.env')).toBeInTheDocument();
    // A row says its part when parts show.
    expect(within(shop).getByRole('button', { name: /^dev, api/ })).toBeInTheDocument();
    // Site's one part isn't shown.
    const site = screen.getByRole('region', { name: 'Site' });
    expect(within(site).queryByRole('heading', { level: 3 })).not.toBeInTheDocument();
    expect(within(site).getByText('2 environments')).toHaveClass('sr-only');
  });

  it('makes a new environment in a section’s project', () => {
    const onNew = show();
    fireEvent.click(screen.getByRole('button', { name: 'New environment in Shop' }));
    expect(onNew).toHaveBeenCalledWith('p-shop');
    fireEvent.click(screen.getByRole('button', { name: 'New environment in Personal' }));
    expect(onNew).toHaveBeenCalledWith(null);
  });
});
