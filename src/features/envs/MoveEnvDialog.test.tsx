import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { MoveEnvDialog } from './MoveEnvDialog';
import { ALL, answer, detailOf, renderIn, stubPointer, summary } from './testing';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsList: vi.fn(),
  envsFilesOverview: vi.fn(),
  envsUpdate: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

function show(env = ALL[5] as ReturnType<typeof summary>) {
  answer(api);
  api.envsUpdate.mockResolvedValue(detailOf(env));
  const onDone = vi.fn();
  renderIn(<MoveEnvDialog env={detailOf(env)} all={ALL} onDone={onDone} />);
  return onDone;
}

const part = () => screen.getByRole('textbox', { name: 'Part' }) as HTMLInputElement;
const move = () => screen.getByRole('button', { name: 'Move' });
async function choose(project: string) {
  fireEvent.keyDown(screen.getByRole('combobox', { name: 'Project' }), { key: 'ArrowDown' });
  fireEvent.click(await screen.findByRole('option', { name: project }));
}

beforeAll(stubPointer);
afterEach(() => vi.clearAllMocks());

describe('moving an environment to another project', () => {
  it('goes into the project’s only part, asking nothing', async () => {
    const onDone = show();
    expect(move()).toBeDisabled();
    await choose('Site');
    expect(part().value).toBe('marketing-site');
    fireEvent.click(move());
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsUpdate).toHaveBeenCalledWith(
      'm1',
      { project: 'p-site', part: 'marketing-site', name: 'local', notes: '' },
      null,
    );
  });

  it('is in its own part again back in its own project', async () => {
    show();
    await choose('Site');
    await choose('Personal');
    expect(part().value).toBe('scripts');
    expect(move()).toBeDisabled();
  });

  it('names the project’s part first when it brings a second, in the same save', async () => {
    const onDone = show();
    await choose('Site');
    fireEvent.change(part(), { target: { value: 'tools' } });
    fireEvent.click(move());
    expect(await screen.findByText('Site gets a second part')).toBeInTheDocument();
    fireEvent.change(screen.getByRole('textbox', { name: 'Part of its other environments' }), {
      target: { value: 'site' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Name it and continue' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsUpdate).toHaveBeenCalledWith(
      'm1',
      { project: 'p-site', part: 'tools', name: 'local', notes: '' },
      { ids: ['e1', 'e2', 'e9'], part: 'site' },
    );
  });

  it('says a stage the part has already', async () => {
    show(summary('m2', null, 'scripts', 'dev'));
    await choose('Site');
    fireEvent.click(move());
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Site · marketing-site already has dev.',
    );
    expect(api.envsUpdate).not.toHaveBeenCalled();
  });
});
