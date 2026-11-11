import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RenamePartDialog } from './RenamePartDialog';
import { ALL, answer, renderIn, summary } from './testing';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsSetPart: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

// Shop's `web` has a prod; a second `admin` has a dev, as `api` has.
const SHOP = [...ALL, summary('s3', 'p-shop', 'admin', 'dev')];

function show(env: ReturnType<typeof summary>, all = SHOP) {
  answer(api);
  api.envsSetPart.mockResolvedValue(undefined);
  const onDone = vi.fn();
  renderIn(<RenamePartDialog env={env} all={all} onDone={onDone} />);
  return onDone;
}

const field = () => screen.getByRole('textbox', { name: 'Part' });
const rename = () => fireEvent.click(screen.getByRole('button', { name: 'Rename' }));

afterEach(() => vi.clearAllMocks());

describe('renaming a part', () => {
  it('renames every stage of it, those in the recycle bin too', async () => {
    const onDone = show(ALL[0] as ReturnType<typeof summary>);
    fireEvent.change(field(), { target: { value: 'site' } });
    rename();
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsSetPart).toHaveBeenCalledWith(['e1', 'e2', 'e9'], 'site');
  });

  it('says which stage the other part has already, and renames nothing', async () => {
    show(SHOP[6] as ReturnType<typeof summary>);
    fireEvent.change(field(), { target: { value: 'API' } });
    rename();
    await vi.waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent('Shop · API already has dev.'),
    );
    expect(api.envsSetPart).not.toHaveBeenCalled();
  });

  it('says that a name the project has joins the two parts', async () => {
    const onDone = show(ALL[4] as ReturnType<typeof summary>);
    fireEvent.change(field(), { target: { value: 'api' } });
    expect(field()).toHaveAccessibleDescription('api already exists: the two parts become one.');
    rename();
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsSetPart).toHaveBeenCalledWith(['s2'], 'api');
  });

  it('says a stage the backend found there', async () => {
    show(ALL[4] as ReturnType<typeof summary>);
    api.envsSetPart.mockRejectedValue({ code: 'already_exists', message: 'front / prod' });
    fireEvent.change(field(), { target: { value: 'front' } });
    rename();
    await vi.waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(
        'Shop · front already has one of these stages. Choose another name.',
      ),
    );
  });
});
