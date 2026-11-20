import { fireEvent, screen, within } from '@testing-library/react';
import { toast } from 'sonner';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { answer, renderIn, stubPointer } from '../testing';
import { AdoptFileDialog } from './AdoptFileDialog';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsList: vi.fn(),
  envsFilesOverview: vi.fn(),
  envsFilesStatus: vi.fn(),
  envsFilesAdoptPreview: vi.fn(),
  envsFilesAdopt: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const file = { folder: '~/code/site', path: 'blog/.env' };
const found = { project: 'p-site', file, location: '/code/site/blog/.env', cloud: null, git: null };

function show() {
  answer(api);
  api.envsFilesAdoptPreview.mockResolvedValue({
    suggestedProject: 'blog',
    suggestedName: '',
    variables: [{ name: 'API_URL', line: 1, secret: false, empty: false, multiline: false }],
    problems: [],
  });
  api.envsFilesAdopt.mockResolvedValue({ id: 'e3', added: 1, replaced: 0 });
  const onDone = vi.fn();
  renderIn(<AdoptFileDialog found={found} onDone={onDone} />);
  return onDone;
}

beforeAll(stubPointer);
afterEach(() => vi.restoreAllMocks());

describe('taking a file under management in a new environment', () => {
  it('names the project’s part first when the file’s part is a second', async () => {
    const onDone = show();
    const part = await screen.findByRole('textbox', { name: 'Part' });
    // The project's only part to start with; the file's folder is offered.
    await vi.waitFor(() => expect(part).toHaveValue('marketing-site'));
    fireEvent.change(part, { target: { value: 'blog' } });
    fireEvent.click(screen.getByRole('button', { name: 'Take under management' }));

    expect(await screen.findByText('Site gets a second part')).toBeInTheDocument();
    // Escape goes back to the form, not out of the dialog.
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(screen.getByRole('textbox', { name: 'Part' })).toHaveValue('blog');
    fireEvent.click(screen.getByRole('button', { name: 'Take under management' }));
    // The name kept: nothing renamed.
    fireEvent.click(await screen.findByRole('button', { name: 'Name it and continue' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsFilesAdopt).toHaveBeenCalledWith(
      'p-site',
      file,
      { type: 'new', project: 'p-site', part: 'blog', name: 'dev' },
      [{ name: 'API_URL', secret: false }],
      null,
    );
  });
});

describe('a file taken under management that isn’t written', () => {
  it('says the environment is saved and the file isn’t, not that the save failed', async () => {
    const success = vi.spyOn(toast, 'success');
    const warning = vi.spyOn(toast, 'warning');
    const onDone = show();
    api.envsFilesAdopt.mockResolvedValue({
      id: 'e3',
      added: 1,
      replaced: 0,
      fileProblem: { code: 'io', message: 'disk full' },
    });
    const part = await screen.findByRole('textbox', { name: 'Part' });
    await vi.waitFor(() => expect(part).toHaveValue('marketing-site'));
    // Site's part has a dev already.
    fireEvent.change(screen.getByRole('textbox', { name: 'Environment' }), {
      target: { value: 'local' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Take under management' }));

    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(warning).toHaveBeenCalledWith(
      'Site · marketing-site · local is saved, but .env wasn’t written',
      expect.objectContaining({
        description:
          'The file could not be read or written. disk full How the file stands shows under the environment.',
      }),
    );
    expect(success).not.toHaveBeenCalled();
  });

  it('says a save that failed in the dialog and keeps it open', async () => {
    const onDone = show();
    api.envsFilesAdopt.mockRejectedValue({ code: 'io', message: 'disk full' });
    const part = await screen.findByRole('textbox', { name: 'Part' });
    await vi.waitFor(() => expect(part).toHaveValue('marketing-site'));
    // Site's part has a dev already.
    fireEvent.change(screen.getByRole('textbox', { name: 'Environment' }), {
      target: { value: 'local' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Take under management' }));

    const dialog = screen.getByRole('dialog');
    expect(await within(dialog).findByText('disk full')).toBeInTheDocument();
    expect(within(dialog).getByText('The file could not be read or written.')).toBeInTheDocument();
    expect(onDone).not.toHaveBeenCalled();
  });
});
