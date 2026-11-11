import { fireEvent, screen } from '@testing-library/react';
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
afterEach(() => vi.clearAllMocks());

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
