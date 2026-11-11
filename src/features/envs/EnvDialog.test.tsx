import { fireEvent, screen, within } from '@testing-library/react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { EnvDialog } from './EnvDialog';
import { ALL, answer, detailOf, renderIn, stubPointer, summary } from './testing';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsList: vi.fn(),
  envsFilesOverview: vi.fn(),
  envsCreate: vi.fn(),
  envsUpdate: vi.fn(),
  envsSetPart: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const made = detailOf(summary('e3', 'p-site', 'blog', 'dev'));

function show({
  env = null,
  defaultProject = 'p-site',
}: {
  env?: ReturnType<typeof detailOf> | null;
  defaultProject?: string | null;
} = {}) {
  answer(api);
  api.envsCreate.mockResolvedValue(made);
  api.envsUpdate.mockImplementation(async (id: string) => detailOf(summary(id, null, '', 'x')));
  const onDone = vi.fn();
  renderIn(<EnvDialog env={env} all={ALL} defaultProject={defaultProject} onDone={onDone} />);
  return onDone;
}

/** Once the projects' names are in: `project`'s parts are offered. */
const named = (project = 'Site') => screen.findByRole('group', { name: `In ${project}:` });

const part = () => screen.getByRole('textbox', { name: 'Part' }) as HTMLInputElement;
const stage = () => screen.getByRole('textbox', { name: 'Stage' }) as HTMLInputElement;
const type = (input: HTMLElement, value: string) => fireEvent.change(input, { target: { value } });
const click = (name: string) => fireEvent.click(screen.getByRole('button', { name }));
const blogDev = () => {
  type(part(), 'blog');
  type(stage(), 'dev');
  click('Create environment');
};
const input = { project: 'p-site', part: 'blog', name: 'dev', notes: '' };

beforeAll(stubPointer);
afterEach(() => vi.clearAllMocks());

describe('a new environment', () => {
  it('starts in the project’s only part, and offers its parts and none', async () => {
    show();
    expect(part().value).toBe('marketing-site');
    const offered = await named();
    expect(within(offered).getByRole('button', { name: 'marketing-site' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    fireEvent.click(within(offered).getByRole('button', { name: 'No part' }));
    expect(part().value).toBe('');
  });

  it('takes the only part of the project it is moved to, none with two', async () => {
    show();
    fireEvent.keyDown(screen.getByRole('combobox', { name: 'Project' }), { key: 'ArrowDown' });
    fireEvent.click(await screen.findByRole('option', { name: 'Shop' }));
    expect(part().value).toBe('');
    fireEvent.keyDown(screen.getByRole('combobox', { name: 'Project' }), { key: 'ArrowDown' });
    fireEvent.click(await screen.findByRole('option', { name: 'Personal' }));
    expect(part().value).toBe('scripts');
  });

  it('says where KeePassXC shows it, Personal’s without a part in its own folder', () => {
    show({ defaultProject: null });
    type(part(), '');
    type(stage(), 'local');
    expect(
      screen.getByText('KeePassXC shows it as Environments / Personal / local'),
    ).toBeInTheDocument();
  });

  it('says a stage the part has already, and makes nothing', async () => {
    show();
    await named();
    type(stage(), 'dev');
    click('Create environment');
    expect(screen.getByText('Site · marketing-site already has dev.')).toBeInTheDocument();
    expect(api.envsCreate).not.toHaveBeenCalled();
  });

  it('names the part a project had when it gets a second, in the same save', async () => {
    const onDone = show();
    await named();
    blogDev();

    expect(screen.getByText('Site gets a second part')).toBeInTheDocument();
    const first = screen.getByRole('textbox', { name: 'Part of its other environments' });
    expect(first).toHaveValue('marketing-site');
    // Its KeePassXC folder's name: the hint says where it comes from.
    expect(first).toHaveAccessibleDescription(/name of their folder in KeePassXC/);
    // Nothing said before a try.
    expect(screen.getByRole('alert')).toBeEmptyDOMElement();
    type(first, 'Blog');
    click('Name it and continue');
    expect(screen.getByRole('alert')).toHaveTextContent('Use a name other than blog.');
    expect(api.envsCreate).not.toHaveBeenCalled();

    type(first, 'site');
    click('Name it and continue');
    await vi.waitFor(() => expect(onDone).toHaveBeenCalledWith('e3'));
    // The stage in the recycle bin takes the name too.
    expect(api.envsCreate).toHaveBeenCalledWith(input, { ids: ['e1', 'e2', 'e9'], part: 'site' });
    expect(api.envsSetPart).not.toHaveBeenCalled();
  });

  it('renames nothing when the name is kept', async () => {
    const onDone = show();
    blogDev();
    click('Name it and continue');
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsCreate).toHaveBeenCalledWith(input, null);
  });

  it('goes back to the form with Back, and with Escape', async () => {
    const onDone = show();
    type(part(), 'blog');
    type(stage(), 'dev');
    // As a click does.
    screen.getByRole('button', { name: 'Create environment' }).focus();
    click('Create environment');
    click('Back');
    expect(part().value).toBe('blog');
    // The focus isn't lost with the step's field.
    await vi.waitFor(() =>
      expect(document.activeElement).toBe(
        screen.getByRole('button', { name: 'Create environment' }),
      ),
    );
    click('Create environment');
    fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
    expect(part().value).toBe('blog');
    expect(onDone).not.toHaveBeenCalled();
    expect(api.envsCreate).not.toHaveBeenCalled();
  });

  it('shows a stage the backend found taken at its field, back in the form', async () => {
    show();
    await named();
    api.envsCreate.mockRejectedValue({ code: 'already_exists', message: 'blog / dev' });
    blogDev();
    click('Name it and continue');
    expect(await screen.findByText('Site · blog already has dev.')).toBeInTheDocument();
    expect(stage()).toHaveValue('dev');
  });
});

describe('editing an environment', () => {
  it('saves notes or a stage without asking anything', async () => {
    const onDone = show({ env: detailOf(ALL[0] as never) });
    await named();
    type(stage(), 'local');
    click('Save changes');
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsUpdate).toHaveBeenCalledWith(
      'e1',
      { project: 'p-site', part: 'marketing-site', name: 'local', notes: '' },
      null,
    );
  });

  it('asks only for the others when its own part changes in a project of one', async () => {
    const onDone = show({ env: detailOf(ALL[0] as never) });
    await named();
    type(part(), 'blog');
    click('Save changes');
    const first = screen.getByRole('textbox', { name: 'Part of its other environments' });
    type(first, 'site');
    click('Name it and continue');
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsUpdate).toHaveBeenCalledWith(
      'e1',
      { project: 'p-site', part: 'blog', name: 'dev', notes: '' },
      { ids: ['e2', 'e9'], part: 'site' },
    );
  });

  it('asks nothing in a project with two parts', async () => {
    const onDone = show({ env: detailOf(ALL[3] as never) });
    await named('Shop');
    type(part(), 'web');
    click('Save changes');
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(screen.queryByText(/gets a second part/)).not.toBeInTheDocument();
  });
});
