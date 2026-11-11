import { fireEvent, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { secondPart } from './model';
import { RestoreEnvDialog } from './RestoreEnvDialog';
import { ALL, answer, renderIn, summary } from './testing';

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  projectsList: vi.fn(),
  envsRestore: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

// In Site's recycle bin, from a part it no longer has.
const binned = summary('e8', 'p-site', 'blog', 'dev', { inTrash: true });
const all = [...ALL, binned];

afterEach(() => vi.clearAllMocks());

describe('restoring an environment that brings its project a second part', () => {
  it('is asked for: the first is named in the same restore', async () => {
    const first = secondPart(all, 'p-site', ['blog']);
    expect(first?.ids).toEqual(['e1', 'e2', 'e9']);
    answer(api);
    api.envsRestore.mockResolvedValue(undefined);
    const onDone = vi.fn();
    renderIn(<RestoreEnvDialog env={binned} first={first as never} onDone={onDone} />);
    expect(await screen.findByText('Site gets a second part')).toBeInTheDocument();
    fireEvent.change(screen.getByRole('textbox', { name: 'Part of its other environments' }), {
      target: { value: 'site' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Name it and restore' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsRestore).toHaveBeenCalledWith('e8', { ids: ['e1', 'e2', 'e9'], part: 'site' });
  });

  it('says in the step why the restore failed', async () => {
    answer(api);
    api.envsRestore.mockRejectedValue({ code: 'already_exists', message: 'blog / dev' });
    const onDone = vi.fn();
    const first = secondPart(all, 'p-site', ['blog']);
    renderIn(<RestoreEnvDialog env={binned} first={first as never} onDone={onDone} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Name it and restore' }));
    await vi.waitFor(() => expect(screen.getByRole('alert')).not.toBeEmptyDOMElement());
    expect(onDone).not.toHaveBeenCalled();
  });

  it('isn’t asked for when the part is one the project has', () => {
    const same = summary('e7', 'p-site', 'marketing-site', 'stage', { inTrash: true });
    expect(secondPart([...ALL, same], 'p-site', [same.part])).toBeNull();
  });
});
