import { fireEvent, screen } from '@testing-library/react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { ALL, renderIn, SITE, stubPointer } from '@/features/envs/testing';
import { AddMembersDialog } from './AddMembersDialog';

const api = vi.hoisted(() => ({
  envsSetPart: vi.fn(),
  projectsSetMember: vi.fn(),
  projectsSuggestions: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

beforeAll(stubPointer);
afterEach(() => vi.clearAllMocks());

describe('adding Personal’s environments to a project of one part', () => {
  it('names its part first, then adds them', async () => {
    api.envsSetPart.mockResolvedValue(undefined);
    api.projectsSetMember.mockResolvedValue(undefined);
    const onDone = vi.fn();
    renderIn(
      <AddMembersDialog
        project={{ ...SITE, environments: ['e1', 'e2'] }}
        kind="environments"
        library={{ envs: ALL }}
        onDone={onDone}
      />,
    );
    fireEvent.click(screen.getByRole('checkbox', { name: /local/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Add 1 item' }));

    expect(screen.getByText('Site gets a second part')).toBeInTheDocument();
    fireEvent.change(screen.getByRole('textbox', { name: 'Part of its other environments' }), {
      target: { value: 'scripts' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Name it and continue' }));
    // The part it brings can't be the name.
    expect(screen.getByRole('alert')).toHaveTextContent('Use a name other than scripts.');

    fireEvent.change(screen.getByRole('textbox', { name: 'Part of its other environments' }), {
      target: { value: 'site' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Name it and continue' }));
    await vi.waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.envsSetPart).toHaveBeenCalledWith(['e1', 'e2', 'e9'], 'site');
    expect(api.projectsSetMember).toHaveBeenCalledWith(
      'p-site',
      { type: 'environment', id: 'm1' },
      true,
    );
  });
});
