import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AgentView } from '@/bindings/AgentView';
import type { AuthorizedKey } from '@/bindings/AuthorizedKey';
import type { KeyView } from '@/bindings/KeyView';
import type { ServerKeys } from '@/bindings/ServerKeys';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { ServerKeysDialog } from './ServerKeysDialog';

const api = vi.hoisted(() => ({
  listKeys: vi.fn(),
  agent: vi.fn(),
  serverKeys: vi.fn(),
  vaultServerKeys: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));
vi.mock('@/app/dialogs', () => ({ useDialogs: () => ({ generateKeyFor: vi.fn() }) }));

function entry(name: string, partial: Partial<AuthorizedKey> = {}): AuthorizedKey {
  return {
    line: 1,
    algorithm: 'ed25519',
    keyType: 'ssh-ed25519',
    bits: 256,
    fingerprint: `SHA256:${name}`,
    comment: name,
    publicKey: `ssh-ed25519 AAAA${name}`,
    expires: null,
    certAuthority: false,
    options: [],
    ...partial,
  };
}

function file(keys: AuthorizedKey[], extra: Partial<ServerKeys> = {}): ServerKeys {
  return {
    ok: true,
    changed: false,
    read: true,
    file: { keys, invalid: [] },
    output: '',
    prompts: [],
    ...extra,
  };
}

const laptop: KeyView = {
  id: 'SHA256:laptop#id_ed25519',
  name: 'id_ed25519',
  privatePath: '/home/dev/.ssh/id_ed25519',
  publicPath: '/home/dev/.ssh/id_ed25519.pub',
  algorithm: 'ed25519',
  keyType: 'ssh-ed25519',
  bits: 256,
  fingerprint: 'SHA256:laptop',
  comment: 'laptop',
  encrypted: false,
  hardware: false,
  format: 'openssh',
  publicKey: 'ssh-ed25519 AAAAlaptop laptop',
  modified: null,
  pairMismatch: false,
  permissions: { ok: true, mode: '600', problem: null },
  inAgent: false,
  usedBy: [],
};

function show(withVault = false) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <Dialog open>
          <ServerKeysDialog
            alias="prod"
            account="deploy@10.0.0.5"
            withVault={withVault}
            passwordSaved={withVault}
            vaultLocked={false}
            onAction={{}}
          />
        </Dialog>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  api.listKeys.mockResolvedValue({ keys: [laptop], skipped: [] });
  api.agent.mockResolvedValue({
    status: { running: true, socket: null, error: null },
    identities: [],
  } as unknown as AgentView);
});

describe('ServerKeysDialog', () => {
  it('lists the keys and keeps this computer from removing its only way in', async () => {
    api.serverKeys.mockResolvedValue(file([entry('laptop'), entry('colleague', { line: 2 })]));
    show();

    const list = await screen.findByRole('list', { name: 'Keys on prod' });
    expect(api.serverKeys).toHaveBeenCalledExactlyOnceWith('prod', { type: 'list' });
    const [mine, theirs] = within(list).getAllByRole('listitem');
    expect(within(mine as HTMLElement).getByText('This computer')).toBeInTheDocument();
    const blocked = screen.getByRole('button', { name: 'Remove laptop' });
    expect(blocked).toHaveAttribute('aria-disabled', 'true');
    expect(blocked).toHaveAccessibleDescription(
      'It’s this computer’s only way in to prod. Add another key first.',
    );
    expect(within(theirs as HTMLElement).queryByText('This computer')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Remove colleague' })).not.toHaveAttribute(
      'aria-disabled',
    );

    await userEvent.click(blocked);
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('removes a key after asking, reading the file in the same sign-in', async () => {
    api.vaultServerKeys
      .mockResolvedValueOnce(file([entry('laptop'), entry('colleague', { line: 2 })]))
      .mockResolvedValueOnce(file([entry('laptop')], { changed: true }));
    show(true);

    await userEvent.click(await screen.findByRole('button', { name: 'Remove colleague' }));
    const confirm = screen.getByRole('alertdialog', { name: 'Remove colleague from prod?' });
    await userEvent.click(within(confirm).getByRole('button', { name: 'Remove key' }));

    expect(await screen.findByText('Removed colleague from prod.')).toBeInTheDocument();
    expect(api.vaultServerKeys).toHaveBeenLastCalledWith('prod', {
      type: 'remove',
      publicKey: 'ssh-ed25519 AAAAcolleague',
    });
    expect(api.serverKeys).not.toHaveBeenCalled();
    expect(screen.queryByRole('button', { name: 'Remove colleague' })).not.toBeInTheDocument();
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument();
  });

  it('explains a sign-in that failed', async () => {
    api.serverKeys.mockResolvedValue(
      file([], {
        ok: false,
        read: false,
        output: 'deploy@prod: Permission denied (publickey,password).',
      }),
    );
    show();

    expect(
      await screen.findByText('The server didn’t accept any of your keys.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('list')).not.toBeInTheDocument();
  });
});
