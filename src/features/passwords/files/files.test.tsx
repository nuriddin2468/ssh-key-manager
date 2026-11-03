import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { ImportPreview } from '@/bindings/ImportPreview';
import type { VaultLocation } from '@/bindings/VaultLocation';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { Dialog } from '@/components/ui/Dialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { ExportDialog } from './ExportDialog';
import { ImportDialog } from './ImportDialog';
import { OpenExistingVaultButton } from './OpenExistingVaultButton';
import { VaultLocationSection } from './VaultLocationSection';

// Radix measures radio items; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const api = vi.hoisted(() => ({
  vaultStatus: vi.fn(),
  environment: vi.fn(),
  vaultImportPreview: vi.fn(),
  vaultImport: vi.fn(),
  vaultTrashImportFile: vi.fn(),
  vaultExportCsv: vi.fn(),
  vaultExportKdbx: vi.fn(),
  vaultLocation: vi.fn(),
  vaultMove: vi.fn(),
  vaultUseFile: vi.fn(),
  vaultUseDefault: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

const pickers = vi.hoisted(() => ({
  pickFile: vi.fn(),
  pickFolder: vi.fn(),
}));
vi.mock('./pickers', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./pickers')>()),
  ...pickers,
}));

const DATA = '/Users/me/Library/Application Support/uz.sshkm.app';
const CSV = '/Users/me/Downloads/bitwarden_export.csv';

function status(state: VaultStatus['state']): VaultStatus {
  return {
    state,
    files: {
      exists: true,
      hasMasterPassword: true,
      hasDeviceUnlock: false,
      deviceSlots: [],
      vaultId: 'id',
    },
    paths: { database: `${DATA}/vault.kdbx`, keys: `${DATA}/vault.keys` },
    settings: {
      database: null,
      autoLockMinutes: 5,
      clipboardSeconds: 30,
      lockOnSleep: true,
      lockOnScreenLock: true,
      lockOnMinimize: false,
      unlockKeysOnOpen: false,
    },
    device: { kind: null, unavailableReason: null, enabled: false },
  };
}

function location(database: string, defaultExists = true): VaultLocation {
  const defaultPaths = { database: `${DATA}/vault.kdbx`, keys: `${DATA}/vault.keys` };
  return {
    paths: { database, keys: database.replace(/\.kdbx$/, '.keys') },
    exists: true,
    isDefault: database === defaultPaths.database,
    defaultPaths,
    defaultExists,
  };
}

const PREVIEW: ImportPreview = {
  format: 'bitwarden',
  skipped: 1,
  rows: [
    {
      index: 0,
      title: 'GitHub',
      username: 'octocat',
      url: 'https://github.com/login',
      group: 'Work',
      hasPassword: true,
      hasOtp: true,
      hasUnreadableOtp: false,
      duplicateOf: null,
    },
    {
      index: 1,
      title: 'Router',
      username: 'admin',
      url: '',
      group: null,
      hasPassword: true,
      hasOtp: false,
      hasUnreadableOtp: false,
      duplicateOf: '3f0c7a52-0d5e-4c1b-9a51-7b0f4e2a8c11',
    },
    {
      index: 3,
      title: 'Wi-Fi',
      username: '',
      url: '',
      group: null,
      hasPassword: false,
      hasOtp: false,
      hasUnreadableOtp: true,
      duplicateOf: null,
    },
  ],
};

function renderWithProviders(ui: ReactNode, { inDialog = false } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <TooltipProvider>{inDialog ? <Dialog open>{ui}</Dialog> : ui}</TooltipProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  for (const fn of [...Object.values(api), ...Object.values(pickers)]) fn.mockReset();
  api.vaultStatus.mockResolvedValue(status('unlocked'));
  api.environment.mockResolvedValue({ paths: { home: '/Users/me' } });
});

describe('ImportDialog', () => {
  it('previews a file, skips duplicates, imports and moves the file to the Trash', async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    // The backend opens the file dialog and says which file was picked.
    api.vaultImportPreview.mockResolvedValue({ path: CSV, preview: PREVIEW });
    api.vaultImport.mockResolvedValue(2);
    api.vaultTrashImportFile.mockResolvedValue(undefined);
    renderWithProviders(<ImportDialog onDone={onDone} />, { inDialog: true });

    expect(screen.getByText('Export files aren’t encrypted')).toBeInTheDocument();
    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));

    expect(await screen.findByText('Format: Bitwarden')).toBeInTheDocument();
    expect(api.vaultImportPreview).toHaveBeenCalledWith();
    expect(pickers.pickFile).not.toHaveBeenCalled();
    expect(
      screen.getByText(
        '3 entries · 1 is already in the vault, so it isn’t selected. · 1 empty or unreadable row was skipped.',
      ),
    ).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Entries in bitwarden_export.csv' });
    expect(within(table).getByText('Already in vault')).toBeInTheDocument();
    expect(within(table).getByText('Folder: Work')).toBeInTheDocument();
    expect(within(table).getByText('2FA for KeePassXC')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Import GitHub' })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Import Router' })).not.toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Select all' })).toHaveAttribute(
      'aria-checked',
      'mixed',
    );

    // Clicking a row toggles it, like its checkbox.
    await user.click(within(table).getByText('Wi-Fi'));
    expect(screen.getByRole('checkbox', { name: 'Import Wi-Fi' })).not.toBeChecked();
    await user.click(screen.getByRole('checkbox', { name: 'Import Wi-Fi' }));
    expect(screen.getByRole('checkbox', { name: 'Import Wi-Fi' })).toBeChecked();

    await user.click(screen.getByRole('button', { name: 'Import 2 entries' }));
    expect(api.vaultImport).toHaveBeenCalledWith([0, 3]);
    expect(await screen.findByText('2 entries imported')).toBeInTheDocument();
    expect(screen.getByText(/bitwarden_export\.csv still holds these passwords/)).toBeVisible();

    await user.click(screen.getByRole('button', { name: 'Move to Trash' }));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.vaultTrashImportFile).toHaveBeenCalledWith();
  });

  it('stays on the first step when the file dialog is cancelled', async () => {
    const user = userEvent.setup();
    api.vaultImportPreview.mockResolvedValue(null);
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));
    await waitFor(() => expect(api.vaultImportPreview).toHaveBeenCalled());
    expect(screen.getByRole('button', { name: 'Choose CSV file…' })).toBeEnabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('says so when a file is not a password export', async () => {
    const user = userEvent.setup();
    api.vaultImportPreview.mockRejectedValue({ code: 'unsupported', message: 'no password' });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'This file doesn’t look like a password export',
    );
    expect(api.vaultImport).not.toHaveBeenCalled();
  });

  it('asks to unlock a locked vault first', async () => {
    api.vaultStatus.mockResolvedValue(status('locked'));
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    expect(await screen.findByText('Unlock the vault to import passwords.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Choose CSV file…' })).toBeDisabled();
  });
});

describe('ExportDialog', () => {
  it('saves an encrypted KeePass copy by default, after the master password', async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    api.vaultExportKdbx.mockResolvedValue({
      path: '/Users/me/Documents/vault-copy.kdbx',
      count: 3,
    });
    renderWithProviders(<ExportDialog onDone={onDone} />, { inDialog: true });

    expect(screen.getByRole('radio', { name: /KeePass database/ })).toBeChecked();
    const submit = screen.getByRole('button', { name: 'Export…' });
    expect(submit).toBeDisabled();
    await waitFor(() => expect(screen.getByLabelText('Master password')).toBeEnabled());
    await user.type(screen.getByLabelText('Master password'), 'master');
    await user.click(submit);

    await waitFor(() => expect(onDone).toHaveBeenCalled());
    // The backend asks where to save; the page names no file.
    expect(api.vaultExportKdbx).toHaveBeenCalledWith('master');
  });

  it('stays open when the save dialog is cancelled', async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    api.vaultExportKdbx.mockResolvedValue(null);
    renderWithProviders(<ExportDialog onDone={onDone} />, { inDialog: true });
    await waitFor(() => expect(screen.getByLabelText('Master password')).toBeEnabled());
    await user.type(screen.getByLabelText('Master password'), 'master');
    await user.click(screen.getByRole('button', { name: 'Export…' }));
    await waitFor(() => expect(api.vaultExportKdbx).toHaveBeenCalled());
    expect(onDone).not.toHaveBeenCalled();
  });

  it('warns about plain text and needs the master password for CSV', async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    const target = '/Users/me/Documents/passwords.csv';
    api.vaultExportCsv
      .mockRejectedValueOnce({ code: 'wrong_passphrase', message: 'wrong passphrase' })
      .mockResolvedValueOnce({ path: target, count: 12 });
    renderWithProviders(<ExportDialog onDone={onDone} />, { inDialog: true });

    await waitFor(() => expect(screen.getByRole('radio', { name: /CSV file/ })).toBeEnabled());
    await user.click(screen.getByRole('radio', { name: /CSV file/ }));
    expect(screen.getByText('Anyone with this file can read every password')).toBeVisible();
    const submit = screen.getByRole('button', { name: 'Export…' });
    expect(submit).toBeDisabled();

    await user.type(screen.getByLabelText('Master password'), 'nope');
    await user.click(submit);
    expect(await screen.findByText('Wrong master password.')).toBeInTheDocument();
    expect(api.vaultExportCsv).toHaveBeenCalledWith('nope');
    expect(onDone).not.toHaveBeenCalled();

    await user.clear(screen.getByLabelText('Master password'));
    await user.type(screen.getByLabelText('Master password'), 'master');
    await user.click(submit);
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(api.vaultExportCsv).toHaveBeenLastCalledWith('master');
  });

  it('exports nothing while the vault is locked', async () => {
    api.vaultStatus.mockResolvedValue(status('locked'));
    renderWithProviders(<ExportDialog onDone={vi.fn()} />, { inDialog: true });
    expect(await screen.findByText('Unlock the vault to export it.')).toBeInTheDocument();
    expect(screen.getByRole('radio', { name: /CSV file/ })).toBeDisabled();
    expect(screen.getByRole('radio', { name: /KeePass database/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Export…' })).toBeDisabled();
  });
});

describe('VaultLocationSection', () => {
  it('moves the vault into a chosen folder after confirming', async () => {
    const user = userEvent.setup();
    const dropbox = '/Users/me/Dropbox';
    api.vaultLocation.mockResolvedValue(location(`${DATA}/vault.kdbx`));
    api.vaultMove.mockResolvedValue(location(`${dropbox}/vault.kdbx`));
    pickers.pickFolder.mockResolvedValue(dropbox);
    renderWithProviders(<VaultLocationSection />);

    expect(await screen.findByTitle(`${DATA}/vault.kdbx`)).toHaveTextContent(
      '~/Library/Application Support/uz.sshkm.app/vault.kdbx',
    );
    expect(screen.getByText('Default')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Back to default' })).not.toBeInTheDocument();
    expect(screen.getByText(/Dropbox, iCloud Drive or OneDrive/)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Move…' }));
    const dialog = await screen.findByRole('alertdialog', {
      name: 'Move the vault to ~/Dropbox?',
    });
    await user.click(within(dialog).getByRole('button', { name: 'Move vault' }));
    await waitFor(() => expect(api.vaultMove).toHaveBeenCalledWith(dropbox));
  });

  it('switches to another vault file after confirming', async () => {
    const user = userEvent.setup();
    const other = '/Users/me/Dropbox/Passwords.kdbx';
    api.vaultLocation.mockResolvedValue(location(`${DATA}/vault.kdbx`));
    api.vaultUseFile.mockResolvedValue(location(other));
    pickers.pickFile.mockResolvedValue(other);
    renderWithProviders(<VaultLocationSection />);

    await user.click(await screen.findByRole('button', { name: 'Use another vault file…' }));
    const dialog = await screen.findByRole('alertdialog', { name: 'Switch to Passwords.kdbx?' });
    expect(dialog).toHaveTextContent('The current vault locks and stays where it is.');
    await user.click(within(dialog).getByRole('button', { name: 'Switch vault' }));
    await waitFor(() => expect(api.vaultUseFile).toHaveBeenCalledWith(other));
  });

  it('moves the files back when there is no vault at the default place', async () => {
    const user = userEvent.setup();
    api.vaultLocation.mockResolvedValue(location('/Users/me/Dropbox/vault.kdbx', false));
    api.vaultUseDefault.mockResolvedValue(location(`${DATA}/vault.kdbx`));
    renderWithProviders(<VaultLocationSection />);

    await user.click(await screen.findByRole('button', { name: 'Back to default' }));
    const dialog = await screen.findByRole('alertdialog', {
      name: 'Move the vault back to the app’s folder?',
    });
    expect(dialog).toHaveTextContent('Both vault files leave ~/Dropbox.');
    await user.click(within(dialog).getByRole('button', { name: 'Move vault' }));
    await waitFor(() => expect(api.vaultUseDefault).toHaveBeenCalledWith(true));
  });

  it('switches back when the default vault still exists', async () => {
    const user = userEvent.setup();
    api.vaultLocation.mockResolvedValue(location('/Users/me/Dropbox/Passwords.kdbx', true));
    api.vaultUseDefault.mockResolvedValue(location(`${DATA}/vault.kdbx`));
    renderWithProviders(<VaultLocationSection />);

    await user.click(await screen.findByRole('button', { name: 'Back to default' }));
    const dialog = await screen.findByRole('alertdialog', {
      name: 'Switch back to the default vault?',
    });
    await user.click(within(dialog).getByRole('button', { name: 'Switch vault' }));
    await waitFor(() => expect(api.vaultUseDefault).toHaveBeenCalledWith(false));
  });
});

describe('OpenExistingVaultButton', () => {
  it('switches to the chosen KeePass file', async () => {
    const user = userEvent.setup();
    const onOpened = vi.fn();
    const file = '/Users/me/iCloud/vault.kdbx';
    pickers.pickFile.mockResolvedValue(file);
    api.vaultUseFile.mockResolvedValue(location(file));
    renderWithProviders(<OpenExistingVaultButton onOpened={onOpened} />);

    await user.click(screen.getByRole('button', { name: 'Open an existing vault…' }));
    await waitFor(() => expect(onOpened).toHaveBeenCalledWith(location(file)));
    expect(pickers.pickFile).toHaveBeenCalledWith(
      'Choose a vault file',
      { name: 'KeePass databases', extensions: ['kdbx'] },
      expect.any(String),
    );
  });

  it('does nothing when the file dialog is cancelled', async () => {
    const user = userEvent.setup();
    pickers.pickFile.mockResolvedValue(null);
    renderWithProviders(<OpenExistingVaultButton />);
    await user.click(screen.getByRole('button', { name: 'Open an existing vault…' }));
    expect(api.vaultUseFile).not.toHaveBeenCalled();
  });
});
