import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { BrowserProfile } from '@/bindings/BrowserProfile';
import type { ImportPreview } from '@/bindings/ImportPreview';
import type { ImportRow } from '@/bindings/ImportRow';
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
  vaultImportCompare: vi.fn(),
  browserStatus: vi.fn(),
  vaultImport: vi.fn(),
  vaultTrashImportFile: vi.fn(),
  vaultBrowserProfiles: vi.fn(),
  vaultBrowserImportPreview: vi.fn(),
  vaultBrowserImport: vi.fn(),
  vaultBrowserImportCompare: vi.fn(),
  vaultBrowserImportForget: vi.fn(),
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
      passwordChanged: false,
      changedInFile: null,
      changedInVault: null,
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
      passwordChanged: false,
      changedInFile: null,
      changedInVault: null,
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
      passwordChanged: false,
      changedInFile: null,
      changedInVault: null,
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
  api.browserStatus.mockResolvedValue({ browsers: [] });
  api.vaultBrowserProfiles.mockResolvedValue([]);
  api.vaultBrowserImportForget.mockResolvedValue(undefined);
});

const CHROME_PROFILES: BrowserProfile[] = [
  { id: 'chrome:Default', browser: 'Google Chrome', name: 'Person 1', family: 'chromium' },
  { id: 'chrome:Profile 2', browser: 'Google Chrome', name: 'Work', family: 'chromium' },
];
const FIREFOX_PROFILE: BrowserProfile = {
  id: 'firefox:0:Profiles/a.default-release',
  browser: 'Firefox',
  name: 'default-release',
  family: 'firefox',
};

describe('ImportDialog', () => {
  it('previews a file, skips duplicates, imports and moves the file to the Trash', async () => {
    const user = userEvent.setup();
    const onDone = vi.fn();
    // The backend opens the file dialog and says which file was picked.
    api.vaultImportPreview.mockResolvedValue({ path: CSV, preview: PREVIEW });
    api.vaultImport.mockResolvedValue({ added: 2, updated: 0 });
    api.vaultTrashImportFile.mockResolvedValue(undefined);
    renderWithProviders(<ImportDialog onDone={onDone} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: /^Bitwarden/ }));
    expect(screen.getByText('Export files aren’t encrypted')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Export from Bitwarden' })).toBeInTheDocument();
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

  it('lists new rows first and updates entries whose password differs', async () => {
    const user = userEvent.setup();
    const [github, router, wifi] = PREVIEW.rows as [ImportRow, ImportRow, ImportRow];
    const changed: ImportRow = {
      ...router,
      index: 4,
      title: 'Mail',
      duplicateOf: '7c1d2e3f-0d5e-4c1b-9a51-7b0f4e2a8c11',
      passwordChanged: true,
    };
    // In the file: an unchanged duplicate first, then a changed one, then two new rows.
    const preview: ImportPreview = { ...PREVIEW, rows: [router, changed, github, wifi] };
    api.vaultImportPreview.mockResolvedValue({ path: CSV, preview });
    api.vaultImport.mockResolvedValue({ added: 2, updated: 1 });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: /^Bitwarden/ }));
    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));
    const table = await screen.findByRole('table', { name: 'Entries in bitwarden_export.csv' });
    const order = within(table)
      .getAllByRole('checkbox')
      .map((box) => box.getAttribute('aria-label'))
      .filter((label) => label !== 'Select all');
    expect(order).toEqual(['Import GitHub', 'Import Wi-Fi', 'Import Mail', 'Import Router']);
    expect(within(table).getByText('Different password')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Import Mail' })).toBeChecked();
    expect(screen.getByRole('checkbox', { name: 'Import Router' })).not.toBeChecked();
    expect(
      screen.getByText(/1 has a different password than in the vault\. Importing it updates/),
    ).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Import 2, update 1' }));
    expect(api.vaultImport).toHaveBeenCalledWith([0, 3, 4]);
    expect(await screen.findByText('2 entries imported')).toBeInTheDocument();
    expect(screen.getByText('1 entry updated')).toBeInTheDocument();
  });

  it('compares the two passwords of a row, with their dates', async () => {
    const user = userEvent.setup();
    const [, router] = PREVIEW.rows as [ImportRow, ImportRow];
    const changed: ImportRow = {
      ...router,
      passwordChanged: true,
      changedInFile: '2026-11-02T09:15:00Z',
      changedInVault: '2025-03-12T08:00:00Z',
    };
    api.vaultImportPreview.mockResolvedValue({
      path: CSV,
      preview: { ...PREVIEW, rows: [changed] },
    });
    api.vaultImportCompare.mockResolvedValue({ file: 'from-file', vault: 'from-vault' });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    await user.click(await screen.findByRole('button', { name: /^Bitwarden/ }));
    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));

    const compare = await screen.findByRole('button', { name: 'Compare the passwords of Router' });
    expect(compare).toHaveAttribute('aria-expanded', 'false');
    await user.click(compare);
    expect(compare).toHaveAttribute('aria-expanded', 'true');
    // Opening the comparison doesn't tick or untick the row.
    expect(screen.getByRole('checkbox', { name: 'Import Router' })).toBeChecked();
    expect(screen.getByText('Changed Nov 2, 2026')).toBeInTheDocument();
    expect(screen.getByText('Changed Mar 12, 2025')).toBeInTheDocument();
    const fileSide = screen.getByText('In the file').closest('div') as HTMLElement;
    expect(within(fileSide).getByText('Newer')).toBeInTheDocument();
    // No password until asked for.
    expect(api.vaultImportCompare).not.toHaveBeenCalled();
    expect(screen.queryByText('from-file')).not.toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Show passwords' }));
    expect(api.vaultImportCompare).toHaveBeenCalledWith(1);
    expect(await screen.findByText('from-file')).toBeInTheDocument();
    expect(screen.getByText('from-vault')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Hide passwords' }));
    expect(screen.queryByText('from-file')).not.toBeInTheDocument();
  });

  it('says when a file has no dates', async () => {
    const user = userEvent.setup();
    const [, router] = PREVIEW.rows as [ImportRow, ImportRow];
    const changed: ImportRow = { ...router, passwordChanged: true, changedInVault: null };
    api.vaultImportPreview.mockResolvedValue({
      path: CSV,
      preview: { ...PREVIEW, rows: [changed] },
    });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    await user.click(await screen.findByRole('button', { name: /^Chrome/ }));
    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));
    await user.click(
      await screen.findByRole('button', { name: 'Compare the passwords of Router' }),
    );
    expect(screen.getByText('The file has no date')).toBeInTheDocument();
    expect(screen.getByText('Date unknown')).toBeInTheDocument();
    expect(screen.queryByText('Newer')).not.toBeInTheDocument();
  });

  it('only updates when every picked row has a different password', async () => {
    const user = userEvent.setup();
    const [, router] = PREVIEW.rows as [ImportRow, ImportRow];
    const preview: ImportPreview = { ...PREVIEW, rows: [{ ...router, passwordChanged: true }] };
    api.vaultImportPreview.mockResolvedValue({ path: CSV, preview });
    api.vaultImport.mockResolvedValue({ added: 0, updated: 1 });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    await user.click(await screen.findByRole('button', { name: /^Bitwarden/ }));
    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));
    await user.click(await screen.findByRole('button', { name: 'Update 1 entry' }));
    expect(await screen.findByText('1 entry updated')).toBeInTheDocument();
    expect(screen.queryByText(/imported/)).not.toBeInTheDocument();
  });

  it('stays on the first step when the file dialog is cancelled', async () => {
    const user = userEvent.setup();
    api.vaultImportPreview.mockResolvedValue(null);
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    await user.click(await screen.findByRole('button', { name: /^Another app or CSV file/ }));
    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));
    await waitFor(() => expect(api.vaultImportPreview).toHaveBeenCalled());
    expect(screen.getByRole('button', { name: 'Choose CSV file…' })).toBeEnabled();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('says so when a file is not a password export', async () => {
    const user = userEvent.setup();
    api.vaultImportPreview.mockRejectedValue({ code: 'unsupported', message: 'no password' });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: /^Another app or CSV file/ }));
    await user.click(await screen.findByRole('button', { name: 'Choose CSV file…' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'This file doesn’t look like a password export',
    );
    expect(api.vaultImport).not.toHaveBeenCalled();
  });

  it('asks to unlock a locked vault first', async () => {
    const user = userEvent.setup();
    api.vaultStatus.mockResolvedValue(status('locked'));
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    expect(await screen.findByText('Unlock the vault to import passwords.')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: /^Bitwarden/ }));
    expect(screen.getByRole('button', { name: 'Choose CSV file…' })).toBeDisabled();
  });

  it('offers the browsers on this computer first, any CSV file last', async () => {
    const user = userEvent.setup();
    api.browserStatus.mockResolvedValue({
      browsers: [
        { name: 'Firefox', registered: true },
        { name: 'Vivaldi', registered: false },
      ],
    });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    await screen.findByRole('button', { name: /^Vivaldi/ });
    const names = screen
      .getAllByRole('button')
      .map((button) => button.textContent ?? '')
      .filter((name) => /Firefox|Vivaldi|Chrome|Bitwarden|CSV/.test(name));
    expect(names.slice(0, 2)).toEqual(['VivaldiOn this computer', 'FirefoxOn this computer']);
    expect(names[2]).toBe('Chrome');
    expect(names.at(-1)).toMatch(/^Another app or CSV file/);

    await user.click(screen.getByRole('button', { name: /^Firefox/ }));
    expect(await screen.findByText('about:logins')).toBeInTheDocument();
  });

  it('says how to stop a browser offering the logins it imported', async () => {
    const user = userEvent.setup();
    api.vaultImportPreview.mockResolvedValue({ path: CSV, preview: PREVIEW });
    api.vaultImport.mockResolvedValue({ added: 2, updated: 0 });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });
    await user.click(await screen.findByRole('button', { name: /^Chrome/ }));
    await user.click(screen.getByRole('button', { name: 'Choose CSV file…' }));
    await user.click(await screen.findByRole('button', { name: 'Import 2 entries' }));
    expect(await screen.findByText('Stop Chrome offering them too')).toBeInTheDocument();
  });

  it('imports straight from a browser profile, without a file', async () => {
    const user = userEvent.setup();
    api.vaultBrowserProfiles.mockResolvedValue(CHROME_PROFILES);
    api.vaultBrowserImportPreview.mockResolvedValue({
      kind: 'preview',
      profile: CHROME_PROFILES[1],
      preview: { ...PREVIEW, format: 'chrome', skipped: 0 },
      unreadable: 1,
      appBound: 1,
    });
    api.vaultBrowserImport.mockResolvedValue({ added: 2, updated: 0 });
    const onDone = vi.fn();
    renderWithProviders(<ImportDialog onDone={onDone} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: /^Chrome/ }));
    expect(await screen.findByRole('heading', { name: 'Import from Chrome' })).toBeInTheDocument();
    await user.click(screen.getByRole('radio', { name: 'Work' }));
    await user.click(screen.getByRole('button', { name: 'Import from Chrome' }));
    expect(api.vaultBrowserImportPreview).toHaveBeenCalledWith('chrome:Profile 2', null);

    expect(await screen.findByText('Chrome · Work')).toBeInTheDocument();
    expect(screen.getByRole('table', { name: 'Logins in Work' })).toBeInTheDocument();
    expect(screen.getByText(/1 password wasn’t read: only Chrome can decrypt it/)).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Import 2 entries' }));
    expect(api.vaultBrowserImport).toHaveBeenCalledWith([0, 3]);
    expect(api.vaultImport).not.toHaveBeenCalled();
    expect(await screen.findByText('2 entries imported')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Move to Trash' })).not.toBeInTheDocument();
    expect(screen.getByText('Stop Chrome offering them too')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Done' }));
    expect(onDone).toHaveBeenCalled();
  });

  it('compares a changed password with the one in the browser', async () => {
    const user = userEvent.setup();
    const [, router] = PREVIEW.rows as [ImportRow, ImportRow];
    api.vaultBrowserProfiles.mockResolvedValue(CHROME_PROFILES.slice(0, 1));
    api.vaultBrowserImportPreview.mockResolvedValue({
      kind: 'preview',
      profile: CHROME_PROFILES[0],
      preview: {
        format: 'chrome',
        skipped: 0,
        rows: [{ ...router, passwordChanged: true, changedInFile: '2026-11-02T09:15:00Z' }],
      },
      unreadable: 0,
      appBound: 0,
    });
    api.vaultBrowserImportCompare.mockResolvedValue({ file: 'from-chrome', vault: 'from-vault' });
    api.vaultBrowserImport.mockResolvedValue({ added: 0, updated: 1 });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: /^Chrome/ }));
    await user.click(await screen.findByRole('button', { name: 'Import from Chrome' }));
    await user.click(
      await screen.findByRole('button', { name: 'Compare the passwords of Router' }),
    );
    expect(screen.getByText('In Chrome')).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Show passwords' }));
    expect(api.vaultBrowserImportCompare).toHaveBeenCalledWith(1);
    expect(api.vaultImportCompare).not.toHaveBeenCalled();
    expect(await screen.findByText('from-chrome')).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: 'Update 1 entry' }));
    expect(api.vaultBrowserImport).toHaveBeenCalledWith([1]);
    expect(await screen.findByText('1 entry updated')).toBeInTheDocument();
  });

  it('asks for the Firefox primary password and says when it is wrong', async () => {
    const user = userEvent.setup();
    api.vaultBrowserProfiles.mockResolvedValue([FIREFOX_PROFILE]);
    api.vaultBrowserImportPreview
      .mockResolvedValueOnce({ kind: 'primaryPasswordRequired' })
      .mockResolvedValueOnce({ kind: 'wrongPrimaryPassword' })
      .mockResolvedValueOnce({
        kind: 'preview',
        profile: FIREFOX_PROFILE,
        preview: { ...PREVIEW, format: 'firefox' },
        unreadable: 0,
        appBound: 0,
      });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: /^Firefox/ }));
    await user.click(await screen.findByRole('button', { name: 'Import from Firefox' }));
    const field = await screen.findByLabelText('Firefox Primary Password');
    await waitFor(() => expect(field).toHaveFocus());
    expect(screen.getByRole('button', { name: 'Import from Firefox' })).toBeDisabled();
    await user.type(field, 'wrong{Enter}');
    expect(await screen.findByText('That’s not the Primary Password. Try again.')).toBeVisible();
    await user.clear(field);
    await user.type(field, 'right{Enter}');
    expect(api.vaultBrowserImportPreview).toHaveBeenLastCalledWith(FIREFOX_PROFILE.id, 'right');
    expect(await screen.findByText('Firefox · default-release')).toBeInTheDocument();
  });

  it('falls back to the CSV guide when only the browser can read its passwords', async () => {
    const user = userEvent.setup();
    api.vaultBrowserProfiles.mockResolvedValue(CHROME_PROFILES.slice(0, 1));
    api.vaultBrowserImportPreview.mockResolvedValue({ kind: 'appBound' });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: /^Chrome/ }));
    // With one profile there is nothing to choose.
    expect(await screen.findByRole('heading', { name: 'Import from Chrome' })).toBeInTheDocument();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Import from Chrome' }));

    expect(await screen.findByText('Chrome keeps these passwords to itself')).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Export from Chrome' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Choose CSV file…' })).toHaveAccessibleDescription(
      /only it can read them/,
    );
  });

  it('says so when the system prompt is refused, and offers to try again', async () => {
    const user = userEvent.setup();
    api.vaultBrowserProfiles.mockResolvedValue(CHROME_PROFILES.slice(0, 1));
    api.vaultBrowserImportPreview.mockResolvedValue({ kind: 'denied' });
    renderWithProviders(<ImportDialog onDone={vi.fn()} />, { inDialog: true });

    await user.click(await screen.findByRole('button', { name: /^Chrome/ }));
    await user.click(await screen.findByRole('button', { name: 'Import from Chrome' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(/Access wasn’t allowed/);
    expect(screen.getByRole('button', { name: 'Import from Chrome' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Use a CSV file instead' }));
    expect(screen.getByRole('heading', { name: 'Export from Chrome' })).toBeInTheDocument();
  });

  it('drops the logins read from a browser when the dialog closes', async () => {
    const { unmount } = renderWithProviders(<ImportDialog onDone={vi.fn()} />, {
      inDialog: true,
    });
    await screen.findByRole('button', { name: /^Chrome/ });
    unmount();
    expect(api.vaultBrowserImportForget).toHaveBeenCalled();
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
