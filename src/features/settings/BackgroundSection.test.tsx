import { QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { queryClient } from '@/api/queries';
import type { AutostartStatus } from '@/bindings/AutostartStatus';
import type { BackgroundStatus } from '@/bindings/BackgroundStatus';
import { BackgroundSection } from './BackgroundSection';

const api = vi.hoisted(() => ({
  backgroundStatus: vi.fn(),
  backgroundSetEnabled: vi.fn(),
  autostartStatus: vi.fn(),
  autostartSetEnabled: vi.fn(),
}));
vi.mock('@/api/commands', () => ({ api }));

function login(extra: Partial<AutostartStatus> = {}): AutostartStatus {
  return { enabled: false, turnedOffInSettings: false, blocker: null, ...extra };
}

function show(background: BackgroundStatus, autostart: AutostartStatus) {
  api.backgroundStatus.mockResolvedValue(background);
  api.autostartStatus.mockResolvedValue(autostart);
  render(
    <QueryClientProvider client={queryClient}>
      <BackgroundSection />
    </QueryClientProvider>,
  );
}

const openAtLogin = () => screen.findByRole('switch', { name: 'Open at login' });

afterEach(() => queryClient.clear());

// jsdom reports Linux, so the hints name the tray.
describe('open at login', () => {
  it('is off by default and promises the tray', async () => {
    show({ enabled: false, available: true, virtualFiles: 0 }, login());
    const toggle = await openAtLogin();
    expect(toggle).not.toBeChecked();
    expect(toggle).toBeEnabled();
    expect(toggle).toHaveAccessibleDescription(
      'Starts in the tray without a window, so browser autofill and your devices work as soon as you log in.',
    );
  });

  it('turns on through the app, and shows both switches as the system has them', async () => {
    show({ enabled: false, available: true, virtualFiles: 0 }, login());
    const toggle = await openAtLogin();
    // The app turns the background on with it; both are read again.
    api.autostartSetEnabled.mockResolvedValue(login({ enabled: true }));
    api.autostartStatus.mockResolvedValue(login({ enabled: true }));
    api.backgroundStatus.mockResolvedValue({ enabled: true, available: true, virtualFiles: 0 });
    await userEvent.click(toggle);
    expect(api.autostartSetEnabled).toHaveBeenCalledWith(true);
    await vi.waitFor(() => expect(toggle).toBeChecked());
    expect(
      screen.getByRole('switch', { name: 'Keep running when the window is closed' }),
    ).toBeChecked();
  });

  it('keeps the keyboard focus while the change is saved', async () => {
    show({ enabled: true, available: true, virtualFiles: 0 }, login());
    const toggle = await openAtLogin();
    let finish: (status: AutostartStatus) => void = () => {};
    api.autostartSetEnabled.mockReturnValue(
      new Promise<AutostartStatus>((resolve) => {
        finish = resolve;
      }),
    );
    toggle.focus();
    await userEvent.keyboard(' ');
    await vi.waitFor(() => expect(toggle).toHaveAttribute('aria-busy', 'true'));
    expect(toggle).toHaveFocus();
    // A second press while it saves asks nothing more.
    await userEvent.keyboard(' ');
    expect(api.autostartSetEnabled).toHaveBeenCalledTimes(1);
    api.autostartStatus.mockResolvedValue(login({ enabled: true }));
    finish(login({ enabled: true }));
    await vi.waitFor(() => expect(toggle).toBeChecked());
    expect(toggle).toHaveFocus();
  });

  it('says the window opens once the background is turned off', async () => {
    show({ enabled: false, available: true, virtualFiles: 0 }, login({ enabled: true }));
    expect(await openAtLogin()).toHaveAccessibleDescription(
      'Opens the window when you log in. To start in the background instead, turn on “Keep running when the window is closed”.',
    );
  });

  it('says what turning it off would stop while virtual files are served', async () => {
    show({ enabled: true, available: true, virtualFiles: 2 }, login());
    expect(
      await screen.findByRole('switch', { name: 'Keep running when the window is closed' }),
    ).toHaveAccessibleDescription(
      /Serves 2 virtual \.env files\. If you turn this off, closing the window quits the app and the files go\.$/,
    );
  });

  it('opens the window at login on a desktop without a tray', async () => {
    show({ enabled: false, available: false, virtualFiles: 0 }, login());
    const toggle = await openAtLogin();
    expect(toggle).toBeEnabled();
    expect(toggle).toHaveAccessibleDescription('Opens the window when you log in.');
  });

  it('says how to allow an entry turned off in System Settings', async () => {
    show({ enabled: true, available: true, virtualFiles: 0 }, login({ turnedOffInSettings: true }));
    const toggle = await openAtLogin();
    expect(toggle).not.toBeChecked();
    expect(toggle).toBeEnabled();
    expect(toggle).toHaveAccessibleDescription(
      'Turned off in System Settings. Turn this switch on, then allow SSH Key Manager in Login Items.',
    );
  });

  it('can’t be turned on from a disk image', async () => {
    show({ enabled: true, available: true, virtualFiles: 0 }, login({ blocker: 'mounted' }));
    const toggle = await openAtLogin();
    expect(toggle).toBeDisabled();
    expect(toggle).toHaveAccessibleDescription(/move it to the Applications folder/);
  });

  it('can turn off an entry from a temporary copy', async () => {
    show(
      { enabled: true, available: true, virtualFiles: 0 },
      login({ enabled: true, blocker: 'temporary' }),
    );
    const toggle = await openAtLogin();
    expect(toggle).toBeEnabled();
    expect(toggle).toHaveAccessibleDescription(/temporary folder/);
  });

  it('leaves the row out if the system can’t be asked', async () => {
    api.backgroundStatus.mockResolvedValue({ enabled: true, available: true, virtualFiles: 0 });
    api.autostartStatus.mockRejectedValue({ code: 'io', message: 'no home folder' });
    render(
      <QueryClientProvider client={queryClient}>
        <BackgroundSection />
      </QueryClientProvider>,
    );
    const section = await screen.findByRole('region', { name: 'Background' });
    expect(within(section).getAllByRole('switch')).toHaveLength(1);
  });
});
