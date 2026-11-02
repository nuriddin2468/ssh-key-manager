import { render, renderHook, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UpdateState } from './updater';

const check = vi.fn();
const relaunch = vi.fn();
const toast = {
  success: vi.fn(),
  error: vi.fn(),
  loading: vi.fn(),
  custom: vi.fn(),
  dismiss: vi.fn(),
};

vi.mock('@tauri-apps/api/core', () => ({ isTauri: () => true }));
vi.mock('@tauri-apps/plugin-updater', () => ({ check }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch }));
vi.mock('sonner', () => ({ toast }));

type DownloadEvent =
  | { event: 'Started'; data: { contentLength?: number } }
  | { event: 'Progress'; data: { chunkLength: number } }
  | { event: 'Finished' };

function fakeUpdate(version: string, events: DownloadEvent[] = []) {
  return {
    version,
    close: vi.fn(),
    downloadAndInstall: vi.fn(async (onEvent: (event: DownloadEvent) => void) => {
      for (const event of events) onEvent(event);
    }),
  };
}

// The store lives at module level, so each test starts from a fresh copy.
async function load() {
  vi.resetModules();
  return import('./updater');
}

/** What a component would see right now. */
function currentStatus(useUpdateState: () => UpdateState): UpdateState {
  return renderHook(() => useUpdateState()).result.current;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkForUpdates', () => {
  it('stays silent when an automatic check finds nothing', async () => {
    check.mockResolvedValue(null);
    const { checkForUpdates, useUpdateState } = await load();
    await checkForUpdates({ quiet: true });
    expect(currentStatus(useUpdateState)).toEqual({ status: 'upToDate' });
    expect(toast.success).not.toHaveBeenCalled();
  });

  it('confirms the latest version when asked', async () => {
    check.mockResolvedValue(null);
    const { checkForUpdates } = await load();
    await checkForUpdates();
    expect(toast.success).toHaveBeenCalledOnce();
  });

  it('offers a new version once, however often the automatic check runs', async () => {
    check.mockImplementation(async () => fakeUpdate('0.2.0'));
    const { checkForUpdates, useUpdateState } = await load();
    await checkForUpdates({ quiet: true });
    await checkForUpdates({ quiet: true });
    expect(currentStatus(useUpdateState)).toEqual({ status: 'available', version: '0.2.0' });
    expect(toast.custom).toHaveBeenCalledOnce();

    await checkForUpdates();
    expect(toast.custom).toHaveBeenCalledTimes(2);
  });

  it('reports a failed check only when asked', async () => {
    check.mockRejectedValue(new Error('offline'));
    const { checkForUpdates, useUpdateState } = await load();
    await checkForUpdates({ quiet: true });
    expect(currentStatus(useUpdateState)).toEqual({ status: 'error' });
    expect(toast.error).not.toHaveBeenCalled();

    await checkForUpdates();
    expect(toast.error).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ description: 'offline' }),
    );
  });
});

describe('installUpdate', () => {
  it('downloads with progress and restarts', async () => {
    const update = fakeUpdate('0.2.0', [
      { event: 'Started', data: { contentLength: 200 } },
      { event: 'Progress', data: { chunkLength: 100 } },
      { event: 'Progress', data: { chunkLength: 100 } },
      { event: 'Finished' },
    ]);
    check.mockResolvedValue(update);
    const { checkForUpdates, installUpdate } = await load();
    await checkForUpdates();
    await installUpdate();

    const progress = toast.loading.mock.calls.map(([, options]) => options.description);
    expect(progress).toEqual([undefined, '50%', '100%']);
    expect(relaunch).toHaveBeenCalledOnce();
  });

  it('lets the user retry after a failed install', async () => {
    const update = fakeUpdate('0.2.0');
    update.downloadAndInstall.mockRejectedValue(new Error('bad signature'));
    check.mockResolvedValue(update);
    const { checkForUpdates, installUpdate, useUpdateState } = await load();
    await checkForUpdates();
    await installUpdate();

    expect(relaunch).not.toHaveBeenCalled();
    expect(currentStatus(useUpdateState)).toEqual({ status: 'available', version: '0.2.0' });
    expect(toast.error).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ description: 'bad signature' }),
    );
  });

  it('does nothing before a check has found an update', async () => {
    const { installUpdate } = await load();
    await installUpdate();
    expect(toast.loading).not.toHaveBeenCalled();
  });
});

describe('the update offer', () => {
  /** Renders what the last offer asked sonner to show. */
  function renderOffer() {
    const [content] = toast.custom.mock.lastCall as [() => ReactElement];
    render(content());
  }

  it('installs and restarts from its button', async () => {
    check.mockResolvedValue(fakeUpdate('0.2.0'));
    const { checkForUpdates } = await load();
    await checkForUpdates();
    renderOffer();

    expect(screen.getByText('Version 0.2.0 is available')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Update and restart' }));
    expect(toast.dismiss).toHaveBeenCalledWith('update-offer');
    await vi.waitFor(() => expect(relaunch).toHaveBeenCalledOnce());
  });

  it('can be put off', async () => {
    const update = fakeUpdate('0.2.0');
    check.mockResolvedValue(update);
    const { checkForUpdates } = await load();
    await checkForUpdates();
    renderOffer();

    await userEvent.click(screen.getByRole('button', { name: 'Later' }));
    expect(toast.dismiss).toHaveBeenCalledWith('update-offer');
    expect(update.downloadAndInstall).not.toHaveBeenCalled();
  });
});
