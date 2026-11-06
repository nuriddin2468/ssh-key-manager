import { render, renderHook, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { ReactElement } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { UpdateOffer } from '@/bindings/UpdateOffer';
import type { UpdateState } from './updater';

const call = vi.fn();
const toast = {
  success: vi.fn(),
  error: vi.fn(),
  loading: vi.fn(),
  custom: vi.fn(),
  dismiss: vi.fn(),
};

/** Stands in for the channel `update_install` reports its progress on. */
class FakeChannel<T> {
  constructor(readonly onmessage: (message: T) => void) {}
}

vi.mock('@tauri-apps/api/core', () => ({
  isTauri: () => true,
  invoke: vi.fn(async () => undefined),
  Channel: FakeChannel,
}));
vi.mock('@/lib/ipc', () => ({ call }));
vi.mock('sonner', () => ({ toast }));

const RELEASES: UpdateOffer['releases'] = [
  {
    version: '0.2.0',
    date: '2026-11-06',
    changes: [{ kind: 'fixed', en: 'Fixed a thing.', ru: null, uz: null }],
  },
];

/** The backend: `update_check` finds `version`; `update_install` reports `progress`. */
function backend(version: string | null, progress: number[] = []) {
  const install = vi.fn(async (args: { progress: FakeChannel<number> }) => {
    for (const percent of progress) args.progress.onmessage(percent);
  });
  const offer: UpdateOffer | null = version ? { version, releases: RELEASES } : null;
  call.mockImplementation(async (command: string, args?: unknown) => {
    if (command === 'update_check') return offer;
    if (command === 'update_install') return install(args as { progress: FakeChannel<number> });
    throw new Error(`unexpected command ${command}`);
  });
  return { install };
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
    backend(null);
    const { checkForUpdates, useUpdateState } = await load();
    await checkForUpdates({ quiet: true });
    expect(currentStatus(useUpdateState)).toEqual({ status: 'upToDate' });
    expect(toast.success).not.toHaveBeenCalled();
  });

  it('confirms the latest version when asked', async () => {
    backend(null);
    const { checkForUpdates } = await load();
    await checkForUpdates();
    expect(toast.success).toHaveBeenCalledOnce();
  });

  it('offers a new version once, however often the automatic check runs', async () => {
    backend('0.2.0');
    const { checkForUpdates, useUpdateState } = await load();
    await checkForUpdates({ quiet: true });
    await checkForUpdates({ quiet: true });
    expect(currentStatus(useUpdateState)).toEqual({
      status: 'available',
      version: '0.2.0',
      releases: RELEASES,
    });
    expect(toast.custom).toHaveBeenCalledOnce();

    await checkForUpdates();
    expect(toast.custom).toHaveBeenCalledTimes(2);
  });

  it('reports a failed check only when asked', async () => {
    call.mockRejectedValue(new Error('offline'));
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
  it('installs the version found, with progress', async () => {
    const { install } = backend('0.2.0', [50, 50, 100]);
    const { checkForUpdates, installUpdate } = await load();
    await checkForUpdates();
    await installUpdate();

    const progress = toast.loading.mock.calls.map(([, options]) => options.description);
    expect(progress).toEqual([undefined, '50%', '100%']);
    expect(install).toHaveBeenCalledOnce();
  });

  it('lets the user retry after a failed install', async () => {
    const { install } = backend('0.2.0');
    install.mockRejectedValue(new Error('bad signature'));
    const { checkForUpdates, installUpdate, useUpdateState } = await load();
    await checkForUpdates();
    await installUpdate();

    expect(currentStatus(useUpdateState)).toEqual({
      status: 'available',
      version: '0.2.0',
      releases: RELEASES,
    });
    expect(toast.error).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ description: 'bad signature' }),
    );
  });

  it('does nothing before a check has found an update', async () => {
    const { install } = backend(null);
    const { checkForUpdates, installUpdate } = await load();
    await installUpdate();
    await checkForUpdates();
    await installUpdate();
    expect(toast.loading).not.toHaveBeenCalled();
    expect(install).not.toHaveBeenCalled();
  });
});

describe('the update offer', () => {
  /** Renders what the last offer asked sonner to show. */
  function renderOffer() {
    const [content] = toast.custom.mock.lastCall as [() => ReactElement];
    render(content());
  }

  it('opens the release notes, to install from there', async () => {
    const { install } = backend('0.2.0');
    const { checkForUpdates } = await load();
    const { useReleaseNotes } = await import('./releaseNotes');
    await checkForUpdates();
    renderOffer();

    expect(screen.getByText('Version 0.2.0 is available')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'What’s new' }));
    expect(toast.dismiss).toHaveBeenCalledWith('update-offer');
    expect(renderHook(() => useReleaseNotes()).result.current).toEqual({
      kind: 'offer',
      version: '0.2.0',
      releases: RELEASES,
    });
    expect(install).not.toHaveBeenCalled();
  });

  it('flags security fixes and what to read first', async () => {
    call.mockResolvedValue({
      version: '0.2.0',
      releases: [
        {
          version: '0.2.0',
          date: '2026-11-06',
          changes: [
            { kind: 'security', en: 'Safer.', ru: null, uz: null },
            { kind: 'notice', en: 'Read this.', ru: null, uz: null },
          ],
        },
      ],
    } satisfies UpdateOffer);
    const { checkForUpdates } = await load();
    await checkForUpdates();
    renderOffer();

    expect(screen.getByText('Security fixes')).toBeInTheDocument();
    expect(screen.getByText('Read before updating')).toBeInTheDocument();
  });

  it('can be put off', async () => {
    const { install } = backend('0.2.0');
    const { checkForUpdates } = await load();
    await checkForUpdates();
    renderOffer();

    await userEvent.click(screen.getByRole('button', { name: 'Later' }));
    expect(toast.dismiss).toHaveBeenCalledWith('update-offer');
    expect(install).not.toHaveBeenCalled();
  });
});
