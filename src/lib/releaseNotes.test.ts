import { renderHook } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Change } from '@/bindings/Change';

const toast = { success: vi.fn() };
vi.mock('sonner', () => ({ toast }));

// The store lives at module level, so each test starts from a fresh copy.
async function load() {
  vi.resetModules();
  return import('./releaseNotes');
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
});

it('orders versions by number', async () => {
  const { compareVersions } = await load();
  expect(compareVersions('0.10.0', '0.9.1')).toBeGreaterThan(0);
  expect(compareVersions('1.0.0', '1.0.0')).toBe(0);
  expect(compareVersions('0.7.0', '0.7.1')).toBeLessThan(0);
});

it('shows a note in the app’s language, or in English', async () => {
  const { noteText } = await load();
  const change: Change = { kind: 'new', en: 'New.', ru: 'Новое.', uz: null };
  expect(noteText(change, 'ru')).toBe('Новое.');
  expect(noteText(change, 'uz')).toBe('New.');
  expect(noteText(change, 'en-US')).toBe('New.');
});

it('ships the notes of the version it was built as', async () => {
  const { RELEASES } = await load();
  const { default: config } = await import('../../src-tauri/tauri.conf.json');
  expect(RELEASES[0]?.version).toBe(config.version);
});

describe('announceUpdate', () => {
  /** The view the toast's button opens. */
  async function whatsNew() {
    const [, options] = toast.success.mock.lastCall as [
      string,
      { action: { onClick: () => void } },
    ];
    options.action.onClick();
    const { useReleaseNotes } = await import('./releaseNotes');
    return renderHook(() => useReleaseNotes()).result.current;
  }

  it('says nothing on a fresh install', async () => {
    const { announceUpdate, RELEASES } = await load();
    announceUpdate(RELEASES[0]?.version ?? '');
    expect(toast.success).not.toHaveBeenCalled();
    expect(localStorage.getItem('sshkm.seenVersion')).toBe(RELEASES[0]?.version);
  });

  it('says nothing when the version is the one it last ran', async () => {
    const { announceUpdate } = await load();
    localStorage.setItem('sshkm.seenVersion', '0.7.0');
    announceUpdate('0.7.0');
    expect(toast.success).not.toHaveBeenCalled();
  });

  it('offers the notes of every version since the last one it ran', async () => {
    const { announceUpdate } = await load();
    localStorage.setItem('sshkm.seenVersion', '0.5.0');
    announceUpdate('0.7.0');
    expect(toast.success).toHaveBeenCalledWith('Updated to 0.7.0', expect.anything());
    const view = await whatsNew();
    expect(view?.kind === 'updated' && view.releases.map((release) => release.version)).toEqual([
      '0.7.0',
      '0.6.0',
    ]);
    expect(localStorage.getItem('sshkm.seenVersion')).toBe('0.7.0');
  });

  it('offers this version’s notes after an update from a version that kept no record', async () => {
    const { announceUpdate } = await load();
    localStorage.setItem('sshkm.settings', '{}');
    announceUpdate('0.7.0');
    const view = await whatsNew();
    expect(view?.kind === 'updated' && view.releases.map((release) => release.version)).toEqual([
      '0.7.0',
    ]);
  });
});
