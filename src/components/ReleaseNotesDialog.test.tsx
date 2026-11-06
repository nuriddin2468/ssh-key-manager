import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, expect, it, vi } from 'vitest';
import type { Release } from '@/bindings/Release';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { RELEASES, showReleaseNotes } from '@/lib/releaseNotes';
import type { UpdateState } from '@/lib/updater';
import { ReleaseNotesDialog } from './ReleaseNotesDialog';

const updater = vi.hoisted(() => ({
  state: { status: 'available', version: '0.9.0', releases: [] } as UpdateState,
  installUpdate: vi.fn(),
}));
vi.mock('@/lib/updater', () => ({
  installUpdate: updater.installUpdate,
  useUpdateState: () => updater.state,
}));

const SINCE: Release[] = [
  {
    version: '0.9.0',
    date: '2026-12-01',
    changes: [
      { kind: 'fixed', en: 'Fixed a crash.', ru: 'Исправлен сбой.', uz: null },
      { kind: 'notice', en: 'Closing the window keeps the app running.', ru: null, uz: null },
    ],
  },
  {
    version: '0.8.0',
    date: '2026-11-20',
    changes: [{ kind: 'security', en: 'Safer autofill.', ru: null, uz: null }],
  },
];

function renderDialog() {
  render(
    <TooltipProvider>
      <ReleaseNotesDialog />
    </TooltipProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  act(() => showReleaseNotes(null));
});

it('puts what to know first before an update, and installs from there', async () => {
  renderDialog();
  act(() => showReleaseNotes({ kind: 'offer', version: '0.9.0', releases: SINCE }));

  const dialog = screen.getByRole('dialog', { name: 'Version 0.9.0 is available' });
  expect(within(dialog).getByText('What changed in the 2 versions since yours.')).toBeVisible();
  expect(within(dialog).getByText('This update fixes security problems')).toBeVisible();
  const before = within(dialog).getByText('Before you update').parentElement as HTMLElement;
  expect(within(before).getByText('Closing the window keeps the app running.')).toBeVisible();
  // Once at the top is enough.
  expect(within(dialog).getAllByText('Closing the window keeps the app running.')).toHaveLength(1);
  expect(within(dialog).getByRole('region', { name: /0\.8\.0/ })).toHaveTextContent(
    'SecuritySafer autofill.',
  );
  expect(within(dialog).getByText(/saves a copy of your vault/)).toBeVisible();

  await userEvent.click(within(dialog).getByRole('button', { name: 'Update and restart' }));
  expect(updater.installUpdate).toHaveBeenCalledOnce();
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('can be put off', async () => {
  renderDialog();
  act(() => showReleaseNotes({ kind: 'offer', version: '0.9.0', releases: SINCE }));
  await userEvent.click(screen.getByRole('button', { name: 'Later' }));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  expect(updater.installUpdate).not.toHaveBeenCalled();
});

it('says so when a version came without notes', () => {
  renderDialog();
  act(() => showReleaseNotes({ kind: 'offer', version: '0.9.0', releases: [] }));
  expect(screen.getByText('This version came without release notes.')).toBeVisible();
  expect(screen.getByText('Read what changes before you update.')).toBeVisible();
});

it('lists every version it knows of, without an install button', () => {
  renderDialog();
  act(() => showReleaseNotes({ kind: 'history' }));

  const dialog = screen.getByRole('dialog', { name: 'What changed in each version' });
  for (const release of RELEASES) {
    expect(within(dialog).getByRole('region', { name: new RegExp(release.version) })).toBeVisible();
  }
  expect(within(dialog).queryByRole('button', { name: 'Update and restart' })).toBeNull();
  // Notices stay with their version here, marked as important.
  expect(within(dialog).queryByText('Before you update')).toBeNull();
  expect(within(dialog).getAllByText('Important').length).toBeGreaterThan(0);
});
