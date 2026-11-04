import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { RouterProvider } from '@/app/router';
import type { BrowserStatus } from '@/bindings/BrowserStatus';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { BrowserAutofillSection } from './BrowserAutofillSection';

const api = vi.hoisted(() => ({ browserStatus: vi.fn() }));
vi.mock('@/api/commands', () => ({ api }));

function status(extra: Partial<BrowserStatus> = {}): BrowserStatus {
  return {
    enabled: true,
    listening: true,
    problem: null,
    browsers: [{ name: 'Firefox', registered: false }],
    paired: [],
    pairing: null,
    ...extra,
  };
}

function show(value: BrowserStatus) {
  api.browserStatus.mockResolvedValue(value);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <TooltipProvider>
        <RouterProvider>
          <BrowserAutofillSection />
        </RouterProvider>
      </TooltipProvider>
    </QueryClientProvider>,
  );
}

describe('browser autofill settings', () => {
  it('offers to set up a browser that is not', async () => {
    show(status());
    expect(await screen.findByText('Firefox · not set up')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Set up again' })).toBeInTheDocument();
  });

  it('explains why a copy in a temporary folder is not set up', async () => {
    show(status({ temporaryLocation: '/tmp/.mount_SSH KeAbC123/usr/bin/sshkm-app' }));
    expect(
      await screen.findByText(/running from a temporary folder \(\/tmp\/\.mount_SSH KeAbC123/),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set up again' })).not.toBeInTheDocument();
  });

  it('asks to move a copy on a disk image to Applications', async () => {
    show(
      status({
        mountedLocation: '/Volumes/SSH Key Manager/SSH Key Manager.app/Contents/MacOS/sshkm-app',
      }),
    );
    expect(
      await screen.findByText(
        /disk image.*\(\/Volumes\/SSH Key Manager\/.*Move the app to the Applications folder/,
      ),
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Set up again' })).not.toBeInTheDocument();
  });
});
