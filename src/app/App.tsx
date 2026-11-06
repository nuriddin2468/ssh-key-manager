import { QueryClientProvider } from '@tanstack/react-query';
import { useEffect } from 'react';
import { Toaster } from 'sonner';
import { queryClient, useEnvironment } from '@/api/queries';
import { SIDEBAR_INSET, Sidebar } from '@/components/layout/Sidebar';
import { ReleaseNotesDialog } from '@/components/ReleaseNotesDialog';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { AgentPage } from '@/features/agent/AgentPage';
import { useKeysFromVault } from '@/features/agent/useKeysFromVault';
import { AuditPage } from '@/features/audit/AuditPage';
import { BrowserPairing } from '@/features/browser/BrowserPairing';
import { HostsPage } from '@/features/hosts/HostsPage';
import { HostsFilePage } from '@/features/hostsFile/HostsFilePage';
import { KeysPage } from '@/features/keys/KeysPage';
import { KnownHostsPage } from '@/features/known/KnownHostsPage';
import { NearbyPage } from '@/features/nearby/NearbyPage';
import { PairingDialog } from '@/features/nearby/PairingDialog';
import { useNearbyEvents } from '@/features/nearby/queries';
import { SyncDialog } from '@/features/nearby/SyncDialog';
import { OverviewPage } from '@/features/overview/OverviewPage';
import { useVaultFileEvents } from '@/features/passwords/files';
import { PasswordsPage } from '@/features/passwords/PasswordsPage';
import { useVaultEvents } from '@/features/passwords/useVaultEvents';
import { SettingsPage } from '@/features/settings/SettingsPage';
import { TerminalPage } from '@/features/terminal/TerminalPage';
import { TerminalProvider } from '@/features/terminal/TerminalProvider';
import { platform } from '@/lib/platform';
import { announceUpdate } from '@/lib/releaseNotes';
import { useSettings } from '@/lib/settings';
import { useAutomaticUpdates } from '@/lib/updater';
import { DialogsProvider } from './dialogs';
import { ErrorBoundary } from './ErrorBoundary';
import { RouterProvider, useRouter } from './router';
import { useAppEvents } from './useAppEvents';

export function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delayDuration={500}>
          <RouterProvider>
            <DialogsProvider>
              {/* Above the pages: sessions keep running in other sections. */}
              <TerminalProvider>
                <Shell />
              </TerminalProvider>
            </DialogsProvider>
          </RouterProvider>
        </TooltipProvider>
        {/* Toasts start in the empty foot of the sidebar and run on over the page's
            left edge: action buttons sit on the right, so they stay clear. */}
        <Toaster
          theme="dark"
          position="bottom-left"
          offset={SIDEBAR_INSET}
          toastOptions={{
            className: '!bg-popover !border-white/10 !text-fg !rounded-xl !shadow-2xl',
            descriptionClassName: '!text-muted',
          }}
        />
      </QueryClientProvider>
    </ErrorBoundary>
  );
}

function Shell() {
  const { route } = useRouter();
  useAppEvents();
  useVaultEvents();
  useVaultFileEvents();
  useNearbyEvents();
  useAutomaticUpdates(useSettings().autoUpdate);
  useKeysFromVault();
  const appVersion = useEnvironment().data?.appVersion;
  useEffect(() => {
    if (appVersion) announceUpdate(appVersion);
  }, [appVersion]);

  // Popovers render in a portal under <body>; giving it the section too lets
  // dropdowns and menus pick up the page's accent colour.
  useEffect(() => {
    document.body.dataset.section = route.page;
  }, [route.page]);

  return (
    <div data-platform={platform} className="flex h-full">
      <Sidebar />
      <main
        data-section={route.page}
        className="section-glow flex min-w-0 flex-1 flex-col overflow-hidden"
      >
        {route.page === 'overview' ? <OverviewPage /> : null}
        {route.page === 'keys' ? <KeysPage keyId={route.keyId} /> : null}
        {route.page === 'hosts' ? <HostsPage hostId={route.hostId} /> : null}
        {route.page === 'agent' ? <AgentPage /> : null}
        {route.page === 'known' ? <KnownHostsPage /> : null}
        {route.page === 'hostsFile' ? (
          <HostsFilePage line={route.line} received={route.received} />
        ) : null}
        {route.page === 'audit' ? <AuditPage /> : null}
        {route.page === 'passwords' ? <PasswordsPage entryId={route.entryId} /> : null}
        {route.page === 'terminal' ? (
          <TerminalPage connect={route.connect} nonce={route.nonce} />
        ) : null}
        {route.page === 'nearby' ? <NearbyPage /> : null}
        {route.page === 'settings' ? <SettingsPage /> : null}
      </main>
      <BrowserPairing />
      <PairingDialog />
      <SyncDialog />
      <ReleaseNotesDialog />
    </div>
  );
}
