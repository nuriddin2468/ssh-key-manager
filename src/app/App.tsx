import { QueryClientProvider } from '@tanstack/react-query';
import { useEffect } from 'react';
import { Toaster } from 'sonner';
import { queryClient } from '@/api/queries';
import { Sidebar } from '@/components/layout/Sidebar';
import { TooltipProvider } from '@/components/ui/Tooltip';
import { AgentPage } from '@/features/agent/AgentPage';
import { useKeysFromVault } from '@/features/agent/useKeysFromVault';
import { AuditPage } from '@/features/audit/AuditPage';
import { HostsPage } from '@/features/hosts/HostsPage';
import { KeysPage } from '@/features/keys/KeysPage';
import { KnownHostsPage } from '@/features/known/KnownHostsPage';
import { OverviewPage } from '@/features/overview/OverviewPage';
import { useVaultFileEvents } from '@/features/passwords/files';
import { PasswordsPage } from '@/features/passwords/PasswordsPage';
import { useVaultEvents } from '@/features/passwords/useVaultEvents';
import { SettingsPage } from '@/features/settings/SettingsPage';
import { platform } from '@/lib/platform';
import { useSettings } from '@/lib/settings';
import { useAutomaticUpdates } from '@/lib/updater';
import { DialogsProvider } from './dialogs';
import { RouterProvider, useRouter } from './router';
import { useAppEvents } from './useAppEvents';

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider delayDuration={500}>
        <RouterProvider>
          <DialogsProvider>
            <Shell />
          </DialogsProvider>
        </RouterProvider>
      </TooltipProvider>
      <Toaster
        theme="dark"
        position="bottom-right"
        toastOptions={{
          className: '!bg-popover !border-white/10 !text-fg !rounded-xl !shadow-2xl',
          descriptionClassName: '!text-muted',
        }}
      />
    </QueryClientProvider>
  );
}

function Shell() {
  const { route } = useRouter();
  useAppEvents();
  useVaultEvents();
  useVaultFileEvents();
  useAutomaticUpdates(useSettings().autoUpdate);
  useKeysFromVault();

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
        {route.page === 'audit' ? <AuditPage /> : null}
        {route.page === 'passwords' ? <PasswordsPage entryId={route.entryId} /> : null}
        {route.page === 'settings' ? <SettingsPage /> : null}
      </main>
    </div>
  );
}
