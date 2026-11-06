// The small window that unlocks the vault when the browser or the tray menu
// asks (src-tauri/src/browser/unlock.rs). Its capability lets it call only the
// unlock commands, so it loads none of the main window's pages.

import { QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@/i18n';
import '@/styles/app.css';
import { queryClient } from '@/api/queries';
import { platform } from '@/lib/platform';
import { UnlockWindow } from './UnlockWindow';

const root = document.getElementById('root');
if (!root) throw new Error('#root is missing from unlock.html');

if (!import.meta.env.DEV) {
  window.addEventListener('contextmenu', (event) => {
    const target = event.target as HTMLElement;
    if (!target.closest('input')) event.preventDefault();
  });
}

createRoot(root).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <div data-platform={platform} className="h-full">
        <UnlockWindow />
      </div>
    </QueryClientProvider>
  </StrictMode>,
);
