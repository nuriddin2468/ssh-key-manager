// The quick search window (src-tauri/src/quick/mod.rs). Its capability lets
// it list, copy, unlock, connect and close, so it loads none of the main
// window's pages.

import { QueryClientProvider } from '@tanstack/react-query';
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@/i18n';
import '@/styles/app.css';
import { queryClient } from '@/api/queries';
import { platform } from '@/lib/platform';
import { startTheme } from '@/lib/theme';
import { QuickWindow } from './QuickWindow';

const root = document.getElementById('root');
if (!root) throw new Error('#root is missing from quick.html');

startTheme();

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
        <QuickWindow />
      </div>
    </QueryClientProvider>
  </StrictMode>,
);
