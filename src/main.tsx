import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@/i18n';
import '@/styles/app.css';
import { App } from '@/app/App';
import { startTheme } from '@/lib/theme';

const root = document.getElementById('root');
if (!root) throw new Error('#root is missing from index.html');

startTheme({ native: true });

// A desktop app has its own menus; the browser's context menu only offers
// "Reload" and "Inspect", which would break the illusion.
if (!import.meta.env.DEV) {
  window.addEventListener('contextmenu', (event) => {
    const target = event.target as HTMLElement;
    if (!target.closest('input, textarea, .selectable')) event.preventDefault();
  });
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
