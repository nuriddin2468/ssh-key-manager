// Picks the light or dark theme before the first paint, in every window
// (index.html, quick.html, unlock.html), so nothing flashes in the wrong one.
// src/lib/theme.ts takes over once the app loads; the setting is the
// `appearance` field of src/lib/settings.ts. A plain script, not a module:
// modules wait until the page is parsed.
(() => {
  let appearance = 'system';
  try {
    const saved = JSON.parse(localStorage.getItem('sshkm.settings') || '{}').appearance;
    if (saved === 'light' || saved === 'dark') appearance = saved;
  } catch {
    // No storage: follow the system.
  }
  const systemLight =
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: light)').matches;
  const theme = appearance === 'system' ? (systemLight ? 'light' : 'dark') : appearance;
  const root = document.documentElement;
  root.dataset.theme = theme;
  root.style.colorScheme = theme;
  // --color-canvas in src/styles/app.css, until the styles load.
  root.style.backgroundColor = theme === 'light' ? '#eceef2' : '#0a0d14';
})();
