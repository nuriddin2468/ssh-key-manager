import { flushSync } from 'react-dom';

/**
 * Runs `update` (a React state change) inside a view transition, so elements
 * with a `view-transition-name` move to their new place; then `after`, on the
 * new DOM. Without view transitions in the webview, or with reduced motion,
 * both run at once and there is no transition.
 */
export function withViewTransition(update: () => void, after?: () => void): ViewTransition | null {
  const run = () => {
    flushSync(update);
    after?.();
  };
  const reduced = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
  if (typeof document.startViewTransition !== 'function' || reduced) {
    run();
    return null;
  }
  return document.startViewTransition(run);
}
