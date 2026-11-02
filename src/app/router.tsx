import { createContext, type ReactNode, use, useCallback, useMemo, useState } from 'react';

/**
 * The app has a handful of top-level sections and no URLs to share, so a
 * typed in-memory route is simpler and safer than a URL router.
 */
export type Route =
  | { page: 'overview' }
  | { page: 'keys'; keyId?: string }
  | { page: 'hosts'; hostId?: number }
  | { page: 'agent' }
  | { page: 'known' }
  | { page: 'hostsFile'; line?: number }
  | { page: 'audit' }
  | { page: 'settings' };

export type Page = Route['page'];

interface RouterValue {
  route: Route;
  navigate: (route: Route) => void;
}

const RouterContext = createContext<RouterValue | null>(null);

/**
 * In `pnpm dev` only, `?page=keys&key=<id>` or `?page=hosts&host=3` opens a
 * screen directly, e.g. for screenshots. Production builds ignore the URL.
 */
function devRoute(): Route | undefined {
  if (!import.meta.env.DEV) return undefined;
  const params = new URLSearchParams(window.location.search);
  const page = params.get('page');
  if (page === 'keys') return { page, keyId: params.get('key') ?? undefined };
  if (page === 'hosts')
    return { page, hostId: params.has('host') ? Number(params.get('host')) : undefined };
  if (page === 'hostsFile')
    return { page, line: params.has('line') ? Number(params.get('line')) : undefined };
  if (
    page === 'overview' ||
    page === 'agent' ||
    page === 'known' ||
    page === 'audit' ||
    page === 'settings'
  ) {
    return { page };
  }
  return undefined;
}

export function RouterProvider({ initial, children }: { initial?: Route; children: ReactNode }) {
  const [route, setRoute] = useState<Route>(() => initial ?? devRoute() ?? { page: 'overview' });
  const navigate = useCallback((next: Route) => setRoute(next), []);
  const value = useMemo(() => ({ route, navigate }), [route, navigate]);
  return <RouterContext value={value}>{children}</RouterContext>;
}

export function useRouter(): RouterValue {
  const value = use(RouterContext);
  if (!value) throw new Error('useRouter must be used inside <RouterProvider>');
  return value;
}
