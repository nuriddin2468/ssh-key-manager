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
  | { page: 'audit' }
  | { page: 'settings' };

export type Page = Route['page'];

interface RouterValue {
  route: Route;
  navigate: (route: Route) => void;
}

const RouterContext = createContext<RouterValue | null>(null);

export function RouterProvider({ initial, children }: { initial?: Route; children: ReactNode }) {
  const [route, setRoute] = useState<Route>(initial ?? { page: 'overview' });
  const navigate = useCallback((next: Route) => setRoute(next), []);
  const value = useMemo(() => ({ route, navigate }), [route, navigate]);
  return <RouterContext value={value}>{children}</RouterContext>;
}

export function useRouter(): RouterValue {
  const value = use(RouterContext);
  if (!value) throw new Error('useRouter must be used inside <RouterProvider>');
  return value;
}
