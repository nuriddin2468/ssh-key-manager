import {
  createContext,
  type ReactNode,
  use,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { currentSettings } from '@/lib/settings';

/**
 * The app has a handful of top-level sections and no URLs to share, so a
 * typed in-memory route is simpler and safer than a URL router.
 */
export type Route =
  /** A project's page: where its hosts, logins, environments and folders are used. */
  | { page: 'project'; id: string }
  /** What is in no project. */
  | { page: 'personal' }
  /** Projects the app proposes, to accept or dismiss. */
  | { page: 'suggestions' }
  | { page: 'keys'; keyId?: string }
  | { page: 'hosts'; hostId?: number }
  | { page: 'agent' }
  | { page: 'known' }
  /** `received` shows the hosts file group that came with that pairing as a change. */
  | { page: 'hostsFile'; line?: number; received?: number }
  | { page: 'audit' }
  | { page: 'passwords'; entryId?: string }
  /** `view: 'files'`: the files environments are written to, of every project or `project`. */
  | { page: 'envs'; envId?: string; view?: 'files'; project?: string }
  /** `connect` starts a session to that alias; `nonce` makes each request a new one. */
  | { page: 'terminal'; connect?: string; nonce?: number }
  | { page: 'nearby' }
  /** `tool` opens one of the Tools page's tools (src/features/tools). */
  | { page: 'tools'; tool?: string }
  | { page: 'settings' };

export type Page = Route['page'];

/** Returns true to stop a navigation (it then asks the user itself). */
type Blocker = (next: Route) => boolean;

interface RouterValue {
  route: Route;
  /** Goes to `route` unless a page blocks it; `force` skips the page's guard. */
  navigate: (route: Route, options?: { force?: boolean }) => void;
  setBlocker: (blocker: Blocker | null) => void;
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
  if (page === 'passwords') return { page, entryId: params.get('entry') ?? undefined };
  if (page === 'envs') {
    return {
      page,
      envId: params.get('env') ?? undefined,
      view: params.get('view') === 'files' ? 'files' : undefined,
      project: params.get('project') ?? undefined,
    };
  }
  if (page === 'terminal') return { page, connect: params.get('connect') ?? undefined };
  if (page === 'tools') return { page, tool: params.get('tool') ?? undefined };
  if (page === 'project') return { page, id: params.get('project') ?? '' };
  if (
    page === 'personal' ||
    page === 'suggestions' ||
    page === 'agent' ||
    page === 'known' ||
    page === 'audit' ||
    page === 'nearby' ||
    page === 'settings'
  ) {
    return { page };
  }
  return undefined;
}

/** Where the app opens: the project used last, Personal the first time. */
export function homeRoute(): Route {
  const last = currentSettings().lastProject;
  return last && last !== 'personal' ? { page: 'project', id: last } : { page: 'personal' };
}

export function RouterProvider({ initial, children }: { initial?: Route; children: ReactNode }) {
  const [route, setRoute] = useState<Route>(() => initial ?? devRoute() ?? homeRoute());
  const blocker = useRef<Blocker | null>(null);
  const navigate = useCallback((next: Route, options?: { force?: boolean }) => {
    if (!options?.force && blocker.current?.(next)) return;
    setRoute(next);
  }, []);
  const setBlocker = useCallback((next: Blocker | null) => {
    blocker.current = next;
  }, []);
  const value = useMemo(() => ({ route, navigate, setBlocker }), [route, navigate, setBlocker]);
  return <RouterContext value={value}>{children}</RouterContext>;
}

export function useRouter(): RouterValue {
  const value = use(RouterContext);
  if (!value) throw new Error('useRouter must be used inside <RouterProvider>');
  return value;
}

/**
 * While `active`, leaving the current page is held until the user decides:
 * `pending` is where they wanted to go, `leave()` goes there, `stay()` drops it.
 */
export function useLeaveGuard(active: boolean) {
  const { route, navigate, setBlocker } = useRouter();
  const [pending, setPending] = useState<Route | null>(null);
  useEffect(() => {
    if (!active) return;
    setBlocker((next) => {
      if (next.page === route.page) return false;
      setPending(next);
      return true;
    });
    return () => setBlocker(null);
  }, [active, route.page, setBlocker]);
  return {
    pending,
    stay: () => setPending(null),
    leave: () => {
      setPending(null);
      if (pending) navigate(pending, { force: true });
    },
  };
}
