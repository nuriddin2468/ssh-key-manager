import { act, renderHook } from '@testing-library/react';
import type { ReactNode } from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { updateSettings } from '@/lib/settings';
import {
  homeRoute,
  type Route,
  RouterProvider,
  useFreshNavigate,
  useRouter,
  withBack,
} from './router';

describe('the route the app opens on', () => {
  afterEach(() => updateSettings({ lastProject: 'personal' }));

  it('is Personal the first time and once the last project is forgotten', () => {
    expect(homeRoute()).toEqual({ page: 'personal' });
    updateSettings({ lastProject: '' });
    expect(homeRoute()).toEqual({ page: 'personal' });
  });

  it('is the project used last', () => {
    updateSettings({ lastProject: '0b6e1c52-6a3f-4c1e-9d55-1f2a3b4c5d01' });
    expect(homeRoute()).toEqual({ page: 'project', id: '0b6e1c52-6a3f-4c1e-9d55-1f2a3b4c5d01' });
  });
});

describe('the way back to a project', () => {
  const opened: Route = { page: 'hosts', hostId: 3, back: 'p1' };

  it('stays while the user picks other items in the section', () => {
    expect(withBack(opened, { page: 'hosts', hostId: 4 })).toEqual({
      page: 'hosts',
      hostId: 4,
      back: 'p1',
    });
  });

  it('stays when the editor closes or the last item goes', () => {
    expect(withBack(opened, { page: 'hosts' })).toEqual({ page: 'hosts', back: 'p1' });
    expect(withBack(opened, { page: 'hosts', hostId: undefined })).toEqual({
      page: 'hosts',
      hostId: undefined,
      back: 'p1',
    });
  });

  it('goes when the section is left or the route says so', () => {
    expect(withBack(opened, { page: 'keys', keyId: 'k' })).toEqual({ page: 'keys', keyId: 'k' });
    expect(withBack(opened, { page: 'hosts', hostId: 4, back: undefined })).toEqual({
      page: 'hosts',
      hostId: 4,
      back: undefined,
    });
  });
});

describe('navigating', () => {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <RouterProvider initial={{ page: 'hosts', hostId: 3, back: 'p1' }}>{children}</RouterProvider>
  );
  const render = () =>
    renderHook(() => ({ router: useRouter(), fresh: useFreshNavigate() }), { wrapper });

  it('keeps the way back inside the section', () => {
    const { result } = render();
    act(() => result.current.router.navigate({ page: 'hosts' }));
    expect(result.current.router.route).toEqual({ page: 'hosts', back: 'p1' });
  });

  it('drops it from the sidebar, menus and palette', () => {
    const { result } = render();
    act(() => result.current.fresh({ page: 'hosts' }));
    expect(result.current.router.route).toEqual({ page: 'hosts' });
  });
});
