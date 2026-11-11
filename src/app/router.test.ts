import { describe, expect, it } from 'vitest';
import { homeRoute, type Route, withBack } from './router';
import { NAV_PAGES } from './useAppEvents';

describe('the route the app opens on', () => {
  it('is All projects, which ⌘1 opens too', () => {
    expect(homeRoute()).toEqual({ page: 'projects' });
    expect(NAV_PAGES[0]).toBe('projects');
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

  it('goes when the section is opened again or left', () => {
    expect(withBack(opened, { page: 'hosts' })).toEqual({ page: 'hosts' });
    expect(withBack(opened, { page: 'keys', keyId: 'k' })).toEqual({ page: 'keys', keyId: 'k' });
    expect(withBack(opened, { page: 'hosts', hostId: 4, back: undefined })).toEqual({
      page: 'hosts',
      hostId: 4,
      back: undefined,
    });
  });
});
