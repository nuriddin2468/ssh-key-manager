import { afterEach, describe, expect, it } from 'vitest';
import { updateSettings } from '@/lib/settings';
import { homeRoute, type Route, withBack } from './router';

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
