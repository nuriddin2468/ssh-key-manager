import { describe, expect, it } from 'vitest';
import type { EnvFilesOverview } from '@/bindings/EnvFilesOverview';
import type { FolderPlace } from '@/bindings/FolderPlace';
import type { PartPlace } from '@/bindings/PartPlace';
import {
  envFolderText,
  fileForStage,
  folderChange,
  folderOptions,
  placeOfEnv,
  placeOfPart,
  placeText,
  startOption,
  unmanagedIn,
} from './places';

const part = (patch: Partial<PartPlace>): PartPlace => ({
  part: 'api',
  source: 'file',
  environments: ['a-local', 'a-prod'],
  local: 'a-local',
  automatic: { folder: '~/shop', path: 'apps/api' },
  automaticFromFile: true,
  suggested: [{ folder: '~/shop', path: 'apps/api' }],
  ...patch,
});

const place = (path: string, parts: PartPlace[]): FolderPlace => ({
  folder: '~/shop',
  path,
  parts,
  terminal: parts.flatMap((p) => p.local ?? []),
  missing: false,
});

const unmanaged = (path: string) => ({
  project: 'p',
  file: { folder: '~/shop', path },
  location: `/Users/dev/shop/${path}`,
  cloud: null,
  git: null,
});

const overview: EnvFilesOverview = {
  files: [],
  unmanaged: [unmanaged('apps/admin/.env'), unmanaged('apps/admin/.env.local'), unmanaged('.env')],
  truncated: false,
};

describe('places', () => {
  it('say where a folder is: the path in the folder, which folder when there are several', () => {
    const api = { folder: '~/code/shop', path: 'apps/api' };
    expect(placeText(api, ['~/code/shop'])).toBe('apps/api');
    expect(placeText(api, ['~/code/shop', '~/code/infra'])).toBe('shop/apps/api');
    expect(placeText({ folder: '~/code/shop', path: '' }, ['~/code/shop'])).toBe('~/code/shop');
    // An environment's row: nothing for the one folder itself.
    expect(envFolderText({ folder: '~/code/shop', path: '' }, ['~/code/shop'])).toBeNull();
    expect(envFolderText({ folder: '~/code/shop', path: '' }, ['~/a', '~/code/shop'])).toBe('shop');
  });

  it('find an environment’s place and a part’s, without case', () => {
    const places = [place('', []), place('apps/api', [part({})])];
    expect(placeOfEnv(places, 'a-prod')?.place.path).toBe('apps/api');
    expect(placeOfEnv(places, 'other')).toBeUndefined();
    expect(placeOfPart(places, ' API ')?.part.part).toBe('api');
  });

  it('offer automatic, the folder set, the files’ folders and the project’s, once each', () => {
    const set = { place: place('services/api', []), part: part({ source: 'set' }) };
    const options = folderOptions({
      part: set,
      folders: ['~/shop', '~/infra'],
      overview,
      picked: { folder: '~/infra', path: 'tools' },
    });
    expect(options.map((o) => [o.value.replace('\n', ' '), o.hint])).toEqual([
      ['auto', 'automatic'],
      ['~/shop services/api', 'current'],
      ['~/shop apps/api', 'files'],
      ['~/shop apps/admin', 'files'],
      ['~/shop ', 'files'],
      ['~/infra ', 'project'],
      ['~/infra tools', 'picked'],
    ]);
    // Starting on the folder set, saving it changes nothing; automatic takes it out.
    const start = startOption(set);
    expect(start).toBe('~/shop\nservices/api');
    expect(folderChange(options, start, start)).toBeNull();
    expect(folderChange(options, 'auto', start)).toEqual({ type: 'automatic' });
    expect(folderChange(options, '~/shop\napps/admin', start)).toEqual({
      type: 'folder',
      folder: '~/shop',
      path: 'apps/admin',
    });
    // A new part starts on automatic.
    expect(startOption(undefined)).toBe('auto');
  });

  it('offer a stage the .env file named for it, else .env', () => {
    const admin = unmanagedIn(overview, { folder: '~/shop', path: 'apps/admin' });
    expect(admin.map((f) => f.file.path)).toEqual(['apps/admin/.env', 'apps/admin/.env.local']);
    expect(fileForStage(admin, 'local')?.file.path).toBe('apps/admin/.env.local');
    expect(fileForStage(admin, 'dev')?.file.path).toBe('apps/admin/.env.local');
    expect(fileForStage([unmanaged('x/.env')], 'dev')?.file.path).toBe('x/.env');
    // Another stage's file is never offered to a local one.
    for (const other of ['x/.env.production', 'x/.env.production.local', 'x/.env.staging']) {
      expect(fileForStage([unmanaged(other)], 'local')).toBeUndefined();
    }
    expect(fileForStage([unmanaged('x/.env.development.local')], 'dev')?.file.path).toBe(
      'x/.env.development.local',
    );
    expect(unmanagedIn(overview, null)).toEqual([]);
  });
});
