import { describe, expect, it } from 'vitest';
import { newProgress } from './plan';
import { forgetRotation, type Rotation, readRotation, saveRotation, withHost } from './store';

const rotation: Rotation = {
  oldKeyId: 'SHA256:old#id_rsa',
  oldName: 'id_rsa',
  oldFingerprint: 'SHA256:old',
  oldPath: '/home/dev/.ssh/id_rsa',
  oldPublicKey: 'ssh-rsa AAAA old',
  newKeyId: null,
  hosts: [newProgress('backup'), newProgress('media')],
  updated: '2026-11-01T10:00:00Z',
};

describe('rotation store', () => {
  it('keeps rotations in local storage until they are forgotten', () => {
    saveRotation(rotation);
    const stored = JSON.parse(localStorage.getItem('sshkm.rotations') ?? '{}');
    expect(readRotation(stored[rotation.oldKeyId])).toMatchObject({
      oldKeyId: rotation.oldKeyId,
      hosts: rotation.hosts,
    });
    forgetRotation(rotation.oldKeyId);
    expect(localStorage.getItem('sshkm.rotations')).toBeNull();
  });

  it('reads what it can of a damaged entry, and nothing of a foreign one', () => {
    expect(readRotation({ oldKeyId: 1 })).toBeNull();
    expect(readRotation(null)).toBeNull();
    const read = readRotation({
      ...rotation,
      hosts: [{ alias: 'backup', install: 'done', verify: 'bogus' }, { alias: '' }, 'media'],
      updated: undefined,
    });
    expect(read?.hosts).toEqual([{ ...newProgress('backup'), install: 'done' }]);
    expect(read?.updated).toBe('1970-01-01T00:00:00.000Z');
  });

  it('changes one host at a time', () => {
    const next = withHost(rotation, 'media', { install: 'failed' });
    expect(next.hosts.map((host) => host.install)).toEqual(['pending', 'failed']);
    expect(rotation.hosts[1]?.install).toBe('pending');
  });
});
