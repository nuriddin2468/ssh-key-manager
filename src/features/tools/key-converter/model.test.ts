import { describe, expect, it } from 'vitest';
import type { KeyFileInfo } from '@/bindings/KeyFileInfo';
import { algorithmText, fileNameProblem, pemAllowed, uniqueName } from './model';

const info: KeyFileInfo = {
  format: 'ppk3',
  algorithm: 'rsa',
  bits: 3072,
  comment: '',
  encrypted: false,
  opened: true,
  fingerprints: null,
  suggestedName: 'work',
};

describe('key converter model', () => {
  it('names the key and the formats it allows', () => {
    expect(algorithmText(info)).toBe('RSA 3072');
    expect(algorithmText({ ...info, algorithm: null })).toBe('');
    expect(pemAllowed(info)).toBe(true);
    expect(pemAllowed({ ...info, algorithm: 'ed25519' })).toBe(false);
  });

  it('suggests a free, valid file name', () => {
    expect(uniqueName('server key (old)', [])).toBe('server-key-old');
    expect(uniqueName('work', ['work', 'work-2'])).toBe('work-3');
    expect(uniqueName('...', [])).toBe('key');
    expect(fileNameProblem('work', ['work'])).toBe('already_exists');
    for (const bad of ['', '.hidden', 'a/b', 'id.pub', 'config', 'a b']) {
      expect(fileNameProblem(bad, [])).toBe('invalid_input');
    }
    expect(fileNameProblem('id_ed25519_putty', [])).toBeNull();
  });
});
