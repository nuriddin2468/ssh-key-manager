import { describe, expect, it } from 'vitest';
import { namesKey } from './useUnlockFix';

describe('namesKey', () => {
  it('matches the path ssh printed, cut to 100 bytes', () => {
    expect(namesKey('/Users/dev/.ssh/id_work', '/Users/dev/.ssh/id_work')).toBe(true);
    expect(namesKey('/Users/dev/.ssh/id_work', '/Users/dev/.ssh/id_work_old')).toBe(false);
    const long = `/Users/dev/${'a'.repeat(120)}/id_ed25519`;
    expect(namesKey(long.slice(0, 100), long)).toBe(true);
    expect(namesKey(long.slice(0, 99), long)).toBe(false);
  });
});
