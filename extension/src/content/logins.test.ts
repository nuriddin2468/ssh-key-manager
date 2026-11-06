import { describe, expect, it } from 'vitest';
import { forUsername } from './logins';

const login = (id: string, username: string) => ({ id, title: id, username, exact: true });

describe('the order of the logins', () => {
  const logins = [login('a', 'bob'), login('b', 'alice.w'), login('c', 'Alice'), login('d', '')];

  it('stays as it came while no username is typed', () => {
    expect(forUsername(logins, '  ')).toBe(logins);
  });

  it('puts the typed username first, then those it begins', () => {
    expect(forUsername(logins, 'alice').map((l) => l.id)).toEqual(['c', 'b', 'a', 'd']);
    expect(forUsername(logins, 'ALI').map((l) => l.id)).toEqual(['b', 'c', 'a', 'd']);
  });
});
