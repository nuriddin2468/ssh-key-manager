import { describe, expect, it } from 'vitest';
import {
  connectionString,
  DEFAULT_CHOICES,
  EMPTY_CONNECTION,
  formatForCopy,
  isVariableName,
  PRESET_GROUPS,
  presetOf,
  VARIABLE,
} from './model';

describe('presets', () => {
  it('lists every preset once', () => {
    const ids = PRESET_GROUPS.flatMap((group) => group.presets);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.sort()).toEqual(Object.keys(VARIABLE).sort());
  });

  it('carry the choices the backend needs', () => {
    expect(presetOf('databasePassword', DEFAULT_CHOICES)).toEqual({
      kind: 'databasePassword',
      length: 32,
    });
    expect(presetOf('jwtSecret', DEFAULT_CHOICES)).toEqual({
      kind: 'jwtSecret',
      encoding: 'base64url',
    });
    expect(presetOf('uuid', { ...DEFAULT_CHOICES, version: 'v7' })).toEqual({
      kind: 'uuid',
      version: 'v7',
    });
    expect(presetOf('laravelAppKey', DEFAULT_CHOICES)).toEqual({ kind: 'laravelAppKey' });
  });
});

describe('formatForCopy', () => {
  it('copies the value as it is', () => {
    expect(formatForCopy('raw', 'X', 'a b')).toBe('a b');
  });

  it('quotes for .env only what needs it', () => {
    expect(formatForCopy('env', 'APP_KEY', 'base64:Zm9v+/bar=')).toBe('APP_KEY=base64:Zm9v+/bar=');
    expect(formatForCopy('env', 'SECRET_KEY', 'a$b#c(d)')).toBe("SECRET_KEY='a$b#c(d)'");
    expect(formatForCopy('env', 'X', `it's "$x"`)).toBe('X="it\'s \\"\\$x\\""');
  });

  it('quotes for a shell export', () => {
    expect(formatForCopy('export', 'TOKEN', 'abc')).toBe("export TOKEN='abc'");
    expect(formatForCopy('export', 'X', "it's")).toBe("export X='it'\\''s'");
  });

  it('writes JSON', () => {
    expect(formatForCopy('json', 'PIN', '0420')).toBe('{"PIN":"0420"}');
    expect(JSON.parse(formatForCopy('json', 'X', 'a"b\\c'))).toEqual({ X: 'a"b\\c' });
  });

  it('takes shell variable names', () => {
    expect(isVariableName('DB_PASSWORD')).toBe(true);
    expect(isVariableName('_x1')).toBe(true);
    expect(isVariableName('1X')).toBe(false);
    expect(isVariableName('MY-KEY')).toBe(false);
    expect(isVariableName('')).toBe(false);
  });
});

describe('connectionString', () => {
  const postgres = {
    ...EMPTY_CONNECTION,
    user: 'app',
    host: 'db.example.com',
    database: 'shop',
  };

  it('builds a URL with the default port', () => {
    expect(connectionString(postgres, 'Pa55-w_rd')).toBe(
      'postgres://app:Pa55-w_rd@db.example.com:5432/shop',
    );
    expect(connectionString({ ...postgres, kind: 'mysql' }, 'p')).toBe(
      'mysql://app:p@db.example.com:3306/shop',
    );
    expect(connectionString({ ...postgres, kind: 'mongodb', port: '27018' }, 'p')).toBe(
      'mongodb://app:p@db.example.com:27018/shop',
    );
  });

  it('percent-encodes what needs it', () => {
    expect(connectionString({ ...postgres, user: 'me@corp', database: 'my db' }, 'a:b/c@d')).toBe(
      'postgres://me%40corp:a%3Ab%2Fc%40d@db.example.com:5432/my%20db',
    );
  });

  it('puts IPv6 hosts in brackets and falls back to localhost', () => {
    expect(connectionString({ ...postgres, host: '::1' }, 'p')).toBe(
      'postgres://app:p@[::1]:5432/shop',
    );
    expect(connectionString({ ...EMPTY_CONNECTION, kind: 'redis', database: '0' }, 'p')).toBe(
      'redis://:p@localhost:6379/0',
    );
  });

  it('leaves the password out on request', () => {
    expect(connectionString(postgres, null)).toBe('postgres://app@db.example.com:5432/shop');
    expect(connectionString({ ...EMPTY_CONNECTION, kind: 'redis' }, null)).toBe(
      'redis://localhost:6379',
    );
  });
});
