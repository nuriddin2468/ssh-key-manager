import { describe, expect, it } from 'vitest';
import type { HostEntry } from '@/bindings/HostEntry';
import {
  EMPTY_FORM,
  editFromForm,
  formFromHost,
  hostMonogram,
  hostTarget,
  optionProblem,
  optionRow,
  splitOption,
  validatePort,
} from './model';

function host(partial: Partial<HostEntry>): HostEntry {
  return {
    id: 0,
    kind: 'host',
    patterns: ['prod'],
    criteria: null,
    options: [],
    hostName: null,
    user: null,
    port: null,
    identityFiles: [],
    proxyJump: null,
    isWildcard: false,
    lineStart: 1,
    lineEnd: 1,
    ...partial,
  };
}

describe('host form', () => {
  it('round-trips known options and keeps the rest', () => {
    const entry = host({
      options: [
        { key: 'HostName', value: '10.0.4.12' },
        { key: 'User', value: 'ubuntu' },
        { key: 'IdentityFile', value: '~/.ssh/id_work' },
        { key: 'IdentityFile', value: '~/.ssh/id_backup' },
        { key: 'IdentitiesOnly', value: 'yes' },
        { key: 'ServerAliveInterval', value: '60' },
      ],
    });
    const form = formFromHost(entry);
    expect(form.hostName).toBe('10.0.4.12');
    expect(form.identityFile).toBe('~/.ssh/id_work');
    expect(form.identitiesOnly).toBe(true);
    expect(form.other.map((o) => o.key)).toEqual(['IdentityFile', 'ServerAliveInterval']);

    const edit = editFromForm(form, entry.id);
    expect(edit.patterns).toEqual(['prod']);
    expect(edit.options).toEqual([
      { key: 'HostName', value: '10.0.4.12' },
      { key: 'User', value: 'ubuntu' },
      { key: 'IdentityFile', value: '~/.ssh/id_work' },
      { key: 'IdentitiesOnly', value: 'yes' },
      { key: 'IdentityFile', value: '~/.ssh/id_backup' },
      { key: 'ServerAliveInterval', value: '60' },
    ]);
  });

  it('drops empty fields and splits patterns on whitespace', () => {
    const edit = editFromForm(
      { ...EMPTY_FORM, patterns: '  web  web-*  ', identitiesOnly: false },
      null,
    );
    expect(edit).toEqual({ id: null, patterns: ['web', 'web-*'], options: [] });
  });
});

describe('validatePort', () => {
  it.each([
    ['', true],
    ['22', true],
    ['65535', true],
    ['0', false],
    ['70000', false],
    ['2.5', false],
    ['ssh', false],
  ])('%s → %s', (port, valid) => {
    expect(validatePort(port)).toBe(valid);
  });
});

describe('host display', () => {
  it('describes the target with user, port and jump host', () => {
    const entry = host({ hostName: '10.0.4.12', user: 'ubuntu', port: 2222, proxyJump: 'bastion' });
    expect(hostTarget(entry, (jump) => `via ${jump}`)).toBe('ubuntu@10.0.4.12:2222 via bastion');
  });

  it('builds a monogram from the first two words', () => {
    expect(hostMonogram(host({ patterns: ['prod-api'] })).text).toBe('PA');
    expect(hostMonogram(host({ patterns: ['*'], isWildcard: true })).text).toBe('*');
  });
});

describe('other options', () => {
  it('splits a whole line typed into the name field', () => {
    expect(splitOption({ key: ' HostKeyAlias  github.com ', value: '' })).toEqual({
      key: 'HostKeyAlias',
      value: 'github.com',
    });
    const edit = editFromForm(
      {
        ...EMPTY_FORM,
        patterns: 'github.com',
        identitiesOnly: false,
        other: [optionRow('HostKeyAlias github.com')],
      },
      null,
    );
    expect(edit.options).toEqual([{ key: 'HostKeyAlias', value: 'github.com' }]);
  });

  it('flags a value without a name and a multi-word name', () => {
    expect(optionProblem({ key: '', value: 'github.com' })).toBe('missingName');
    expect(optionProblem({ key: 'Host Key', value: 'x' })).toBe('oneWord');
    expect(optionProblem({ key: 'HostKeyAlias', value: 'github.com' })).toBeNull();
    expect(optionProblem({ key: '', value: '' })).toBeNull();
  });
});
