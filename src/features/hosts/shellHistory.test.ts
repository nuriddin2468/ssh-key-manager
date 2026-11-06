import { describe, expect, it } from 'vitest';
import type { HostSuggestion } from '@/bindings/HostSuggestion';
import { editFromForm } from './model';
import { formFromSuggestion, suggestionTarget } from './shellHistory';

function suggestion(partial: Partial<HostSuggestion>): HostSuggestion {
  return {
    id: '0'.repeat(32),
    alias: 'root-10-0-0-5',
    host: '10.0.0.5',
    user: null,
    port: null,
    identityFile: null,
    proxyJump: null,
    forwardAgent: false,
    options: [],
    uses: 1,
    lastUsed: null,
    shells: ['zsh'],
    ...partial,
  };
}

describe('suggestionTarget', () => {
  it('reads like the command', () => {
    expect(suggestionTarget(suggestion({ user: 'root', port: 2222 }))).toBe('root@10.0.0.5:2222');
    expect(suggestionTarget(suggestion({}))).toBe('10.0.0.5');
    expect(suggestionTarget(suggestion({ host: '2001:db8::1', user: 'admin' }))).toBe(
      'admin@[2001:db8::1]',
    );
    expect(suggestionTarget(suggestion({ host: '::1', port: 22 }))).toBe('[::1]:22');
  });
});

describe('formFromSuggestion', () => {
  it('fills the Add Host form', () => {
    const form = formFromSuggestion(
      suggestion({
        user: 'root',
        port: 2222,
        identityFile: '~/.ssh/id_work',
        proxyJump: 'bastion',
        options: [
          { key: 'IdentityFile', value: '~/.ssh/old' },
          { key: 'ServerAliveInterval', value: '30' },
        ],
      }),
    );
    expect(form).toMatchObject({
      patterns: 'root-10-0-0-5',
      hostName: '10.0.0.5',
      user: 'root',
      port: '2222',
      method: 'key',
      identityFile: '~/.ssh/id_work',
      identitiesOnly: true,
      proxyJump: 'bastion',
      forwardAgent: false,
      saved: null,
    });
    expect(editFromForm(form, null)).toEqual({
      id: null,
      patterns: ['root-10-0-0-5'],
      options: [
        { key: 'HostName', value: '10.0.0.5' },
        { key: 'User', value: 'root' },
        { key: 'Port', value: '2222' },
        { key: 'IdentityFile', value: '~/.ssh/id_work' },
        { key: 'IdentitiesOnly', value: 'yes' },
        { key: 'ProxyJump', value: 'bastion' },
        { key: 'IdentityFile', value: '~/.ssh/old' },
        { key: 'ServerAliveInterval', value: '30' },
      ],
    });
  });

  it('gives IdentitiesOnly and ForwardAgent their controls', () => {
    const form = formFromSuggestion(
      suggestion({
        options: [
          { key: 'IdentitiesOnly', value: 'no' },
          { key: 'ForwardAgent', value: 'yes' },
          { key: 'Compression', value: 'yes' },
        ],
      }),
    );
    expect(form.identitiesOnly).toBe(false);
    expect(form.forwardAgent).toBe(true);
    expect(form.other.map((row) => [row.key, row.value])).toEqual([['Compression', 'yes']]);
    expect(editFromForm(form, null).options).toEqual([
      { key: 'HostName', value: '10.0.0.5' },
      { key: 'ForwardAgent', value: 'yes' },
      { key: 'Compression', value: 'yes' },
    ]);
  });
});
