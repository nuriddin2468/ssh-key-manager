import type { TFunction } from 'i18next';
import { describe, expect, it } from 'vitest';
import { type LineForm, optionsOf, problemsByField } from './model';

const t = ((key: string, values?: { pattern?: string }) =>
  values?.pattern ? `${key}:${values.pattern}` : key) as unknown as TFunction;

const form: LineForm = {
  publicKey: 'ssh-ed25519 AAAA',
  restrict: true,
  from: ' 10.0.0.0/8, ,*.corp ',
  command: '  ',
  expiry: '2027-01-31',
  noPortForwarding: false,
  noAgentForwarding: true,
  noPty: false,
  noX11Forwarding: false,
};

describe('authorized_keys line model', () => {
  it('turns the form into options', () => {
    expect(optionsOf(form)).toEqual({
      restrict: true,
      from: ['10.0.0.0/8', '*.corp'],
      command: null,
      expiryTime: '20270131',
      noPortForwarding: false,
      noAgentForwarding: true,
      noPty: false,
      noX11Forwarding: false,
    });
    expect(optionsOf({ ...form, expiry: '' }).expiryTime).toBeNull();
  });

  it('puts each problem next to its field', () => {
    expect(
      problemsByField(t, [
        { kind: 'keyInvalid' },
        { kind: 'fromInvalid', pattern: 'a b' },
        { kind: 'fromOnlyExcludes' },
        { kind: 'expiryPast' },
      ]),
    ).toEqual({
      key: 'toolSsh.line.problem.keyInvalid',
      from: 'toolSsh.line.problem.fromInvalid:a b',
      expiry: 'toolSsh.line.problem.expiryPast',
    });
  });
});
