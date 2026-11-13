import { describe, expect, it } from 'vitest';
import type { AskedPrompt } from '@/bindings/AskedPrompt';
import type { PromptKind } from '@/bindings/PromptKind';
import type { PromptOutcome } from '@/bindings/PromptOutcome';
import { explain, loginMessage, type SshRun } from './login';

const DENIED = 'deploy@10.0.4.12: Permission denied (publickey,password).';

function prompt(kind: PromptKind, outcome: PromptOutcome, account?: string): AskedPrompt {
  const [user = '', host = ''] = account?.split('@') ?? [];
  return { text: '', kind, outcome, account: account ? { user, host } : null };
}

const password = (outcome: PromptOutcome) => prompt({ type: 'password' }, outcome);
const code = (outcome: PromptOutcome) => prompt({ type: 'oneTimeCode' }, outcome);

function run(ok: boolean, prompts: AskedPrompt[] = [], output = ''): SshRun {
  return { ok, output, prompts };
}

describe('explain', () => {
  it('reports how a successful login got in', () => {
    expect(explain(run(true, [password('answered')]))).toEqual({
      kind: 'signedIn',
      password: true,
      code: false,
    });
    expect(explain(run(true, [password('answered'), code('answered')]))).toEqual({
      kind: 'signedIn',
      password: true,
      code: true,
    });
    expect(explain(run(true))).toEqual({ kind: 'signedIn', password: false, code: false });
  });

  it('sees a rejected password when it is asked again', () => {
    expect(explain(run(false, [password('answered'), password('repeated')], DENIED))).toEqual({
      kind: 'passwordRejected',
      code: false,
    });
  });

  it('sees a rejected password when it was given once and ssh was denied', () => {
    expect(explain(run(false, [password('answered')], DENIED))).toEqual({
      kind: 'passwordRejected',
      code: false,
    });
    expect(explain(run(false, [password('answered'), code('answered')], DENIED))).toEqual({
      kind: 'passwordRejected',
      code: true,
    });
  });

  it('blames a missing 2FA code, not the password that went in first', () => {
    expect(explain(run(false, [password('answered'), code('missing')], DENIED))).toEqual({
      kind: 'otpMissing',
    });
    expect(explain(run(false, [password('answered'), code('answered'), code('repeated')]))).toEqual(
      { kind: 'otpRejected' },
    );
  });

  it('says when the user chose not to fill in a saved secret', () => {
    const withheld = run(false, [password('withheld')], DENIED);
    expect(explain(withheld)).toEqual({ kind: 'notFilled' });
    expect(loginMessage(withheld, 'install')).toEqual({
      tone: 'error',
      title: 'notFilled',
      detail: 'notFilledHint',
    });
    const passphrase = prompt({ type: 'passphrase', key: '/home/u/.ssh/id' }, 'withheld');
    expect(explain(run(false, [passphrase], DENIED))).toEqual({ kind: 'notFilled' });
  });

  it('sees an untrusted host key from the prompt or from what ssh printed', () => {
    expect(explain(run(false, [prompt({ type: 'hostKeyConfirm' }, 'declined')]))).toEqual({
      kind: 'hostKeyUnknown',
    });
    expect(explain(run(false, [], 'Host key verification failed.'))).toEqual({
      kind: 'hostKeyUnknown',
    });
    expect(
      explain(
        run(
          false,
          [],
          '@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.',
        ),
      ),
    ).toEqual({ kind: 'hostKeyChanged' });
  });

  it('names the jump host whose prompt was refused', () => {
    const asked = [prompt({ type: 'password' }, 'refused', 'admin@bastion.example.net')];
    expect(explain(run(false, asked, DENIED))).toEqual({
      kind: 'otherAccount',
      account: 'admin@bastion.example.net',
    });
  });

  it('names a key whose passphrase is not saved', () => {
    const asked = [prompt({ type: 'passphrase', key: '/Users/dev/.ssh/id_work' }, 'missing')];
    expect(explain(run(false, asked, 'dev@host: Permission denied (publickey).'))).toEqual({
      kind: 'passphraseMissing',
      key: '/Users/dev/.ssh/id_work',
    });
  });

  it('tells a failed command after signing in from a failed connection', () => {
    expect(explain(run(false, [password('answered')], 'sh: 1: cannot create .ssh'))).toEqual({
      kind: 'commandFailed',
    });
    expect(explain(run(false, [password('answered')], '(timed out)'))).toEqual({
      kind: 'failed',
    });
    expect(explain(run(false, [], DENIED))).toEqual({ kind: 'keysRejected' });
    expect(explain(run(false, [], 'ssh: connect to host x port 22: Operation timed out'))).toEqual({
      kind: 'failed',
    });
  });
});

describe('loginMessage', () => {
  it('words success for each kind of run', () => {
    const withPassword = run(true, [password('answered')]);
    expect(loginMessage(withPassword, 'vaultTest').title).toBe('signedInPassword');
    expect(loginMessage(run(true), 'vaultTest').title).toBe('signedInKey');
    expect(loginMessage(run(true), 'test').title).toBe('signedIn');
    expect(loginMessage(run(true), 'keyLogin').title).toBe('signedInKeyOnly');
    expect(loginMessage({ ...withPassword, added: true }, 'install').title).toBe('keyAdded');
    expect(loginMessage({ ...withPassword, added: false }, 'install').title).toBe('keyPresent');
  });

  it('offers the fix that matches the problem', () => {
    const rejected = loginMessage(run(false, [password('repeated')]), 'vaultTest');
    expect(rejected).toMatchObject({ tone: 'error', title: 'passwordRejected' });
    expect(rejected.action).toBe('editPassword');
    expect(loginMessage(run(false, [code('missing')]), 'install').action).toBe('addOtp');
    expect(loginMessage(run(false, [], 'Host key verification failed.'), 'test').action).toBe(
      'checkHostKey',
    );
    // A test without the vault still hears which key ssh could not open.
    const locked = [prompt({ type: 'passphrase', key: '/Users/dev/.ssh/id_work' }, 'missing')];
    expect(loginMessage(run(false, locked, DENIED), 'test')).toMatchObject({
      title: 'passphraseMissing',
      values: { key: '/Users/dev/.ssh/id_work' },
      action: 'unlockKey',
    });
  });

  it('explains a turned-down key by context', () => {
    expect(loginMessage(run(false, [], DENIED), 'keyLogin').title).toBe('keyRejected');
    expect(loginMessage(run(false, [], DENIED), 'test').detail).toBe('keysRejectedHint');
    expect(loginMessage(run(false, [], DENIED), 'test', { vaultLocked: true }).detail).toBe(
      'keysRejectedLockedHint',
    );
    expect(loginMessage(run(false, [password('answered')], 'mkdir: x'), 'install').title).toBe(
      'installFailed',
    );
  });
});
