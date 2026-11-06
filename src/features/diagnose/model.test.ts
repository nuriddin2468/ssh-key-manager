import { describe, expect, it } from 'vitest';
import type { Cause } from '@/bindings/Cause';
import type { Diagnosis } from '@/bindings/Diagnosis';
import { explain, type SshRun, shownDiagnosis } from '@/features/hosts/login';
import { diagnosisMessage, type HostFacts, legacyOption, messageValues, NO_FACTS } from './model';

const diagnosis = (cause: Cause, hop: string | null = null): Diagnosis => ({
  cause,
  hop,
  lines: [],
});

const facts = (change: Partial<HostFacts> = {}): HostFacts => ({ ...NO_FACTS, ...change });

const rejected = diagnosis({ kind: 'keysRejected', offered: [], passwordAllowed: false });

describe('diagnosisMessage', () => {
  it('offers to install the key with a saved password, else to copy it', () => {
    const withKey = facts({ hasKey: true });
    expect(diagnosisMessage(rejected, withKey).fixes).toEqual(['copyPublicKey', 'chooseKey']);
    expect(diagnosisMessage(rejected, { ...withKey, passwordSaved: true }).fixes).toEqual([
      'installKey',
      'chooseKey',
    ]);
  });

  it('adds a locked key to the agent first', () => {
    const message = diagnosisMessage(rejected, facts({ hasKey: true, keyLocked: true }));
    expect(message.fixes).toEqual(['addToAgent', 'copyPublicKey']);
  });

  it('asks for a key when the host names none', () => {
    const message = diagnosisMessage(rejected, facts());
    expect(message.title).toBe('keysRejectedNoKey');
    expect(message.fixes).toEqual(['chooseKey']);
  });

  it('says the server takes a password too, and to unlock the vault', () => {
    const both = diagnosis({ kind: 'keysRejected', offered: [], passwordAllowed: true });
    const message = diagnosisMessage(both, facts({ hasKey: true, vaultLocked: true }));
    expect(message.title).toBe('keysRejectedPasswordToo');
    expect(message.detail).toBe('keysRejectedPasswordTooDetail');
    expect(message.unlockVault).toBe(true);
  });

  it('edits the password in the open vault, or opens it first', () => {
    const password = diagnosis({ kind: 'passwordRejected' });
    expect(diagnosisMessage(password, facts({ vaultOpen: true })).fixes).toEqual(['editPassword']);
    expect(diagnosisMessage(password, facts({ vaultLocked: true })).fixes).toEqual(['unlockVault']);
    // No vault at all: nothing to save it in yet.
    expect(diagnosisMessage(password, facts()).fixes).toEqual([]);
  });

  it('turns IdentitiesOnly on only for a host with a key', () => {
    const tooMany = diagnosis({ kind: 'tooManyAuthFailures', offered: [] });
    expect(diagnosisMessage(tooMany, facts({ hasKey: true })).fixes).toEqual(['identitiesOnly']);
    expect(diagnosisMessage(tooMany, facts()).fixes).toEqual(['chooseKey']);
  });

  it('checks the port of an unreachable server, not of one that isn’t SSH', () => {
    const timedOut = diagnosis({ kind: 'network', problem: 'timedOut', host: 'h', port: 2222 });
    const message = diagnosisMessage(timedOut, NO_FACTS);
    expect(message).toMatchObject({ title: 'timedOut', fixes: ['probe', 'openHost'] });
    expect(message.values.port).toBe('2222');
    const notSsh = diagnosis({ kind: 'network', problem: 'notSsh', host: 'h', port: 80 });
    expect(diagnosisMessage(notSsh, NO_FACTS).fixes).toEqual(['openHost']);
  });

  it('never accepts a host key, only opens the check', () => {
    for (const cause of [
      { kind: 'hostKeyUnknown', host: null },
      { kind: 'hostKeyChanged', host: null, keyType: null, fingerprint: null, knownHosts: null },
    ] satisfies Cause[]) {
      expect(diagnosisMessage(diagnosis(cause), NO_FACTS).fixes).toEqual(['checkHostKey']);
    }
  });

  it('warns that an old algorithm is weaker', () => {
    const legacy = diagnosis({
      kind: 'legacy',
      what: 'cipher',
      offer: ['aes128-cbc'],
      option: 'Ciphers',
      value: '+aes128-cbc',
    });
    const message = diagnosisMessage(legacy, NO_FACTS);
    expect(message).toMatchObject({
      title: 'legacyCipher',
      warning: 'legacyWarning',
      fixes: ['allowLegacy'],
    });
    expect(message.values.option).toBe('Ciphers +aes128-cbc');
    expect(legacyOption(legacy)).toEqual({ key: 'Ciphers', value: '+aes128-cbc' });
    expect(legacyOption(rejected)).toBeNull();
  });

  it('fixes a config file and a key by their kind', () => {
    const config = diagnosis({
      kind: 'badPermissions',
      path: '/home/a/.ssh/config',
      file: 'config',
    });
    expect(diagnosisMessage(config, NO_FACTS)).toMatchObject({
      title: 'configPermissions',
      fixes: ['fixPermissions'],
    });
    const key = diagnosis({ kind: 'badPermissions', path: '/k', file: 'privateKey' });
    expect(diagnosisMessage(key, NO_FACTS).title).toBe('keyPermissions');
  });

  it('names the host by its alias when ssh named none, and paths from home', () => {
    const timedOut = diagnosis({ kind: 'network', problem: 'timedOut', host: null, port: null });
    const values = messageValues(diagnosisMessage(timedOut, NO_FACTS), 'prod', '/home/a');
    expect(values).toMatchObject({ host: 'prod', port: '22' });
    const missing = diagnosis({ kind: 'identityFileMissing', path: '/home/a/.ssh/id_old' });
    expect(messageValues(diagnosisMessage(missing, NO_FACTS), 'prod', '/home/a').path).toBe(
      '~/.ssh/id_old',
    );
  });
});

describe('shownDiagnosis', () => {
  const run = (change: Partial<SshRun>): SshRun => ({
    ok: false,
    output: 'deploy@h: Permission denied (publickey).',
    prompts: [],
    diagnosis: rejected,
    ...change,
  });

  it('shows why a check failed', () => {
    expect(explain(run({})).kind).toBe('keysRejected');
    expect(shownDiagnosis(run({}), 'test')).toBe(rejected);
    expect(shownDiagnosis(run({ output: 'something else' }), 'vaultTest')).toBe(rejected);
  });

  it('leaves what the prompts tell to their own messages', () => {
    const missing = run({
      prompts: [{ text: '', kind: { type: 'password' }, outcome: 'missing', account: null }],
    });
    expect(shownDiagnosis(missing, 'vaultTest')).toBeNull();
    expect(shownDiagnosis(run({}), 'install')).toBeNull();
    expect(shownDiagnosis(run({ ok: true }), 'test')).toBeNull();
    expect(shownDiagnosis(run({ diagnosis: null }), 'test')).toBeNull();
  });
});
