import { describe, expect, it } from 'vitest';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostOption } from '@/bindings/HostOption';
import {
  changedLines,
  chooseKey,
  EMPTY_FORM,
  editFromForm,
  formFromHost,
  gitAccount,
  gitService,
  type HostForm,
  hostMonogram,
  hostTarget,
  optionProblem,
  optionRow,
  pointHostAtKey,
  previewLines,
  type SignInMethod,
  splitOption,
  suppressedOption,
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

describe('pointHostAtKey', () => {
  const NEW = '~/.ssh/id_ed25519_prod';

  it('adds the key first and keeps every other option', () => {
    const entry = host({
      id: 3,
      options: [
        { key: 'HostName', value: '10.0.4.12' },
        { key: 'User', value: 'deploy' },
        { key: 'ServerAliveInterval', value: '60' },
      ],
    });
    const { edit, changed } = pointHostAtKey(entry, NEW, { identitiesOnly: true });
    expect(changed).toBe(true);
    expect(edit).toEqual({
      id: 3,
      patterns: ['prod'],
      options: [
        { key: 'HostName', value: '10.0.4.12' },
        { key: 'User', value: 'deploy' },
        { key: 'IdentityFile', value: NEW },
        { key: 'IdentitiesOnly', value: 'yes' },
        { key: 'ServerAliveInterval', value: '60' },
      ],
    });
  });

  it('keeps the keys listed before, after the new one', () => {
    const entry = host({
      options: [
        { key: 'IdentityFile', value: '~/.ssh/id_old' },
        { key: 'IdentityFile', value: '~/.ssh/id_older' },
      ],
    });
    const { edit } = pointHostAtKey(entry, NEW, { identitiesOnly: false });
    expect(edit.options).toEqual([
      { key: 'IdentityFile', value: NEW },
      { key: 'IdentityFile', value: '~/.ssh/id_old' },
      { key: 'IdentityFile', value: '~/.ssh/id_older' },
    ]);
  });

  it('changes nothing when the block already names the key, in any spelling', () => {
    const entry = host({
      options: [
        { key: 'IdentityFile', value: '~/.ssh/id_old' },
        { key: 'IdentityFile', value: '/Users/dev/.ssh/id_ed25519_prod' },
        { key: 'IdentitiesOnly', value: 'yes' },
      ],
    });
    const isKey = (raw: string) => raw === NEW || raw === '/Users/dev/.ssh/id_ed25519_prod';
    expect(pointHostAtKey(entry, NEW, { identitiesOnly: true, isKey }).changed).toBe(false);
    // Declining IdentitiesOnly never removes it.
    const kept = pointHostAtKey(entry, NEW, { identitiesOnly: false, isKey });
    expect(kept.changed).toBe(false);
    expect(kept.edit.options).toContainEqual({ key: 'IdentitiesOnly', value: 'yes' });
  });

  it('only turns IdentitiesOnly on when the key is already there', () => {
    const entry = host({ options: [{ key: 'IdentityFile', value: NEW }] });
    const { edit, changed } = pointHostAtKey(entry, NEW, { identitiesOnly: true });
    expect(changed).toBe(true);
    expect(edit.options).toEqual([
      { key: 'IdentityFile', value: NEW },
      { key: 'IdentitiesOnly', value: 'yes' },
    ]);
  });

  it('lets a password-only host try the key', () => {
    const entry = host({
      options: [
        { key: 'User', value: 'admin' },
        { key: 'PubkeyAuthentication', value: 'no' },
      ],
    });
    const { edit, changed } = pointHostAtKey(entry, NEW, { identitiesOnly: true });
    expect(changed).toBe(true);
    expect(edit.options).toEqual([
      { key: 'User', value: 'admin' },
      { key: 'IdentityFile', value: NEW },
      { key: 'IdentitiesOnly', value: 'yes' },
    ]);
  });
});

const opt = (key: string, value: string): HostOption => ({ key, value });

/** The form after the user picks `method`, as the sign-in cards set it. */
const pick = (form: HostForm, method: SignInMethod): HostForm => ({ ...form, method });

describe('sign-in method', () => {
  const KEY = '~/.ssh/id_ed25519_work';
  const keyHost = host({
    id: 3,
    patterns: ['prod-api'],
    options: [
      opt('HostName', '10.0.4.12'),
      opt('User', 'ubuntu'),
      opt('IdentityFile', KEY),
      opt('IdentitiesOnly', 'yes'),
      opt('ProxyJump', 'bastion'),
      opt('ForwardAgent', 'yes'),
      opt('ServerAliveInterval', '60'),
    ],
  });
  const passwordHost = host({
    id: 4,
    patterns: ['legacy-nas'],
    options: [
      opt('HostName', '192.168.1.20'),
      opt('User', 'admin'),
      opt('PubkeyAuthentication', 'no'),
      opt('ServerAliveInterval', '30'),
    ],
  });
  const edit = (form: HostForm, id = 0) => editFromForm(form, id).options;

  describe('initial method', () => {
    it('is Password when the block has PubkeyAuthentication no, in any case', () => {
      expect(formFromHost(passwordHost).method).toBe('password');
      const shouting = host({ options: [opt('pubkeyauthentication', 'No')] });
      expect(formFromHost(shouting).method).toBe('password');
      // The block wins over a saved password.
      expect(formFromHost(passwordHost, { passwordSaved: true }).method).toBe('password');
    });

    it('is Key and password with a saved password, Key otherwise', () => {
      expect(formFromHost(keyHost, { passwordSaved: true }).method).toBe('both');
      expect(formFromHost(keyHost).method).toBe('key');
      expect(formFromHost(host({ options: [] })).method).toBe('key');
    });

    it('leaves any other PubkeyAuthentication value as an option', () => {
      const form = formFromHost(host({ options: [opt('PubkeyAuthentication', 'yes')] }));
      expect(form.method).toBe('key');
      expect(form.other.map((o) => [o.key, o.value])).toEqual([['PubkeyAuthentication', 'yes']]);
      expect(edit(form)).toEqual([opt('PubkeyAuthentication', 'yes')]);
    });

    it('has no method for patterns, which keep their sign-in options as they are', () => {
      for (const patterns of [['*'], ['*.corp.example.com']]) {
        const entry = host({
          patterns,
          isWildcard: true,
          options: [
            opt('IdentityFile', KEY),
            opt('IdentitiesOnly', 'yes'),
            opt('PubkeyAuthentication', 'no'),
            opt('User', 'deploy'),
          ],
        });
        const form = formFromHost(entry, { passwordSaved: true });
        expect(form.method).toBeNull();
        expect(form.identityFile).toBe('');
        expect(form.other.map((o) => o.key)).toEqual([
          'IdentityFile',
          'IdentitiesOnly',
          'PubkeyAuthentication',
        ]);
        expect(edit(form)).toEqual([
          opt('User', 'deploy'),
          opt('IdentityFile', KEY),
          opt('IdentitiesOnly', 'yes'),
          opt('PubkeyAuthentication', 'no'),
        ]);
      }
    });
  });

  describe('round trips', () => {
    // Each block as written comes back unchanged (up to the form's order of
    // its own options; the backend edits lines in place).
    it.each<[string, HostOption[], boolean, SignInMethod]>([
      [
        'a specific key',
        [opt('User', 'ubuntu'), opt('IdentityFile', KEY), opt('IdentitiesOnly', 'yes')],
        false,
        'key',
      ],
      ['any key', [opt('HostName', 'example.org'), opt('User', 'ubuntu')], false, 'key'],
      ['a password', [opt('User', 'admin'), opt('PubkeyAuthentication', 'no')], false, 'password'],
      [
        'a key and a password',
        [opt('User', 'ubuntu'), opt('IdentityFile', KEY), opt('IdentitiesOnly', 'yes')],
        true,
        'both',
      ],
      [
        'an IdentityFile without IdentitiesOnly',
        [opt('User', 'git'), opt('IdentityFile', KEY)],
        false,
        'key',
      ],
      [
        'IdentitiesOnly without an IdentityFile',
        [opt('User', 'git'), opt('IdentitiesOnly', 'yes')],
        false,
        'key',
      ],
      [
        'a key next to PubkeyAuthentication no',
        [
          opt('User', 'admin'),
          opt('IdentityFile', KEY),
          opt('IdentitiesOnly', 'yes'),
          opt('PubkeyAuthentication', 'no'),
        ],
        false,
        'password',
      ],
    ])('%s', (_, options, passwordSaved, method) => {
      const form = formFromHost(host({ options }), { passwordSaved });
      expect(form.method).toBe(method);
      expect(edit(form)).toEqual(options);
    });

    it('keeps a second IdentityFile with a specific key', () => {
      const options = [opt('IdentityFile', KEY), opt('IdentityFile', '~/.ssh/id_backup')];
      expect(edit(formFromHost(host({ options })))).toEqual(options);
    });
  });

  describe('mapping', () => {
    it('Password writes PubkeyAuthentication no and drops the key', () => {
      const form = pick(formFromHost(keyHost), 'password');
      expect(edit(form)).toEqual([
        opt('HostName', '10.0.4.12'),
        opt('User', 'ubuntu'),
        opt('PubkeyAuthentication', 'no'),
        opt('ProxyJump', 'bastion'),
        opt('ForwardAgent', 'yes'),
        opt('ServerAliveInterval', '60'),
      ]);
    });

    it('Password also drops repeated keys and other PubkeyAuthentication lines', () => {
      const entry = host({
        options: [
          opt('IdentityFile', KEY),
          opt('IdentityFile', '~/.ssh/id_backup'),
          opt('PubkeyAuthentication', 'yes'),
          opt('Compression', 'yes'),
        ],
      });
      const form = pick(formFromHost(entry), 'password');
      expect(edit(form)).toEqual([opt('PubkeyAuthentication', 'no'), opt('Compression', 'yes')]);
      expect(form.other.filter((row) => !suppressedOption(form, row)).map((r) => r.key)).toEqual([
        'Compression',
      ]);
    });

    it('Key removes PubkeyAuthentication no and writes the chosen key', () => {
      const anyKey = pick(formFromHost(passwordHost), 'key');
      expect(edit(anyKey)).toEqual([
        opt('HostName', '192.168.1.20'),
        opt('User', 'admin'),
        opt('ServerAliveInterval', '30'),
      ]);
      const specific = chooseKey(anyKey, KEY);
      expect(edit(specific)).toEqual([
        opt('HostName', '192.168.1.20'),
        opt('User', 'admin'),
        opt('IdentityFile', KEY),
        opt('IdentitiesOnly', 'yes'),
        opt('ServerAliveInterval', '30'),
      ]);
      expect(edit({ ...specific, identitiesOnly: false })).toContainEqual(opt('IdentityFile', KEY));
      expect(edit({ ...specific, identitiesOnly: false })).not.toContainEqual(
        opt('IdentitiesOnly', 'yes'),
      );
    });

    it('Key and password writes what Key writes', () => {
      const fromPassword = chooseKey(pick(formFromHost(passwordHost), 'both'), KEY);
      expect(edit(fromPassword)).toEqual(edit(pick(fromPassword, 'key')));
      expect(edit(fromPassword)).not.toContainEqual(opt('PubkeyAuthentication', 'no'));
      const fromKey = formFromHost(keyHost);
      expect(edit(pick(fromKey, 'both'))).toEqual(edit(fromKey));
    });

    it('any key removes IdentityFile and IdentitiesOnly, repeats included', () => {
      const entry = host({
        options: [
          opt('IdentityFile', KEY),
          opt('IdentitiesOnly', 'yes'),
          opt('IdentityFile', '~/.ssh/id_backup'),
          opt('PubkeyAuthentication', 'no'),
          opt('LogLevel', 'ERROR'),
        ],
      });
      // From Password to any key: the repeated `PubkeyAuthentication no` goes too.
      const form = chooseKey(pick(formFromHost(entry), 'key'), '');
      expect(edit(form)).toEqual([opt('LogLevel', 'ERROR')]);
    });

    it('never sets aside a row the user typed', () => {
      const form: HostForm = {
        ...pick(formFromHost(keyHost), 'password'),
        other: [optionRow('IdentityFile', '~/.ssh/extra')],
      };
      expect(edit(form)).toContainEqual(opt('IdentityFile', '~/.ssh/extra'));
    });
  });

  describe('switching back and forth', () => {
    it('Key → Password → Key restores the key and every other option', () => {
      const form = formFromHost(keyHost);
      const back = pick(pick(form, 'password'), 'key');
      expect(edit(back, 3)).toEqual(keyHost.options);
      expect(edit(pick(back, 'both'), 3)).toEqual(keyHost.options);
    });

    it('Password → Key → Password restores PubkeyAuthentication no', () => {
      const form = formFromHost(passwordHost);
      const back = pick(chooseKey(pick(form, 'key'), KEY), 'password');
      expect(edit(back, 4)).toEqual(passwordHost.options);
    });

    it('a specific key → any key → the same key restores the repeats', () => {
      const options = [
        opt('IdentityFile', KEY),
        opt('IdentitiesOnly', 'yes'),
        opt('IdentityFile', '~/.ssh/id_backup'),
      ];
      const form = formFromHost(host({ options }));
      const back = chooseKey(chooseKey(form, ''), KEY);
      expect(edit(back)).toEqual(options);
    });

    it('keeps a key the block had next to PubkeyAuthentication no', () => {
      const options = [opt('IdentityFile', KEY), opt('PubkeyAuthentication', 'no')];
      const form = formFromHost(host({ options }));
      // The key card opens on the saved key…
      expect(pick(form, 'key').identityFile).toBe(KEY);
      // …and coming back to Password writes the block as it was.
      expect(edit(pick(pick(form, 'key'), 'password'))).toEqual(options);
    });
  });

  describe('chooseKey', () => {
    it('turns "Only offer this key" on when a specific key replaces any key', () => {
      const anyKey = { ...EMPTY_FORM, identitiesOnly: false };
      expect(chooseKey(anyKey, KEY).identitiesOnly).toBe(true);
    });

    it('leaves the switch alone otherwise', () => {
      const off = { ...EMPTY_FORM, identityFile: KEY, identitiesOnly: false };
      expect(chooseKey(off, '~/.ssh/other').identitiesOnly).toBe(false);
      expect(chooseKey(off, '').identitiesOnly).toBe(false);
    });
  });

  it('a new host writes IdentitiesOnly only with a key', () => {
    const form = { ...EMPTY_FORM, patterns: 'web' };
    expect(edit(form)).toEqual([]);
    expect(edit(chooseKey(form, KEY))).toEqual([
      opt('IdentityFile', KEY),
      opt('IdentitiesOnly', 'yes'),
    ]);
  });
});

describe('changedLines', () => {
  const saved = host({
    patterns: ['prod'],
    options: [opt('HostName', '10.0.4.12'), opt('IdentityFile', '~/.ssh/a')],
  });

  it('marks new and changed lines, matching keywords in any case', () => {
    const lines = previewLines({
      id: 0,
      patterns: ['prod'],
      options: [
        opt('hostname', '10.0.4.12'),
        opt('IdentityFile', '~/.ssh/b'),
        opt('PubkeyAuthentication', 'no'),
      ],
    });
    expect(changedLines(lines, saved)).toEqual([false, false, true, true]);
  });

  it('marks a renamed header and counts each saved line once', () => {
    const lines = previewLines({
      id: 0,
      patterns: ['prod-1'],
      options: [opt('IdentityFile', '~/.ssh/a'), opt('IdentityFile', '~/.ssh/a')],
    });
    expect(changedLines(lines, saved)).toEqual([true, false, true]);
  });
});

describe('git hosts', () => {
  it('recognises services by address or alias, and git users', () => {
    expect(gitService(host({ patterns: ['github.com'] }))).toBe('GitHub');
    expect(gitService(host({ patterns: ['work'], hostName: 'ssh.github.com' }))).toBe('GitHub');
    expect(gitService(host({ patterns: ['gl'], hostName: 'GitLab.com' }))).toBe('GitLab');
    expect(gitService(host({ patterns: ['ssh.dev.azure.com'] }))).toBe('Azure DevOps');
    expect(
      gitService(host({ patterns: ['forge'], hostName: 'git.example.org', user: 'git' })),
    ).toBe('git.example.org');
    expect(gitService(host({ patterns: ['prod-api'], hostName: '10.0.4.12' }))).toBeNull();
    expect(gitService(host({ patterns: ['*.github.com'], isWildcard: true }))).toBeNull();
  });

  it('reads the account from the greeting', () => {
    expect(
      gitAccount(
        "Hi dev! You've successfully authenticated, but GitHub does not provide shell access.",
      ),
    ).toBe('dev');
    expect(gitAccount('Welcome to GitLab, @dev!')).toBe('dev');
    expect(
      gitAccount(
        "Hi there, dev! You've successfully authenticated with the key named laptop, but Forgejo does not provide shell access.",
      ),
    ).toBe('dev');
    expect(gitAccount('logged in as dev.')).toBe('dev');
    expect(gitAccount('Permission denied (publickey).')).toBeNull();
  });
});
