import { describe, expect, it } from 'vitest';
import type { ConfigFile } from '@/bindings/ConfigFile';
import type { ConnectionEvent } from '@/bindings/ConnectionEvent';
import type { HostEntry } from '@/bindings/HostEntry';
import type { HostOption } from '@/bindings/HostOption';
import {
  type CandidateInput,
  findCandidates,
  type HostProgress,
  hostMatches,
  isDefaultKeyFile,
  jumpHost,
  moved,
  namesKeyFile,
  newProgress,
  nextStep,
  oldKeyNeeds,
  type RemovalInput,
  removalBlock,
  replaceKeyEdit,
  rotationOrder,
  sameAccount,
  serverAccount,
} from './plan';

const DIR = '/home/dev/.ssh';
const OLD = `${DIR}/id_rsa`;

const opt = (key: string, value: string): HostOption => ({ key, value });

function block(id: number, patterns: string[], options: HostOption[] = []): HostEntry {
  const first = (key: string) =>
    options.find((o) => o.key.toLowerCase() === key.toLowerCase())?.value ?? null;
  const port = first('Port');
  return {
    id,
    kind: 'host',
    patterns,
    criteria: null,
    options,
    hostName: first('HostName'),
    user: first('User'),
    port: port ? Number(port) : null,
    identityFiles: options.filter((o) => o.key === 'IdentityFile').map((o) => o.value),
    proxyJump: first('ProxyJump'),
    isWildcard: patterns.some((p) => /[*?]/.test(p)),
    lineStart: 1,
    lineEnd: 1,
  };
}

/** A config of `blocks`, each `IdentityFile` resolved under `DIR`. */
function config(blocks: HostEntry[], global: string[] = []): CandidateInput['config'] {
  const resolve = (raw: string) => raw.replace(/^~\/\.ssh/, DIR);
  const usage: ConfigFile['usage'] = [
    ...global.map((raw) => ({ hostId: null, patterns: [], raw })),
    ...blocks.flatMap((host) =>
      host.identityFiles.map((raw) => ({ hostId: host.id, patterns: host.patterns, raw })),
    ),
  ].map((usage) => ({
    ...usage,
    path: resolve(usage.raw),
    resolved: true,
    exists: true,
    remote: false,
  }));
  return {
    view: { globalOptions: [], hosts: blocks, includes: [], issues: [], revision: 'r' },
    usage,
  };
}

const signedIn = (at: string): ConnectionEvent => ({ at, via: 'check', outcome: 'signedIn' });

function candidates(
  blocks: HostEntry[],
  options: { key?: string; global?: string[]; history?: CandidateInput['history'] } = {},
) {
  return findCandidates({
    key: { privatePath: options.key ?? OLD },
    config: config(blocks, options.global),
    history: options.history ?? {},
    sshDir: DIR,
  });
}

describe('hostMatches', () => {
  it('matches wildcards, case-insensitively', () => {
    expect(hostMatches(['*.corp'], 'db.CORP')).toBe(true);
    expect(hostMatches(['web-?'], 'web-1')).toBe(true);
    expect(hostMatches(['web-?'], 'web-10')).toBe(false);
    expect(hostMatches(['*'], 'anything')).toBe(true);
  });

  it('lets a negated pattern win', () => {
    expect(hostMatches(['*.corp', '!vpn.corp'], 'db.corp')).toBe(true);
    expect(hostMatches(['*.corp', '!vpn.corp'], 'vpn.corp')).toBe(false);
    expect(hostMatches(['!vpn.corp'], 'db.corp')).toBe(false);
  });

  it('takes dots and brackets literally', () => {
    expect(hostMatches(['a.b'], 'axb')).toBe(false);
    expect(hostMatches(['[a]'], '[a]')).toBe(true);
  });
});

describe('isDefaultKeyFile', () => {
  it('knows the files ssh tries by itself', () => {
    expect(isDefaultKeyFile(`${DIR}/id_rsa`, DIR)).toBe(true);
    expect(isDefaultKeyFile(`${DIR}/id_ed25519`, `${DIR}/`)).toBe(true);
    expect(isDefaultKeyFile(`${DIR}/id_rsa_work`, DIR)).toBe(false);
    expect(isDefaultKeyFile(`${DIR}/old/id_rsa`, DIR)).toBe(false);
    expect(isDefaultKeyFile('/elsewhere/id_rsa', DIR)).toBe(false);
    expect(isDefaultKeyFile(null, DIR)).toBe(false);
  });

  it('works with Windows paths', () => {
    expect(isDefaultKeyFile('C:\\Users\\dev\\.ssh\\id_dsa', 'C:\\Users\\dev\\.ssh')).toBe(true);
  });
});

describe('findCandidates', () => {
  it('suggests hosts whose own block names the key', () => {
    const found = candidates([
      block(0, ['backup'], [opt('IdentityFile', '~/.ssh/id_rsa')]),
      block(1, ['github.com'], [opt('IdentityFile', '~/.ssh/id_ed25519')]),
    ]);
    expect(found).toEqual([
      {
        hostId: 0,
        alias: 'backup',
        reason: 'config',
        passwordOnly: false,
        suggested: true,
        via: null,
        lastSignedIn: null,
      },
    ]);
  });

  it('suggests hosts a pattern block or the global section gives the key', () => {
    const found = candidates(
      [
        block(0, ['db.corp']),
        block(1, ['web.example']),
        block(2, ['*.corp', '!vpn.corp'], [opt('IdentityFile', '~/.ssh/id_rsa')]),
        block(3, ['vpn.corp']),
      ],
      { global: [] },
    );
    expect(found.map((c) => [c.alias, c.reason, c.suggested])).toEqual([
      ['db.corp', 'pattern', true],
    ]);
    const everywhere = candidates([block(0, ['db.corp']), block(1, ['web.example'])], {
      global: ['~/.ssh/id_rsa'],
    });
    expect(everywhere.map((c) => c.alias)).toEqual(['db.corp', 'web.example']);
  });

  it('lists hosts that sign in with a password alone without suggesting them', () => {
    const [nas] = candidates([
      block(0, ['nas'], [opt('IdentityFile', '~/.ssh/id_rsa'), opt('PubkeyAuthentication', 'no')]),
    ]);
    expect(nas).toMatchObject({ alias: 'nas', reason: 'config', passwordOnly: true });
    expect(nas?.suggested).toBe(false);
  });

  it('offers a default key for hosts that signed in with no IdentityFile, unticked', () => {
    const history = {
      router: [
        { at: '2026-11-01T10:00:00Z', via: 'check', outcome: 'keysRejected' } as const,
        signedIn('2026-10-30T10:00:00Z'),
      ],
      quiet: [{ at: '2026-11-01T10:00:00Z', via: 'check', outcome: 'unreachable' } as const],
    };
    const blocks = [
      block(0, ['router'], [opt('HostName', '192.168.1.1')]),
      block(1, ['quiet']),
      block(2, ['named'], [opt('IdentityFile', '~/.ssh/id_ed25519')]),
    ];
    const found = candidates(blocks, {
      history: { ...history, named: [signedIn('2026-11-01T10:00:00Z')] },
    });
    expect(found).toEqual([
      expect.objectContaining({
        alias: 'router',
        reason: 'default',
        suggested: false,
        lastSignedIn: '2026-10-30T10:00:00Z',
      }),
    ]);
    // Not a file ssh tries by itself: nothing to guess.
    expect(candidates(blocks, { key: `${DIR}/id_rsa_old`, history })).toEqual([]);
  });

  it('skips pattern and Match blocks themselves, and keys without a private file', () => {
    const blocks = [block(0, ['*.corp'], [opt('IdentityFile', '~/.ssh/id_rsa')])];
    expect(candidates(blocks)).toEqual([]);
    expect(
      findCandidates({
        key: { privatePath: null },
        config: config([block(0, ['a'], [opt('IdentityFile', '~/.ssh/id_rsa')])]),
        history: {},
        sshDir: DIR,
      }),
    ).toEqual([]);
  });

  it('keeps the jump host', () => {
    const [prod] = candidates([
      block(0, ['prod'], [opt('IdentityFile', '~/.ssh/id_rsa'), opt('ProxyJump', 'bastion')]),
    ]);
    expect(prod?.via).toBe('bastion');
  });
});

describe('jumpHost', () => {
  it('reads the host the connection goes through last', () => {
    expect(jumpHost('bastion')).toBe('bastion');
    expect(jumpHost('deploy@bastion:2222')).toBe('bastion');
    expect(jumpHost('outer,admin@inner')).toBe('inner');
    expect(jumpHost('ssh://me@[fe80::1]:22')).toBe('fe80::1');
    expect(jumpHost('none')).toBeNull();
    expect(jumpHost(null)).toBeNull();
  });
});

describe('rotationOrder', () => {
  it('moves a jump host before the hosts behind it, else keeps the order', () => {
    const hosts = [
      { alias: 'prod', via: 'deploy@bastion' },
      { alias: 'web', via: null },
      { alias: 'deep', via: 'prod' },
      { alias: 'bastion', via: null },
      { alias: 'outside', via: 'gateway' },
    ];
    expect(rotationOrder(hosts).map((h) => h.alias)).toEqual([
      'web',
      'bastion',
      'outside',
      'prod',
      'deep',
    ]);
  });

  it('survives a loop', () => {
    const hosts = [
      { alias: 'a', via: 'b' },
      { alias: 'b', via: 'a' },
    ];
    expect(rotationOrder(hosts).map((h) => h.alias)).toEqual(['a', 'b']);
  });
});

describe('replaceKeyEdit', () => {
  const isOld = (raw: string) => raw === '~/.ssh/id_rsa' || raw === `${DIR}/id_rsa`;
  const isNew = (raw: string) => raw === '~/.ssh/id_ed25519_new';
  const NEW = '~/.ssh/id_ed25519_new';

  it('puts the new key where the old one was and keeps every other line', () => {
    const host = block(
      4,
      ['backup'],
      [
        opt('HostName', 'backup.example'),
        opt('IdentityFile', '~/.ssh/id_backup'),
        opt('IdentityFile', '~/.ssh/id_rsa'),
        opt('IdentitiesOnly', 'yes'),
        opt('IdentityFile', `${DIR}/id_rsa`),
      ],
    );
    const { edit, changed } = replaceKeyEdit(host, { isOld, isNew }, NEW);
    expect(changed).toBe(true);
    expect(edit).toEqual({
      id: 4,
      patterns: ['backup'],
      options: [
        opt('HostName', 'backup.example'),
        opt('IdentityFile', '~/.ssh/id_backup'),
        opt('IdentityFile', NEW),
        opt('IdentitiesOnly', 'yes'),
      ],
    });
  });

  it('only drops the old key when the new one is listed already', () => {
    const host = block(
      0,
      ['backup'],
      [opt('IdentityFile', NEW), opt('IdentityFile', '~/.ssh/id_rsa')],
    );
    expect(replaceKeyEdit(host, { isOld, isNew }, NEW).edit.options).toEqual([
      opt('IdentityFile', NEW),
    ]);
  });

  it('names the new key in a block that named no key', () => {
    const host = block(0, ['router'], [opt('HostName', '192.168.1.1'), opt('User', 'admin')]);
    const { edit, changed } = replaceKeyEdit(host, { isOld, isNew }, NEW);
    expect(changed).toBe(true);
    expect(edit.options).toEqual([
      opt('HostName', '192.168.1.1'),
      opt('User', 'admin'),
      opt('IdentityFile', NEW),
    ]);
  });

  it('changes nothing once the block names only the new key', () => {
    const host = block(0, ['backup'], [opt('IdentityFile', NEW)]);
    expect(replaceKeyEdit(host, { isOld, isNew }, NEW)).toEqual({
      edit: { id: 0, patterns: ['backup'], options: [opt('IdentityFile', NEW)] },
      changed: false,
    });
  });
});

describe('namesKeyFile', () => {
  it('knows every way the block writes the key', () => {
    const file = config([
      block(
        0,
        ['a'],
        [opt('IdentityFile', '~/.ssh/id_rsa'), opt('IdentityFile', '%d/.ssh/id_rsa')],
      ),
      block(1, ['b'], [opt('IdentityFile', '~/.ssh/id_rsa_b')]),
    ]);
    // `%d/.ssh/id_rsa`, as ssh expands it.
    file.usage = file.usage.map((usage) =>
      usage.raw.startsWith('%d') ? { ...usage, path: OLD } : usage,
    );
    const names = namesKeyFile(file, 0, OLD, '/home/dev');
    expect(names('~/.ssh/id_rsa')).toBe(true);
    expect(names('%d/.ssh/id_rsa')).toBe(true);
    expect(names(OLD)).toBe(true);
    expect(names('~/.ssh/id_rsa_b')).toBe(false);
    expect(namesKeyFile(file, 0, null, '/home/dev')('~/.ssh/id_rsa')).toBe(false);
  });
});

describe('sameAccount', () => {
  const account = (patterns: string[], options: HostOption[] = []) =>
    serverAccount(block(0, patterns, options));

  it('compares the server, the port and the account', () => {
    const backup = account(['backup'], [opt('HostName', 'Backup.example'), opt('User', 'root')]);
    expect(
      sameAccount(
        backup,
        account(['b2'], [opt('HostName', 'backup.example'), opt('User', 'root')]),
      ),
    ).toBe(true);
    expect(
      sameAccount(backup, account(['b2'], [opt('HostName', 'backup.example'), opt('User', 'web')])),
    ).toBe(false);
    expect(
      sameAccount(
        backup,
        account(
          ['b2'],
          [opt('HostName', 'backup.example'), opt('User', 'root'), opt('Port', '2222')],
        ),
      ),
    ).toBe(false);
    expect(sameAccount(account(['nas']), account(['nas2'], [opt('HostName', 'nas')]))).toBe(true);
  });

  it('counts an account that is not written as possibly the same', () => {
    const backup = account(['backup'], [opt('HostName', 'backup.example'), opt('User', 'root')]);
    expect(sameAccount(backup, account(['b2'], [opt('HostName', 'backup.example')]))).toBe(true);
  });
});

describe('progress', () => {
  const progress = (partial: Partial<HostProgress>): HostProgress => ({
    ...newProgress('backup'),
    ...partial,
  });

  it('goes install, verify, config', () => {
    expect(nextStep(progress({}))).toBe('install');
    expect(nextStep(progress({ install: 'failed' }))).toBe('install');
    expect(nextStep(progress({ install: 'done' }))).toBe('verify');
    // Added by hand on a git service's website.
    expect(nextStep(progress({ install: 'skipped', verify: 'failed' }))).toBe('verify');
    expect(nextStep(progress({ install: 'done', verify: 'done' }))).toBe('config');
    expect(nextStep(progress({ install: 'done', verify: 'done', config: 'done' }))).toBeNull();
  });

  it('counts a host as moved once the new key signed in and the block names it', () => {
    expect(moved(progress({ install: 'done', verify: 'done' }))).toBe(false);
    expect(moved(progress({ install: 'done', verify: 'done', config: 'done' }))).toBe(true);
    // A block saved before a failed check does not count.
    expect(moved(progress({ install: 'done', verify: 'failed', config: 'done' }))).toBe(false);
  });
});

describe('oldKeyNeeds', () => {
  const done = (alias: string): HostProgress => ({
    ...newProgress(alias),
    install: 'done',
    verify: 'done',
    config: 'done',
  });

  it('is empty once every host moved and no block names the old key', () => {
    expect(oldKeyNeeds({ progress: [done('a'), done('b')], oldKey: { usedBy: [] } })).toEqual([]);
  });

  it('lists hosts not moved yet and blocks that still name the key', () => {
    const needs = oldKeyNeeds({
      progress: [done('a'), { ...newProgress('media'), install: 'done', verify: 'failed' }],
      oldKey: {
        usedBy: [
          { hostId: 5, patterns: ['legacy-nas'] },
          { hostId: 6, patterns: ['media'] },
          { hostId: null, patterns: [] },
        ],
      },
    });
    expect(needs).toEqual([
      { kind: 'notMoved', alias: 'media' },
      { kind: 'config', hostId: 5, patterns: ['legacy-nas'] },
      { kind: 'config', hostId: null, patterns: [] },
    ]);
  });
});

describe('removalBlock', () => {
  const done = (alias: string, partial: Partial<HostProgress> = {}): HostProgress => ({
    ...newProgress(alias),
    install: 'done',
    verify: 'done',
    config: 'done',
    oldOnServer: true,
    ...partial,
  });
  const hosts = [
    block(0, ['backup'], [opt('HostName', 'backup.example'), opt('User', 'root')]),
    block(1, ['backup-root'], [opt('HostName', 'backup.example')]),
    block(2, ['media'], [opt('HostName', '192.168.1.40'), opt('User', 'pi')]),
    block(3, ['*'], [opt('ServerAliveInterval', '30')]),
  ];
  const input = (partial: Partial<RemovalInput>): RemovalInput => ({
    progress: [],
    hosts,
    stillUsing: new Set(),
    ...partial,
  });

  it('allows it once the new key signed in and the block was saved', () => {
    expect(removalBlock('media', input({ progress: [done('media')] }))).toBeNull();
  });

  it('never allows it before the new key signed in', () => {
    for (const partial of [
      { verify: 'failed' },
      { verify: 'pending' },
      { config: 'pending' },
      { config: 'failed' },
    ] as const) {
      expect(removalBlock('media', input({ progress: [done('media', partial)] }))).toEqual({
        kind: 'notMoved',
      });
    }
    expect(removalBlock('media', input({}))).toEqual({ kind: 'notMoved' });
  });

  it('leaves keys added by hand to the user, and skips servers without the old key', () => {
    expect(
      removalBlock('media', input({ progress: [done('media', { install: 'skipped' })] })),
    ).toEqual({
      kind: 'manual',
    });
    expect(
      removalBlock('media', input({ progress: [done('media', { oldOnServer: false })] })),
    ).toEqual({ kind: 'notOnServer' });
    // Not read (signed in with a password, say): it may be there.
    expect(
      removalBlock('media', input({ progress: [done('media', { oldOnServer: null })] })),
    ).toBeNull();
  });

  it('waits for another alias of the same account that still needs the old key', () => {
    const notYet = { ...newProgress('backup-root'), install: 'done', verify: 'failed' } as const;
    expect(removalBlock('backup', input({ progress: [done('backup'), notYet] }))).toEqual({
      kind: 'sharedAccount',
      alias: 'backup-root',
    });
    expect(
      removalBlock('backup', input({ progress: [done('backup'), done('backup-root')] })),
    ).toBeNull();
    // Left out of the rotation, and still signing in with the old key.
    expect(
      removalBlock(
        'backup',
        input({ progress: [done('backup')], stillUsing: new Set(['backup-root']) }),
      ),
    ).toEqual({ kind: 'sharedAccount', alias: 'backup-root' });
    expect(removalBlock('backup', input({ progress: [done('backup')] }))).toBeNull();
  });
});
