import i18n from 'i18next';
import { describe, expect, it } from 'vitest';
import type { Failure } from '@/bindings/Failure';
import type { HostEntry } from '@/bindings/HostEntry';
import type { PromptRequest } from '@/bindings/PromptRequest';
import type { TerminalEvent } from '@/bindings/TerminalEvent';
import {
  type AccountAsk,
  afterClose,
  announcement,
  applyEvent,
  connectableAliases,
  cycle,
  failureView,
  hostIdOf,
  hostKeyHost,
  isConnectable,
  isLive,
  loadRecent,
  newTab,
  promptAccount,
  rememberRecent,
  saveRecent,
  signInText,
  statusLine,
  type Tab,
  waitingText,
} from './model';

const t = i18n.getFixedT('en');

function tab(alias = 'prod-api', change: Partial<Tab> = {}): Tab {
  return {
    ...newTab(alias),
    info: {
      id: 1,
      alias,
      user: 'ubuntu',
      host: '10.0.4.12',
      proxyJump: 'bastion',
      startedAt: '2026-11-03T10:00:00Z',
      phase: 'connecting',
    },
    id: 1,
    ...change,
  };
}

const passwordPrompt: PromptRequest = {
  id: 7,
  ask: {
    type: 'password',
    account: { user: 'ubuntu', host: '10.0.4.12' },
    why: 'savedRejected',
    save: 'update',
    foreign: false,
  },
};

function failure(change: Partial<Failure>): Failure {
  return { reason: 'other', saved: false, exitCode: 255, output: '', ...change };
}

describe('tab state', () => {
  it('follows a session from connecting to connected to ended', () => {
    let current = tab();
    expect(isLive(current)).toBe(true);

    current = applyEvent(current, { type: 'prompt', prompt: passwordPrompt }, true);
    expect(current.prompt).toEqual(passwordPrompt);
    expect(current.promptOpen).toBe(true);

    current = applyEvent(current, { type: 'promptClosed', id: 7, reason: 'answered' }, true);
    expect(current.prompt).toBeNull();

    const signIn = { password: 'user', oneTimeCode: null, key: null, passphrase: null } as const;
    current = applyEvent(current, { type: 'state', state: { phase: 'connected', signIn } }, true);
    expect(current.state.phase).toBe('connected');
    expect(current.banner).toEqual(signIn);
    expect(current.info?.phase).toBe('connected');

    current = applyEvent(
      current,
      { type: 'state', state: { phase: 'ended', exitCode: 0, durationSecs: 2520 } },
      true,
    );
    expect(isLive(current)).toBe(false);
    expect(current.id).toBeNull();
    expect(current.banner).toBeNull();
  });

  it('keeps a prompt for a tab in the background behind "Show prompt"', () => {
    const current = applyEvent(tab(), { type: 'prompt', prompt: passwordPrompt }, false);
    expect(current.prompt).not.toBeNull();
    expect(current.promptOpen).toBe(false);
  });

  it('ignores a closed prompt that is not the waiting one', () => {
    const waiting = applyEvent(tab(), { type: 'prompt', prompt: passwordPrompt }, true);
    const event: TerminalEvent = { type: 'promptClosed', id: 3, reason: 'timeout' };
    expect(applyEvent(waiting, event, true)).toBe(waiting);
  });

  it('raises the changed-key alert only for a changed key', () => {
    const changed = applyEvent(
      tab(),
      { type: 'state', state: { phase: 'failed', failure: failure({ reason: 'hostKeyChanged' }) } },
      true,
    );
    expect(changed.keyChanged).toBe(true);
    expect(changed.prompt).toBeNull();
    const refused = applyEvent(
      tab(),
      { type: 'state', state: { phase: 'failed', failure: failure({ reason: 'unreachable' }) } },
      true,
    );
    expect(refused.keyChanged).toBe(false);
  });

  it('picks the next tab when the active one closes', () => {
    const [a, b, c] = [tab('a'), tab('b'), tab('c')];
    expect(afterClose([a, b, c], b.key, b.key)).toEqual({ tabs: [a, c], active: c.key });
    expect(afterClose([a, b, c], c.key, c.key)).toEqual({ tabs: [a, b], active: b.key });
    expect(afterClose([a, b, c], a.key, c.key)).toEqual({ tabs: [b, c], active: c.key });
    expect(afterClose([a], a.key, a.key)).toEqual({ tabs: [], active: null });
  });

  it('cycles through tabs both ways', () => {
    const [a, b, c] = [tab('a'), tab('b'), tab('c')];
    expect(cycle([a, b, c], a.key, 1)).toBe(b.key);
    expect(cycle([a, b, c], c.key, 1)).toBe(a.key);
    expect(cycle([a, b, c], a.key, -1)).toBe(c.key);
    expect(cycle([], null, 1)).toBeNull();
  });
});

describe('connectable hosts', () => {
  const host = (id: number, patterns: string[], kind: HostEntry['kind'] = 'host') =>
    ({ id, kind, patterns, isWildcard: patterns.some((p) => /[*?]/.test(p)) }) as HostEntry;

  it('skips patterns, negations and Match blocks', () => {
    for (const alias of ['prod-api', 'web_01', 'git@github.com', '10.0.4.12', '[::1]:22']) {
      expect(isConnectable(alias)).toBe(true);
    }
    for (const alias of [
      '',
      '*',
      'web-*',
      '!bad',
      'a b',
      '-oProxyCommand=x',
      "x';id;'.internal",
      'a$(id)',
      'a`id`',
      'a|b',
      'a,b',
      'сервер',
    ]) {
      expect(isConnectable(alias)).toBe(false);
    }
    const hosts = [
      host(0, ['prod', 'prod.example.com']),
      host(1, ['*.corp.example.com']),
      host(2, ['staging', '!staging-old']),
      host(3, ['all'], 'match'),
      host(4, ['prod']),
    ];
    expect(connectableAliases(hosts)).toEqual(['prod', 'prod.example.com', 'staging']);
    expect(hostIdOf(hosts, 'staging')).toBe(2);
    expect(hostIdOf(hosts, 'nope')).toBeUndefined();
  });
});

describe('what the section says', () => {
  it('names what signing in used', () => {
    expect(
      signInText(
        t,
        {
          password: 'vault',
          oneTimeCode: 'vault',
          key: '/Users/dev/.ssh/id_ed25519_work',
          passphrase: 'user',
        },
        'en',
      ),
    ).toBe('Signed in: key id_ed25519_work, password and 2FA code from the vault');
    expect(
      signInText(t, { password: null, oneTimeCode: null, key: '/k/id', passphrase: 'vault' }, 'en'),
    ).toBe('Signed in: key id, passphrase from the vault');
    expect(
      signInText(t, { password: null, oneTimeCode: null, key: null, passphrase: null }, 'en'),
    ).toBe('Signed in with your SSH key');
    expect(
      signInText(t, { password: 'user', oneTimeCode: null, key: null, passphrase: null }, 'en'),
    ).toBe('Signed in');
  });

  it('builds the status line', () => {
    expect(statusLine(t, tab())).toBe('ubuntu@10.0.4.12 · via bastion · connecting…');
    const waiting = applyEvent(tab(), { type: 'prompt', prompt: passwordPrompt }, true);
    expect(statusLine(t, waiting)).toBe('ubuntu@10.0.4.12 · via bastion · waiting for your answer');
    expect(statusLine(t, tab('solo', { info: null }))).toBe('solo · connecting…');
  });

  it('says what a prompt waits for', () => {
    expect(waitingText(t, tab(), passwordPrompt.ask)).toBe(
      'the server asks for the password of ubuntu@prod-api.',
    );
    expect(
      waitingText(t, tab(), {
        type: 'passphrase',
        key: '/Users/dev/.ssh/id_rsa',
        retry: false,
        save: 'none',
      }),
    ).toBe('ssh needs the passphrase for id_rsa.');
  });

  it('names the account a prompt is for', () => {
    expect(promptAccount(tab(), passwordPrompt.ask as AccountAsk)).toBe('ubuntu@prod-api');
    const jump: AccountAsk = {
      type: 'oneTimeCode',
      question: 'Verification code:',
      retry: false,
      account: { user: 'bob', host: 'bastion.example.net' },
      foreign: true,
    };
    expect(promptAccount(tab(), jump)).toBe('bob@bastion.example.net');
    const unknown: AccountAsk = {
      type: 'other',
      text: 'Password:',
      account: null,
      foreign: false,
      unverified: true,
    };
    expect(promptAccount(tab('solo', { info: null }), unknown)).toBe('solo');
  });

  it('names the host a key is for', () => {
    expect(hostKeyHost('bastion.example.net (203.0.113.7)')).toBe('bastion.example.net');
    expect(hostKeyHost('prod (<no hostip for proxy command>)')).toBe('prod');
    expect(hostKeyHost('[10.0.0.5]:2222')).toBe('[10.0.0.5]:2222');
  });

  it('turns failure reasons into messages and fixes', () => {
    const rejected = failureView(
      t,
      tab(),
      failure({ reason: 'passwordRejected', saved: true, output: 'denied' }),
    );
    expect(rejected.title).toBe('The server didn’t accept the password');
    expect(rejected.detail).toBe(
      'The saved password for ubuntu didn’t work. It may have been changed on the server.',
    );
    expect(rejected.fixes).toEqual(['enterPassword', 'retry', 'output']);

    const typed = failureView(t, tab(), failure({ reason: 'passwordRejected' }));
    expect(typed.detail).toBe('Check the password for ubuntu and try again.');
    // No output, so no "ssh output".
    expect(typed.fixes).toEqual(['enterPassword', 'retry']);

    const changed = failureView(t, tab(), failure({ reason: 'hostKeyChanged', output: '@@@' }));
    expect(changed.title).toBe('prod-api’s key has changed');
    expect(changed.fixes[0]).toBe('compare');

    expect(failureView(t, tab(), failure({ reason: 'other', exitCode: 1 })).detail).toBe(
      'Exit code 1. See what ssh said for details.',
    );
    const notStarted = failureView(t, tab(), {
      reason: 'openFailed',
      message: 'ssh is not installed',
    });
    expect(notStarted).toEqual({
      title: 'Couldn’t start ssh',
      detail: 'ssh is not installed',
      fixes: ['retry'],
    });
    for (const reason of [
      'oneTimeCodeRejected',
      'oneTimeCodeMissing',
      'notAccepted',
      'hostKeyNotTrusted',
      'unreachable',
      'cancelled',
    ] as const) {
      const view = failureView(t, tab(), failure({ reason }));
      expect(view.title, reason).not.toContain('terminal.');
      expect(view.detail, reason).not.toContain('terminal.');
    }
  });

  it('announces state changes', () => {
    expect(
      announcement(t, tab(), { phase: 'failed', failure: failure({ reason: 'passwordRejected' }) }),
    ).toBe('prod-api: The server didn’t accept the password');
    expect(
      announcement(t, tab(), {
        phase: 'connected',
        signIn: { password: null, oneTimeCode: null, key: null, passphrase: null },
      }),
    ).toBe('prod-api connected');
    expect(announcement(t, tab(), { phase: 'connecting' })).toBeNull();
  });
});

describe('recent hosts', () => {
  function memory(): Storage {
    const data = new Map<string, string>();
    return {
      getItem: (key) => data.get(key) ?? null,
      setItem: (key, value) => void data.set(key, value),
      removeItem: (key) => void data.delete(key),
      clear: () => data.clear(),
      key: () => null,
      get length() {
        return data.size;
      },
    };
  }

  it('keeps the newest first, without duplicates, at most ten', () => {
    let list = rememberRecent([], 'a', 1);
    list = rememberRecent(list, 'b', 2);
    list = rememberRecent(list, 'a', 3);
    expect(list).toEqual([
      { alias: 'a', at: 3 },
      { alias: 'b', at: 2 },
    ]);
    for (let i = 0; i < 20; i += 1) list = rememberRecent(list, `h${i}`, 10 + i);
    expect(list).toHaveLength(10);
    expect(list[0]?.alias).toBe('h19');
  });

  it('survives a round trip and ignores junk', () => {
    const storage = memory();
    saveRecent(storage, [{ alias: 'prod', at: 5 }]);
    expect(loadRecent(storage)).toEqual([{ alias: 'prod', at: 5 }]);
    storage.setItem('sshkm.terminal.recent', '{"not":"a list"}');
    expect(loadRecent(storage)).toEqual([]);
    storage.setItem('sshkm.terminal.recent', '[{"alias":"ok","at":1},{"alias":2},"x"]');
    expect(loadRecent(storage)).toEqual([{ alias: 'ok', at: 1 }]);
    storage.setItem('sshkm.terminal.recent', 'not json');
    expect(loadRecent(storage)).toEqual([]);
    expect(loadRecent(undefined)).toEqual([]);
  });
});
