// Mock terminal sessions for `pnpm dev` (see backend.ts), so every state of
// the Terminal section can be seen in a browser:
//
// - prod-api: signs in at once (key, password and 2FA code from the vault),
//   prints a login banner and runs a tiny shell that echoes input;
// - bastion: asks to trust its new host key;
// - staging-api: asks for a password ("wrong" is refused), then a 2FA code;
// - gitlab.com: asks for a key passphrase, greets and exits;
// - legacy-nas: fails, its host key changed;
// - old-vpn: fails, the server can't be reached.

import type { FailReason } from '@/bindings/FailReason';
import type { HostEntry } from '@/bindings/HostEntry';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { PromptAsk } from '@/bindings/PromptAsk';
import type { SaveOffer } from '@/bindings/SaveOffer';
import type { SessionState } from '@/bindings/SessionState';
import type { SignIn } from '@/bindings/SignIn';
import type { TerminalEvent } from '@/bindings/TerminalEvent';
import type { TerminalInfo } from '@/bindings/TerminalInfo';
import type { VaultStatus } from '@/bindings/VaultStatus';
import { vaultHandlers } from './vault';

type Emit = (message: ArrayBuffer | TerminalEvent) => void;

interface Session {
  info: TerminalInfo;
  emit: Emit;
  /** The prompt waiting for an answer. */
  waiting: { id: number; resolve: (answer: PromptAnswer | null) => void } | null;
  /** Typed so far on the shell's current line; `null` before the shell runs. */
  line: string | null;
  connectedAt: number;
  ended: boolean;
  /** Answers to "save" once signed in. */
  saves: ('password' | 'passphrase')[];
}

const sessions = new Map<number, Session>();
let nextId = 0;
let nextPrompt = 0;
const encoder = new TextEncoder();

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function write(session: Session, text: string) {
  if (!session.ended) session.emit(encoder.encode(text).buffer as ArrayBuffer);
}

function setState(session: Session, state: SessionState) {
  if (session.ended) return;
  session.info.phase = state.phase;
  if (state.phase === 'ended' || state.phase === 'failed') {
    session.ended = true;
    sessions.delete(session.info.id);
    session.waiting?.resolve(null);
  }
  session.emit({ type: 'state', state });
}

function ask(session: Session, prompt: PromptAsk): Promise<PromptAnswer | null> {
  nextPrompt += 1;
  const id = nextPrompt;
  return new Promise((resolve) => {
    session.waiting = {
      id,
      resolve: (answer) => {
        session.waiting = null;
        if (!session.ended)
          session.emit({ type: 'promptClosed', id, reason: answer ? 'answered' : 'ended' });
        resolve(answer);
      },
    };
    session.emit({ type: 'prompt', prompt: { id, ask: prompt } });
  });
}

function vaultOffer(): SaveOffer {
  const state = (vaultHandlers.vault_status?.({}) as VaultStatus | undefined)?.state;
  return state === 'unlocked' ? 'new' : state === 'locked' ? 'locked' : 'noVault';
}

function fail(session: Session, reason: FailReason, output: string, saved = false) {
  write(session, output.replace(/\n/g, '\r\n'));
  setState(session, {
    phase: 'failed',
    failure: { reason, saved, exitCode: 255, output },
  });
}

const RESET = '\x1b[0m';

function prompt(session: Session) {
  const user = session.info.user ?? 'dev';
  write(session, `\x1b[1;32m${user}@${session.info.alias}${RESET}:\x1b[1;34m~${RESET}$ `);
}

function connect(session: Session, signIn: SignIn) {
  session.connectedAt = Date.now();
  setState(session, { phase: 'connected', signIn });
  for (const target of session.saves) {
    session.emit({ type: 'saved', target, error: null });
  }
}

function banner(session: Session) {
  write(
    session,
    [
      'Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)',
      '',
      '  System load:  0.08              Processes:             132',
      '  Usage of /:   41.2% of 78.69GB  Users logged in:       1',
      `  Memory usage: 23%               IPv4 address for eth0: ${session.info.host ?? '10.0.4.12'}`,
      '',
      'Last login: Mon Nov  2 18:04:11 2026 from 10.0.1.5',
      '',
    ].join('\r\n'),
  );
  session.line = '';
  prompt(session);
}

function end(session: Session, code: number) {
  setState(session, {
    phase: 'ended',
    exitCode: code,
    durationSecs: Math.round((Date.now() - session.connectedAt) / 1000),
  });
}

async function run(session: Session, askPassword: boolean) {
  await sleep(700);
  if (session.ended) return;
  switch (session.info.alias) {
    case 'bastion': {
      const answer = await ask(session, {
        type: 'hostKey',
        host: 'bastion.example.net (203.0.113.7)',
        keyType: 'ED25519',
        fingerprint: 'SHA256:Ka7Sd1Fg5Hj9Kl3Zx7Cv1Bn5Mq9Wr3Ty7Ui1Op5As9D',
        extra: [],
        unverified: false,
      });
      if (answer?.type !== 'trust' || !answer.trust) {
        if (!session.ended) fail(session, 'hostKeyNotTrusted', 'Host key verification failed.\n');
        return;
      }
      write(
        session,
        "Warning: Permanently added '[bastion.example.net]:2222' (ED25519) to the list of known hosts.\r\n",
      );
      await sleep(500);
      connect(session, { password: null, oneTimeCode: null, key: null, passphrase: null });
      banner(session);
      return;
    }
    case 'staging-api': {
      const offer = vaultOffer();
      let why: 'keyFailed' | 'rejected' = 'keyFailed';
      for (let attempt = 0; ; attempt += 1) {
        const answer = await ask(session, {
          type: 'password',
          account: { user: 'ubuntu', host: '10.0.8.20' },
          why: askPassword && attempt === 0 ? 'keyFailed' : why,
          save: offer,
          foreign: false,
        });
        if (session.ended) return;
        if (answer?.type !== 'secret') {
          fail(session, 'cancelled', 'ubuntu@10.0.8.20: Permission denied (publickey,password).\n');
          return;
        }
        if (answer.value !== 'wrong') {
          if (answer.save) session.saves.push('password');
          break;
        }
        await sleep(600);
        if (attempt >= 1) {
          fail(
            session,
            'passwordRejected',
            'ubuntu@10.0.8.20: Permission denied (publickey,password).\n',
          );
          return;
        }
        why = 'rejected';
      }
      const code = await ask(session, {
        type: 'oneTimeCode',
        question: 'Verification code:',
        retry: false,
        account: { user: 'ubuntu', host: '10.0.8.20' },
        foreign: false,
      });
      if (session.ended) return;
      if (code?.type !== 'secret') {
        fail(
          session,
          'oneTimeCodeMissing',
          'ubuntu@10.0.8.20: Permission denied (keyboard-interactive).\n',
        );
        return;
      }
      await sleep(400);
      connect(session, { password: 'user', oneTimeCode: 'user', key: null, passphrase: null });
      banner(session);
      return;
    }
    case 'gitlab.com': {
      const key = '/Users/dev/.ssh/id_ed25519';
      const answer = await ask(session, {
        type: 'passphrase',
        key,
        retry: false,
        save: vaultOffer(),
      });
      if (session.ended) return;
      if (answer?.type !== 'secret') {
        fail(session, 'cancelled', 'git@gitlab.com: Permission denied (publickey).\n');
        return;
      }
      if (answer.save) session.saves.push('passphrase');
      connect(session, { password: null, oneTimeCode: null, key, passphrase: 'user' });
      write(
        session,
        'PTY allocation request failed on channel 0\r\nWelcome to GitLab, @dev!\r\nConnection to gitlab.com closed.\r\n',
      );
      await sleep(300);
      end(session, 0);
      return;
    }
    case 'legacy-nas':
      fail(
        session,
        'hostKeyChanged',
        [
          '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
          '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @',
          '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@',
          'IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!',
          'Someone could be eavesdropping on you right now (man-in-the-middle attack)!',
          'The fingerprint for the ED25519 key sent by the remote host is',
          'SHA256:N3wServerKeyAfterReinstall0000000000000000.',
          'Offending ED25519 key in /Users/dev/.ssh/known_hosts:18',
          'Host key verification failed.',
          '',
        ].join('\n'),
      );
      return;
    case 'old-vpn':
      await sleep(1500);
      if (!session.ended) {
        fail(
          session,
          'unreachable',
          'ssh: connect to host vpn.example.org port 22: Operation timed out\n',
        );
      }
      return;
    default:
      connect(session, {
        password: 'vault',
        oneTimeCode: 'vault',
        key: '/Users/dev/.ssh/id_ed25519_work',
        passphrase: null,
      });
      banner(session);
  }
}

/** A few commands of a shell, enough to see output and input. */
function command(session: Session, line: string) {
  const [name] = line.trim().split(/\s+/);
  const user = session.info.user ?? 'dev';
  const out = (text: string) => write(session, `${text}\r\n`);
  switch (name) {
    case undefined:
    case '':
      break;
    case 'exit':
    case 'logout':
      out('logout');
      out(`Connection to ${session.info.host ?? session.info.alias} closed.`);
      end(session, 0);
      return;
    case 'whoami':
      out(user);
      break;
    case 'ls':
      out('\x1b[1;34mapp\x1b[0m  deploy.sh  \x1b[1;34mlogs\x1b[0m  README.md');
      break;
    case 'date':
      out(new Date().toUTCString());
      break;
    case 'clear':
      write(session, '\x1b[2J\x1b[H');
      break;
    case 'colors':
      out(
        [31, 32, 33, 34, 35, 36, 91, 92, 93, 94, 95, 96]
          .map((c) => `\x1b[${c}m■ ${c}${RESET}`)
          .join(' '),
      );
      break;
    default:
      out(`-bash: ${name}: command not found`);
  }
  prompt(session);
}

/** The shell's line editing: echo, backspace, Ctrl+C, Enter. */
function type(session: Session, data: string) {
  if (session.line === null) return;
  for (const char of data) {
    if (char === '\r') {
      write(session, '\r\n');
      const line = session.line;
      session.line = '';
      command(session, line);
      if (session.ended) return;
    } else if (char === '\x7f' || char === '\b') {
      if (session.line.length > 0) {
        session.line = session.line.slice(0, -1);
        write(session, '\b \b');
      }
    } else if (char === '\x03') {
      write(session, '^C\r\n');
      session.line = '';
      prompt(session);
    } else if (char >= ' ') {
      session.line += char;
      write(session, char);
    }
  }
}

type Handler = (args: Record<string, unknown>) => unknown;

export function terminalHandlers(hosts: () => HostEntry[]): Record<string, Handler> {
  return {
    terminal_open: ({ alias, options, events }) => {
      const name = String(alias);
      const host = hosts().find((h) => h.patterns.includes(name));
      nextId += 1;
      const session: Session = {
        info: {
          id: nextId,
          alias: name,
          user: host?.user ?? (name.includes('.com') ? 'git' : 'dev'),
          host: host?.hostName ?? name,
          proxyJump: host?.proxyJump ?? null,
          startedAt: new Date().toISOString(),
          phase: 'connecting',
        },
        emit: events as Emit,
        waiting: null,
        line: null,
        connectedAt: Date.now(),
        ended: false,
        saves: [],
      };
      sessions.set(session.info.id, session);
      const askPassword = Boolean((options as { askPassword?: boolean } | undefined)?.askPassword);
      void run(session, askPassword);
      return { ...session.info };
    },
    terminal_write: ({ id, data }) => {
      const session = sessions.get(Number(id));
      if (session) type(session, String(data));
    },
    terminal_resize: () => undefined,
    terminal_answer: ({ id, prompt: promptId, answer }) => {
      const session = sessions.get(Number(id));
      if (!session?.waiting || session.waiting.id !== promptId) return false;
      session.waiting.resolve(answer as PromptAnswer);
      return true;
    },
    terminal_close: ({ id }) => {
      const session = sessions.get(Number(id));
      if (session) end(session, 255);
    },
    terminal_list: () => [...sessions.values()].map((session) => ({ ...session.info })),
    terminal_open_external: () => undefined,
  };
}
