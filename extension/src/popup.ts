// The toolbar popup: where SSH Key Manager stands for this browser, and the
// one thing to do about it.

import {
  disconnect,
  hello,
  isPaired,
  launchApp,
  type Problem,
  request,
  showApp,
} from './shared/client';
import { button, h } from './shared/dom';
import { ext } from './shared/ext';
import { currentLanguage, type Key, t } from './shared/i18n';

type State =
  | 'checking'
  | 'noHost'
  | 'notRunning'
  | 'noVault'
  | 'unpaired'
  | 'revoked'
  | 'locked'
  | 'ready'
  | 'failed';

const app = document.getElementById('app') as HTMLElement;
document.documentElement.lang = currentLanguage();

function fromProblem(problem: Problem): State {
  switch (problem) {
    case 'locked':
      return 'locked';
    case 'unknownClient':
      return 'revoked';
    case 'noVault':
      return 'noVault';
    case 'notRunning':
      return 'notRunning';
    case 'noHost':
      return 'noHost';
    default:
      return 'failed';
  }
}

async function check(): Promise<State> {
  if (await isPaired()) {
    const status = await request('status');
    return status.ok ? 'ready' : fromProblem(status.problem);
  }
  const reply = await hello();
  if (!reply.ok) return fromProblem(reply.problem);
  return reply.value === 'missing' ? 'noVault' : 'unpaired';
}

const TEXT: Record<Exclude<State, 'checking'>, [Key, Key]> = {
  noHost: ['noHostTitle', 'noHostText'],
  notRunning: ['notRunningTitle', 'notRunningText'],
  noVault: ['noVaultTitle', 'noVaultText'],
  unpaired: ['unpairedTitle', 'unpairedText'],
  revoked: ['revokedTitle', 'revokedText'],
  locked: ['lockedTitle', 'lockedText'],
  ready: ['readyTitle', 'readyText'],
  failed: ['failedTitle', 'failedText'],
};

function openConnect(): void {
  void ext.tabs.create({ url: ext.runtime.getURL('connect.html') });
  window.close();
}

function openApp(): void {
  void showApp();
  window.close();
}

async function launch(): Promise<void> {
  render('checking');
  const launched = await launchApp();
  if (launched.ok) {
    for (let i = 0; i < 20; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 750));
      const reply = await hello();
      if (reply.ok || reply.problem !== 'notRunning') break;
    }
  }
  await refresh();
}

function actionsFor(state: State): HTMLElement[] {
  switch (state) {
    case 'notRunning':
      return [button(t('openApp'), () => void launch(), 'primary')];
    case 'noVault':
      return [button(t('openApp'), openApp, 'primary')];
    case 'unpaired':
      return [button(t('connect'), openConnect, 'primary')];
    case 'revoked':
      return [button(t('connectAgain'), openConnect, 'primary')];
    case 'locked':
      return [button(t('unlockInApp'), openApp, 'primary')];
    case 'ready':
      return [
        button(
          t('disconnect'),
          () => {
            render('checking');
            void disconnect().then(refresh);
          },
          'danger',
        ),
      ];
    case 'noHost':
    case 'failed':
      return [button(t('tryAgain'), () => void refresh())];
    default:
      return [];
  }
}

function render(state: State): void {
  const brand = h(
    'div',
    { className: 'brand' },
    h('img', { src: 'icons/icon-32.png', alt: '' }),
    h('span', {}, t('appName')),
  );
  let card: HTMLElement;
  if (state === 'checking') {
    card = h(
      'div',
      { className: 'card' },
      h('p', { className: 'status' }, h('span', { className: 'spinner' }), t('checking')),
    );
  } else {
    const [title, text] = TEXT[state];
    const tone = state === 'ready' ? 'dot ok' : state === 'failed' ? 'dot' : 'dot warn';
    card = h(
      'section',
      { className: 'card' },
      h(
        'div',
        { className: 'title-row' },
        h('span', { className: tone, 'aria-hidden': 'true' }),
        h('h1', {}, t(title)),
      ),
      h('p', {}, t(text)),
    );
  }
  const actions = h('div', { className: 'actions' }, ...actionsFor(state));
  app.replaceChildren(brand, card, actions);
}

async function refresh(): Promise<void> {
  render('checking');
  render(await check());
}

void refresh();
