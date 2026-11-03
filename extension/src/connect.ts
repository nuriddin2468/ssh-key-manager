// The connect page: pairs this browser with SSH Key Manager. It shows the
// code the app shows too, then waits until the user decides in the app. A
// tab rather than the popup, which closes as soon as the app takes focus.

import { hello, launchApp, type Problem, pair, showApp } from './shared/client';
import { button, h } from './shared/dom';
import { currentLanguage, type Key, t } from './shared/i18n';

const app = document.getElementById('app') as HTMLElement;
document.documentElement.lang = currentLanguage();

const PROBLEMS: Partial<Record<Problem, Key>> = {
  denied: 'connectDenied',
  expired: 'connectExpired',
  busy: 'connectBusy',
  locked: 'connectLocked',
  notRunning: 'connectNotRunning',
  noVault: 'noVaultText',
  noHost: 'noHostText',
};

function brand(): HTMLElement {
  return h(
    'div',
    { className: 'brand' },
    h('img', { src: 'icons/icon-32.png', alt: '' }),
    h('span', {}, t('appName')),
  );
}

function show(...card: (Node | string | null)[]): void {
  // The button just pressed goes away: keep keyboard focus in the card.
  const hadFocus = app.contains(document.activeElement);
  const section = h('section', { className: 'card', tabindex: '-1' }, ...card);
  app.replaceChildren(brand(), section);
  if (hadFocus) section.focus({ preventScroll: true });
}

function heading(key: Key = 'connectTitle'): HTMLElement {
  return h('h1', {}, t(key));
}

function grouped(code: string): string {
  return `${code.slice(0, 3)} ${code.slice(3)}`;
}

function problem(found: Problem): void {
  const actions = h('div', { className: 'actions' });
  if (found === 'notRunning') {
    actions.append(
      button(
        t('openApp'),
        () => void launchApp().then(() => setTimeout(() => void start(), 1500)),
        'primary',
      ),
    );
  } else if (found === 'locked' || found === 'noVault') {
    actions.append(button(t('openApp'), () => void showApp()));
  }
  actions.append(
    button(t('tryAgain'), () => void start(), found === 'notRunning' ? 'secondary' : 'primary'),
  );
  show(
    heading(),
    h('p', { className: 'problem', role: 'alert' }, t(PROBLEMS[found] ?? 'connectFailed')),
    actions,
  );
}

async function connect(): Promise<void> {
  show(
    heading(),
    h('p', { className: 'status' }, h('span', { className: 'spinner' }), t('checking')),
  );
  const result = await pair((code) => {
    show(
      heading(),
      h('p', {}, t('connectCompare')),
      h('p', { className: 'status' }, t('connectCode')),
      h(
        'div',
        { className: 'code', role: 'img', 'aria-label': code.split('').join(' ') },
        grouped(code),
      ),
      h(
        'p',
        { className: 'status', role: 'status' },
        h('span', { className: 'spinner' }),
        t('connectWaiting'),
      ),
    );
  });
  if (result.ok) {
    show(
      h('h1', { className: 'success' }, t('readyTitle')),
      h('p', { role: 'status' }, t('connectDoneText')),
    );
  } else {
    problem(result.problem);
  }
}

async function start(): Promise<void> {
  show(
    heading(),
    h('p', { className: 'status' }, h('span', { className: 'spinner' }), t('checking')),
  );
  const reply = await hello();
  if (!reply.ok) return problem(reply.problem);
  if (reply.value === 'missing') return problem('noVault');
  if (reply.value === 'locked') return problem('locked');
  show(
    heading(),
    h('p', {}, t('connectIntro')),
    h(
      'div',
      { className: 'actions' },
      button(t('connect'), () => void connect(), 'primary'),
    ),
  );
}

void start();
