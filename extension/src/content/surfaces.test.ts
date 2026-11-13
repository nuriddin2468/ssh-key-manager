import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireTrusted, press } from '../test/user';
import {
  drawnText,
  LoginMenu,
  SaveBanner,
  SETTLE_MS,
  Settling,
  SignInBanner,
  uncovered,
  uncoveredAt,
} from './surfaces';

const LOGIN = { id: 'e1', title: 'Bank', username: 'alice', exact: true };

function menu(): LoginMenu {
  return new LoginMenu({ onPick: vi.fn(), onUnlock: vi.fn(), onLeave: vi.fn() });
}

function settlingOf(surface: LoginMenu | SaveBanner | SignInBanner): Settling {
  return (surface as unknown as { settling: Settling }).settling;
}

function field(top: number): HTMLInputElement {
  const input = document.createElement('input');
  document.body.append(input);
  const rect = { left: 10, top, width: 200, height: 30, right: 210, bottom: top + 30 };
  input.getBoundingClientRect = () => ({ ...rect, x: 10, y: top, toJSON: () => rect });
  return input;
}

afterEach(() => {
  document.body.innerHTML = '';
  for (const node of [...document.documentElement.children]) {
    if (node !== document.head && node !== document.body) node.remove();
  }
  delete (document as { elementFromPoint?: unknown }).elementFromPoint;
});

describe('settling', () => {
  it('counts a choice only a while after the surface appeared, moved or took focus', () => {
    let now = 1000;
    const settling = new Settling(() => now);
    expect(settling.settled).toBe(false);
    settling.restart();
    now += SETTLE_MS - 1;
    expect(settling.settled).toBe(false);
    now += 1;
    expect(settling.settled).toBe(true);
    settling.restart();
    expect(settling.settled).toBe(false);
  });

  it('starts over when the menu is shown or moves, not when the arrow keys move into it', () => {
    const clock = vi.spyOn(performance, 'now').mockReturnValue(10_000);
    const logins = menu();
    const input = field(100);
    logins.showLogins(input, [LOGIN]);
    const settling = settlingOf(logins);
    expect(settling.settled).toBe(false);
    clock.mockReturnValue(10_000 + SETTLE_MS);
    expect(settling.settled).toBe(true);

    // A scroll that leaves it in place changes nothing; one that moves it does.
    window.dispatchEvent(new Event('scroll'));
    expect(settling.settled).toBe(true);
    input.getBoundingClientRect = () => {
      const rect = { left: 10, top: 300, width: 200, height: 30, right: 210, bottom: 330 };
      return { ...rect, x: 10, y: 300, toJSON: () => rect };
    };
    window.dispatchEvent(new Event('scroll'));
    expect(settling.settled).toBe(false);

    clock.mockReturnValue(20_000);
    expect(settling.settled).toBe(true);
    logins.focusFirst();
    expect(settling.settled).toBe(true);
  });

  it('starts over when the banner is shown', () => {
    vi.spyOn(performance, 'now').mockReturnValue(10_000);
    const banner = new SaveBanner({ onSave: vi.fn(), onDismiss: vi.fn() });
    banner.show({ id: 'p1', site: 'bank.example', username: 'alice', mode: 'save' });
    expect(settlingOf(banner).settled).toBe(false);
  });
});

describe('cover check', () => {
  it('counts a choice only where the surface is on top', () => {
    const logins = menu();
    logins.showLogins(field(100), [LOGIN]);
    const part = document.createElement('span');
    const rect = { left: 0, top: 0, width: 100, height: 20, right: 100, bottom: 20 };
    part.getBoundingClientRect = () => ({ ...rect, x: 0, y: 0, toJSON: () => rect });
    const hit = vi.fn<(x: number, y: number) => Element | null>(() => logins.host);
    Object.defineProperty(document, 'elementFromPoint', { configurable: true, value: hit });
    expect(uncovered(logins.host, part)).toBe(true);
    expect(hit).toHaveBeenCalledWith(50, 10);
    hit.mockReturnValue(document.body);
    expect(uncovered(logins.host, part)).toBe(false);
    hit.mockReturnValue(null);
    expect(uncovered(logins.host, part)).toBe(false);
  });

  it('looks at what of a part the window shows, or where a click landed', () => {
    const logins = menu();
    logins.showLogins(field(100), [LOGIN]);
    const part = document.createElement('span');
    const rect = { left: 0, top: -30, width: 100, height: 40, right: 100, bottom: 10 };
    part.getBoundingClientRect = () => ({ ...rect, x: 0, y: -30, toJSON: () => rect });
    const hit = vi.fn<(x: number, y: number) => Element | null>(() => logins.host);
    Object.defineProperty(document, 'elementFromPoint', { configurable: true, value: hit });
    expect(uncovered(logins.host, part)).toBe(true);
    expect(hit).toHaveBeenLastCalledWith(50, 5);
    expect(uncoveredAt(logins.host, { x: 7, y: 9 })).toBe(true);
    expect(hit).toHaveBeenLastCalledWith(7, 9);
  });
});

/** What the page can't see: the surface's own state. */
function inside(surface: LoginMenu | SaveBanner | SignInBanner) {
  return surface as unknown as {
    root: ShadowRoot;
    body: HTMLElement | null;
    seen: boolean | null;
    intact(): boolean;
  };
}

/** Lets jsdom, which has no top layer, pretend to show popovers. */
function withPopover(host: HTMLElement): { shown: ReturnType<typeof vi.fn> } {
  const shown = vi.fn();
  Object.assign(host, { showPopover: shown, hidePopover: vi.fn() });
  return { shown };
}

async function microtasks(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('the page changing the surface', () => {
  it('takes it down when the page restyles its element', async () => {
    const logins = menu();
    logins.showLogins(field(100), [LOGIN]);
    expect(inside(logins).intact()).toBe(true);
    logins.host.style.setProperty('opacity', '0', 'important');
    expect(inside(logins).intact()).toBe(false);
    await microtasks();
    expect(logins.shown).toBe(false);
  });

  it('takes it down when the page moves its element', () => {
    const logins = menu();
    logins.showLogins(field(100), [LOGIN]);
    document.body.append(logins.host);
    expect(inside(logins).intact()).toBe(false);
  });

  it('comes back to the front when the page opens a layer over it, and waits again', () => {
    const clock = vi.spyOn(performance, 'now').mockReturnValue(10_000);
    const logins = menu();
    const { shown } = withPopover(logins.host);
    logins.showLogins(field(100), [LOGIN]);
    expect(shown).toHaveBeenCalledTimes(1);
    clock.mockReturnValue(10_000 + SETTLE_MS);
    expect(settlingOf(logins).settled).toBe(true);

    const layer = document.createElement('div');
    document.body.append(layer);
    const opened = () =>
      layer.dispatchEvent(Object.assign(new Event('toggle'), { newState: 'open' }));
    opened();
    expect(shown).toHaveBeenCalledTimes(2);
    expect(settlingOf(logins).settled).toBe(false);
    expect(logins.shown).toBe(true);

    // A page that keeps doing it gets no menu.
    for (let i = 0; i < 5; i += 1) opened();
    expect(logins.shown).toBe(false);
  });
});

describe('the menu', () => {
  it('fits in the window', () => {
    const logins = menu();
    logins.showLogins(field(100), [LOGIN]);
    expect(inside(logins).body?.style.height).toBe('126px');
    // A short window: the menu goes above the field, and shrinks.
    const height = window.innerHeight;
    Object.defineProperty(window, 'innerHeight', { configurable: true, value: 300 });
    try {
      logins.showLogins(field(160), [LOGIN]);
      expect(inside(logins).body?.style.height).toBe('112px');
    } finally {
      Object.defineProperty(window, 'innerHeight', { configurable: true, value: height });
    }
  });

  it('is as tall with one login as with many, locked or with a notice', () => {
    const logins = menu();
    const input = field(100);
    const many = Array.from({ length: 12 }, (_, n) => ({ ...LOGIN, id: `e${n}` }));
    const heights = [
      () => logins.showLogins(input, [LOGIN]),
      () => logins.showLogins(input, many),
      () => logins.showLocked(input),
      () => logins.showNotice(input, 'Confirm in SSH Key Manager'),
    ].map((show) => {
      show();
      return inside(logins).body?.style.height;
    });
    expect(new Set(heights)).toEqual(new Set(['126px']));
  });

  it('draws titles and usernames where find-in-page doesn’t look', () => {
    const logins = menu();
    const login = {
      id: 'e1',
      title: 'Corp SSO',
      username: 'alice.smith@corp.example',
      exact: true,
    };
    logins.showLogins(field(100), [login, { ...login, id: 'e2', username: '' }]);
    const root = inside(logins).root;
    // `window.find` searches the text of closed shadow roots, not CSS
    // generated content.
    expect(root.textContent).not.toContain('Corp SSO');
    expect(root.textContent).not.toContain('alice.smith');
    const drawn = [...root.querySelectorAll('[data-text]')].map(drawnText);
    expect(drawn).toEqual(['Corp SSO', 'alice.smith@corp.example', 'Corp SSO', 'No username']);
    const style = root.querySelector('style')?.textContent ?? '';
    expect(style).toContain('[data-text]::before { content: attr(data-text); }');
  });
});

describe('a page that scales the surface', () => {
  const zoomed = (zoom: number | undefined) =>
    Object.defineProperty(document.documentElement, 'currentCSSZoom', {
      configurable: true,
      value: zoom,
    });
  const at = (host: HTMLElement, box: { left: number; top: number; width: number }) => {
    const rect = { ...box, height: 180, right: box.left + box.width, bottom: box.top + 180 };
    host.getBoundingClientRect = () => ({ ...rect, x: rect.left, y: rect.top, toJSON: () => rect });
  };
  const item = (logins: LoginMenu) => {
    const button = inside(logins).root.querySelector<HTMLButtonElement>('button.item');
    if (!button) throw new Error('no menu item');
    return button;
  };
  const clickAt = (button: HTMLElement, x: number, y: number) =>
    fireTrusted(
      button,
      new MouseEvent('click', { detail: 1, clientX: x, clientY: y, bubbles: true, composed: true }),
    );

  afterEach(() => {
    zoomed(undefined);
  });

  it('gets it back to its size, where it was put', () => {
    zoomed(0.1);
    const logins = menu();
    logins.showLogins(field(100), [LOGIN]);
    expect(logins.host.style.getPropertyValue('zoom')).toBe('10');
    zoomed(1);
    logins.showLogins(field(100), [LOGIN]);
    expect(logins.host.style.getPropertyValue('zoom')).toBe('');
  });

  it('gets no choice from a click on it while it shows smaller or elsewhere', () => {
    const clock = vi.spyOn(performance, 'now').mockReturnValue(10_000);
    const onPick = vi.fn();
    const logins = new LoginMenu({ onPick, onUnlock: vi.fn(), onLeave: vi.fn() });
    logins.showLogins(field(100), [LOGIN]);
    Object.defineProperty(document, 'elementFromPoint', {
      configurable: true,
      value: () => logins.host,
    });
    clock.mockReturnValue(10_000 + SETTLE_MS);
    // Put at (10, 134), 260 px wide; the page shrank it to a speck.
    at(logins.host, { left: 1, top: 13.4, width: 26 });
    expect(inside(logins).intact()).toBe(false);
    clickAt(item(logins), 5, 20);
    expect(onPick).not.toHaveBeenCalled();
    expect(logins.shown).toBe(false);

    // Shown where it was put, it counts.
    logins.showLogins(field(100), [LOGIN]);
    clock.mockReturnValue(20_000);
    at(logins.host, { left: 10, top: 134, width: 260 });
    expect(inside(logins).intact()).toBe(true);
    clickAt(item(logins), 50, 150);
    expect(onPick).toHaveBeenCalledWith(LOGIN);
  });
});

describe('a key press in the menu', () => {
  it('counts only while the browser says nothing hides the menu', () => {
    const clock = vi.spyOn(performance, 'now').mockReturnValue(10_000);
    const onPick = vi.fn();
    const logins = new LoginMenu({ onPick, onUnlock: vi.fn(), onLeave: vi.fn() });
    logins.showLogins(field(100), [LOGIN]);
    clock.mockReturnValue(10_000 + SETTLE_MS);
    const button = inside(logins).root.querySelector<HTMLButtonElement>('button.item');
    if (!button) throw new Error('no menu item');
    const enter = () =>
      fireTrusted(button, new MouseEvent('click', { detail: 0, bubbles: true, composed: true }));
    // IntersectionObserver v2 said it is hidden or faded (an invisible frame).
    inside(logins).seen = false;
    enter();
    expect(onPick).not.toHaveBeenCalled();
    inside(logins).seen = true;
    enter();
    expect(onPick).toHaveBeenCalledWith(LOGIN);
  });
});

describe('the banner', () => {
  const field = (banner: SaveBanner) =>
    inside(banner).root.querySelector<HTMLInputElement>('input.input');

  it('names only the site for a login typed on another site', () => {
    const banner = new SaveBanner({ onSave: vi.fn(), onDismiss: vi.fn() });
    banner.show({ id: 'p1', site: 'bank.example', username: '', mode: 'save', elsewhere: true });
    expect(field(banner)).toBeNull();
    const heading = () => inside(banner).root.querySelector('h2');
    expect(drawnText(heading())).toContain('bank.example');
    expect(inside(banner).root.textContent).not.toContain('bank.example');
    banner.show({ id: 'p1', site: 'bank.example', username: 'alice', mode: 'save' });
    expect(field(banner)?.value).toBe('alice');
  });

  it('keeps a username from the vault, and the saved login’s title, off the page', () => {
    const banner = new SaveBanner({ onSave: vi.fn(), onDismiss: vi.fn() });
    banner.show({
      id: 'p1',
      site: 'shop.example',
      username: '',
      mode: 'update',
      title: 'Shop (work)',
      fromVault: true,
    });
    expect(field(banner)?.value).toBe('');
    expect(drawnText(inside(banner).root.querySelector('h2'))).toContain('Shop (work)');
    expect(inside(banner).root.textContent).not.toContain('Shop (work)');
  });

  it('saves with the username the user put in its field', async () => {
    vi.spyOn(performance, 'now').mockReturnValue(10_000);
    const onSave = vi.fn(async () => ({ ok: true, message: 'Saved' }));
    const banner = new SaveBanner({ onSave, onDismiss: vi.fn() });
    const offer = { id: 'p1', site: 'bank.example', username: '', mode: 'save' as const };
    banner.show(offer);
    const input = field(banner);
    expect(input?.value).toBe('');
    expect(input?.getAttribute('aria-label')).toBeTruthy();
    if (!input) return;
    input.value = ' alice@bank.example ';
    vi.spyOn(performance, 'now').mockReturnValue(10_000 + SETTLE_MS);
    press(input, 'Enter');
    await microtasks();
    expect(onSave).toHaveBeenCalledWith(offer, 'alice@bank.example');
  });

  it('keeps the key presses in its field from the page', () => {
    const banner = new SaveBanner({ onSave: vi.fn(), onDismiss: vi.fn() });
    banner.show({ id: 'p1', site: 'bank.example', username: '', mode: 'save' });
    const heard = vi.fn();
    document.addEventListener('keydown', heard);
    const input = field(banner);
    if (input) press(input, 'a');
    document.removeEventListener('keydown', heard);
    expect(heard).not.toHaveBeenCalled();
  });
});

describe('surfaces', () => {
  it('live on a built-in element, out of reach of a custom element the page defines', () => {
    const logins = menu();
    logins.showLogins(field(100), [LOGIN]);
    expect(logins.host.localName).toBe('div');
    expect(logins.host.shadowRoot).toBeNull();
    expect(logins.host.isConnected).toBe(true);
  });
});

describe('notices', () => {
  it('take the place of the logins until the menu hides', () => {
    const logins = menu();
    const input = field(100);
    logins.showLogins(input, [LOGIN]);
    expect(logins.showsNotice).toBe(false);
    logins.showNotice(input, 'Confirm in SSH Key Manager');
    const root = inside(logins).root;
    expect(root.querySelector('.notice')?.textContent).toBe('Confirm in SSH Key Manager');
    expect(root.querySelector('.notice')?.getAttribute('role')).toBe('status');
    expect(root.querySelectorAll('button.item')).toHaveLength(0);
    expect(logins.showsNotice).toBe(true);
    logins.hide();
    expect(logins.showsNotice).toBe(false);
  });
});

describe('the "couldn\u2019t sign in?" banner', () => {
  /** A click with the keyboard (Enter or Space on a button), as the browser sends it. */
  const choose = (button: HTMLElement | undefined) => {
    if (!button) throw new Error('no such button');
    fireTrusted(button, new MouseEvent('click', { bubbles: true, composed: true, detail: 0 }));
  };
  const buttons = (banner: SignInBanner) => [
    ...inside(banner).root.querySelectorAll<HTMLButtonElement>('.actions button'),
  ];
  const login = { title: 'Bank', username: 'alice' };

  it('names the login and points the user at the page for Update', () => {
    const clock = vi.spyOn(performance, 'now').mockReturnValue(10_000);
    const onUpdate = vi.fn();
    const banner = new SignInBanner({ onUpdate, onRemove: vi.fn(), onDismiss: vi.fn() });
    banner.show(login);
    const detail = inside(banner).root.querySelector('.detail');
    expect(drawnText(detail)).toContain('Bank');
    expect(detail?.textContent).toBe('');
    const [, update] = buttons(banner);
    // Not in the first moments: the page could have put it under a click.
    choose(update);
    expect(onUpdate).not.toHaveBeenCalled();
    clock.mockReturnValue(10_000 + SETTLE_MS);
    choose(update);
    expect(onUpdate).toHaveBeenCalledTimes(1);
    expect(inside(banner).root.querySelector('.status')?.textContent).not.toBe('');
    expect(buttons(banner)).toHaveLength(0);
  });

  it('asks before it removes the login, and lets the user keep it', async () => {
    const clock = vi.spyOn(performance, 'now').mockReturnValue(20_000);
    const onRemove = vi.fn(async () => ({ ok: true, message: 'Moved' }));
    const banner = new SignInBanner({ onUpdate: vi.fn(), onRemove, onDismiss: vi.fn() });
    banner.show(login);
    clock.mockReturnValue(20_000 + SETTLE_MS);
    choose(buttons(banner)[0]);
    expect(onRemove).not.toHaveBeenCalled();
    // The question waits again before its answer counts.
    expect(settlingOf(banner).settled).toBe(false);
    choose(buttons(banner)[1]);
    expect(onRemove).not.toHaveBeenCalled();
    // Cancel: back to the two choices.
    choose(buttons(banner)[0]);
    expect(buttons(banner)).toHaveLength(2);

    clock.mockReturnValue(20_000 + 3 * SETTLE_MS);
    choose(buttons(banner)[0]);
    clock.mockReturnValue(20_000 + 5 * SETTLE_MS);
    choose(buttons(banner)[1]);
    await microtasks();
    expect(onRemove).toHaveBeenCalledTimes(1);
    expect(inside(banner).root.querySelector('.status')?.textContent).toBe('Moved');
  });

  it('ignores clicks a page script makes up', () => {
    vi.spyOn(performance, 'now').mockReturnValue(30_000 + SETTLE_MS);
    const onRemove = vi.fn();
    const onUpdate = vi.fn();
    const banner = new SignInBanner({ onUpdate, onRemove, onDismiss: vi.fn() });
    banner.show(login);
    for (const button of buttons(banner)) button.click();
    expect(buttons(banner)).toHaveLength(2);
    expect(onUpdate).not.toHaveBeenCalled();
  });
});
