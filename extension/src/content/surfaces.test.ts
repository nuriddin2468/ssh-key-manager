import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireTrusted, press } from '../test/user';
import {
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
  return surface as unknown as { root: ShadowRoot; list: HTMLElement | null; intact(): boolean };
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
  it('fits its list in the window', () => {
    const logins = menu();
    logins.showLogins(field(100), [LOGIN]);
    expect(inside(logins).list?.style.maxHeight).toBe('264px');
    // 208 px below the field: the menu stays below, and its list shrinks.
    logins.showLogins(field(window.innerHeight - 238), [LOGIN]);
    expect(inside(logins).list?.style.maxHeight).toBe('160px');
  });
});

describe('the banner', () => {
  const field = (banner: SaveBanner) =>
    inside(banner).root.querySelector<HTMLInputElement>('input.input');

  it('names only the site for a login typed on another site', () => {
    const banner = new SaveBanner({ onSave: vi.fn(), onDismiss: vi.fn() });
    banner.show({ id: 'p1', site: 'bank.example', username: '', mode: 'save', elsewhere: true });
    expect(field(banner)).toBeNull();
    banner.show({ id: 'p1', site: 'bank.example', username: 'alice', mode: 'save' });
    expect(field(banner)?.value).toBe('alice');
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
    expect(inside(banner).root.querySelector('.detail')?.textContent).toContain('Bank');
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
