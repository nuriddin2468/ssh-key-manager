import { afterEach, describe, expect, it, vi } from 'vitest';
import { LoginMenu, SaveBanner, SETTLE_MS, Settling, uncovered, uncoveredAt } from './surfaces';

const LOGIN = { id: 'e1', title: 'Bank', username: 'alice', exact: true };

function menu(): LoginMenu {
  return new LoginMenu({ onPick: vi.fn(), onUnlock: vi.fn(), onLeave: vi.fn() });
}

function settlingOf(surface: LoginMenu | SaveBanner): Settling {
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
function inside(surface: LoginMenu | SaveBanner) {
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
  it('names only the site for a login typed on another site', () => {
    const banner = new SaveBanner({ onSave: vi.fn(), onDismiss: vi.fn() });
    banner.show({ id: 'p1', site: 'bank.example', username: '', mode: 'save', elsewhere: true });
    expect(inside(banner).root.querySelector('.sub')).toBeNull();
    banner.show({ id: 'p1', site: 'bank.example', username: 'alice', mode: 'save' });
    expect(inside(banner).root.querySelector('.sub')?.textContent).toBe('alice');
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
