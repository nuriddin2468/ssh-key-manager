// What the extension draws on a page: the menu of saved logins under a login
// field, the "Save login?" banner, and the "Couldn't sign in?" banner. Each lives in a closed shadow root on
// an element of its own, so the page's styles can't reach in and its scripts
// can't read the logins listed. The look follows the app: its dark popover
// surface, the Passwords section's pink accent and its type sizes.
//
// A closed shadow root keeps out the page's scripts, but not find-in-page:
// `window.find` matches text in it. So what comes from the vault (titles,
// usernames, other sites' names) is drawn as CSS generated content, which
// find doesn't search (`drawText`). The menu is as tall whatever it shows,
// so its size doesn't tell how many logins there are.
//
// A choice in them counts only when the user could see what they chose:
// not in the first moments after the surface appeared or moved (a page
// could have put it under a click or a key press meant for something else),
// not where anything covers it, not after the page restyled, moved or hid
// the element it lives on, which is in the page's own DOM, and not while it
// shows smaller or elsewhere than it was put (a page's `zoom` scales even
// the top layer).

import type { LoginOffer } from '../shared/client';
import { loginName, t } from '../shared/i18n';

const STYLE = `
:host { all: initial; }
* { box-sizing: border-box; }
[data-text]::before { content: attr(data-text); }
.panel {
  font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
  color: #f2f4f8;
  background: linear-gradient(180deg, #1a1f2e, #0f121c);
  border: 1px solid rgb(255 255 255 / 0.1);
  border-radius: 12px;
  box-shadow: 0 24px 48px -16px rgb(0 0 0 / 0.7), inset 0 1px 0 rgb(255 255 255 / 0.06);
  color-scheme: dark;
  -webkit-font-smoothing: antialiased;
}
.head {
  display: flex; align-items: center; gap: 7px;
  padding: 8px 12px 6px;
  font-size: 11px; font-weight: 600; letter-spacing: 0.02em; color: #8892a6;
}
.logo {
  display: grid; place-items: center; flex: none;
  width: 16px; height: 16px; border-radius: 5px;
  background: linear-gradient(140deg, #f9a8d4, #db2777);
  box-shadow: inset 0 1px 0 rgb(255 255 255 / 0.32);
}
.logo svg { width: 10px; height: 10px; }
.list { margin: 0; padding: 0 4px 4px; list-style: none; overflow-y: auto; }
.body { display: flex; flex-direction: column; }
.body > .list { flex: 1; }
.body.state { justify-content: center; padding-bottom: 8px; }
.body.state > .list { flex: none; }
.item {
  all: unset; box-sizing: border-box;
  display: flex; align-items: center; gap: 10px;
  width: 100%; padding: 7px 8px; border-radius: 8px; cursor: pointer;
}
.item:hover { background: rgb(255 255 255 / 0.06); }
.item:focus-visible { background: rgb(244 114 182 / 0.16); outline: 2px solid #f9a8d4; outline-offset: -2px; }
.lines { display: flex; flex-direction: column; min-width: 0; }
.title, .user { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.title { font-weight: 600; color: #f2f4f8; }
.user { font-size: 12px; color: #a7b0c0; }
.user.none { font-style: italic; color: #8892a6; }
.item:hover .user.none, .item:focus-visible .user.none { color: #a7b0c0; }
.icon { flex: none; width: 16px; height: 16px; color: #fbcfe8; }
.notice { margin: 0; padding: 2px 12px 10px; font-size: 12.5px; line-height: 18px; color: #c9cfda; }
.banner { width: 100%; padding: 14px 14px 12px; }
.sr-only {
  position: absolute; width: 1px; height: 1px; margin: -1px; padding: 0; border: 0;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap;
}
.banner .row { display: flex; align-items: flex-start; gap: 10px; }
.banner .logo { width: 28px; height: 28px; border-radius: 8px; }
.banner .logo svg { width: 15px; height: 15px; }
.banner h2 {
  display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; overflow: hidden;
  height: 38px; margin: 1px 0 2px; font-size: 14px; line-height: 19px; font-weight: 600; color: #f2f4f8; overflow-wrap: anywhere;
}
.banner h2.short { height: auto; margin-bottom: 4px; }
.banner .text { flex: 1; min-width: 0; }
.banner .input {
  appearance: none; box-sizing: border-box; display: block; width: 100%;
  height: 30px; margin: 4px 0 0; padding: 0 9px; border-radius: 8px;
  font: 12.5px/28px ui-monospace, "Geist Mono", Menlo, monospace; color: #f2f4f8;
  background: rgb(255 255 255 / 0.05); border: 1px solid rgb(255 255 255 / 0.14);
  outline: none; caret-color: #f9a8d4;
}
.banner .input::placeholder {
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
  color: #8892a6; opacity: 1;
}
.banner .input:hover { border-color: rgb(255 255 255 / 0.22); }
.banner .input:focus { border-color: #f9a8d4; box-shadow: 0 0 0 3px rgb(244 114 182 / 0.22); }
.banner .input:disabled { opacity: 0.6; }
.status { margin: 10px 0 0; font-size: 12.5px; line-height: 18px; color: #ffc266; }
.status.ok { color: #5eead4; }
.status:empty { display: none; }
.actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 12px; }
.btn {
  all: unset; box-sizing: border-box;
  display: inline-flex; align-items: center; justify-content: center;
  height: 30px; padding: 0 12px; border-radius: 8px;
  font-size: 12.5px; font-weight: 500; color: #c9cfda; cursor: pointer;
}
.btn:hover { background: rgb(255 255 255 / 0.06); color: #f2f4f8; }
.btn.primary {
  background: linear-gradient(135deg, #f9a8d4, #ec4899); color: #3f0a24; font-weight: 600;
  box-shadow: 0 8px 20px -8px rgb(244 114 182 / 0.75), inset 0 1px 0 rgb(255 255 255 / 0.5);
}
.btn.primary:hover { filter: brightness(1.1); }
.btn.danger { color: #ff9b9b; }
.btn.danger:hover { background: rgb(255 107 107 / 0.12); color: #ffb4b4; }
.banner .detail { margin: 0; font-size: 12.5px; line-height: 18px; color: #c9cfda; overflow-wrap: anywhere; }
.btn:focus-visible { outline: 2px solid #f9a8d4; outline-offset: 2px; }
.btn[aria-busy="true"] { opacity: 0.6; pointer-events: none; }
.close {
  all: unset; box-sizing: border-box; flex: none;
  display: grid; place-items: center; width: 24px; height: 24px; border-radius: 6px;
  color: #8892a6; cursor: pointer;
}
.close:hover { background: rgb(255 255 255 / 0.06); color: #f2f4f8; }
.close:focus-visible { outline: 2px solid #f9a8d4; }
.close svg { width: 14px; height: 14px; }

`;

const SVG = 'http://www.w3.org/2000/svg';

/**
 * The height of the menu below its header, whatever it shows: two logins
 * (49 px each), half of a third, which shows there are more to scroll to,
 * and the list's padding. Less where the window has no room.
 */
const BODY_HEIGHT = 126;
/** The header, and the space kept above and below the menu. */
const HEAD_HEIGHT = 36;
/** The banners' width, where the window has room. */
const BANNER_WIDTH = 340;

function icon(paths: string[], className?: string): SVGSVGElement {
  const svg = document.createElementNS(SVG, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2.25');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  if (className) svg.setAttribute('class', className);
  for (const d of paths) {
    const path = document.createElementNS(SVG, 'path');
    path.setAttribute('d', d);
    svg.append(path);
  }
  return svg;
}

const KEY = [
  'M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z',
  'M16.5 7.5h.01',
];
const LOCK = [
  'M5 11h14a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2z',
  'M7 11V7a5 5 0 0 1 10 0v4',
];
const CLOSE = ['M18 6 6 18', 'm6 6 12 12'];

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

/**
 * Shows `text` in `node` as CSS generated content rather than as text in
 * the DOM: a page's `window.find` searches the text of closed shadow roots,
 * but not generated content. Screen readers read it all the same.
 */
export function drawText<T extends Element>(node: T, text: string): T {
  node.textContent = '';
  node.setAttribute('data-text', text);
  return node;
}

/** What `drawText` put in `node`. */
export function drawnText(node: Element | null | undefined): string | null {
  return node?.getAttribute('data-text') ?? null;
}

function logo(): HTMLElement {
  const box = element('span', 'logo');
  box.append(icon(KEY));
  box.style.color = '#fff';
  return box;
}

/** How long a surface must stay put before a choice in it counts. */
export const SETTLE_MS = 500;

/** At most this many returns to the front of the top layer a second; a page that forces more gets no surface. */
const MAX_FRONTS = 5;

/** How far, in pixels, a surface may show from where it was put. */
const PLACE_SLACK = 1;
/** Shorter than this, a surface can't be what the user sees. */
const MIN_HEIGHT = 24;

interface Point {
  x: number;
  y: number;
}

/** Where `place` put a surface, in the window's pixels, as far as it said. */
interface Placement {
  left?: number;
  top?: number;
  width?: number;
}

/**
 * How much `element` and its ancestors scale what they hold with CSS
 * `zoom`. The top layer is no exception.
 */
function zoomOf(element: Element): number {
  const current = (element as Element & { currentCSSZoom?: number }).currentCSSZoom;
  if (typeof current === 'number') return current > 0 && Number.isFinite(current) ? current : 1;
  // Browsers before `currentCSSZoom`: each element's own.
  let zoom = 1;
  for (let node: Element | null = element; node; node = node.parentElement) {
    const own = Number.parseFloat(getComputedStyle(node).zoom);
    if (own > 0 && Number.isFinite(own)) zoom *= own;
  }
  return zoom;
}

function pixels(value: string | undefined): number | undefined {
  const parsed = value?.endsWith('px') ? Number.parseFloat(value) : Number.NaN;
  return Number.isFinite(parsed) ? parsed : undefined;
}

/**
 * IntersectionObserver v2 (Chromium) also tells whether anything covers an
 * element, including what hit testing skips: content with
 * `pointer-events: none` on top of it.
 */
const TRACKS_VISIBILITY =
  typeof IntersectionObserverEntry !== 'undefined' &&
  'isVisible' in IntersectionObserverEntry.prototype;

/** When a choice in a surface starts to count. */
export class Settling {
  private from = Number.POSITIVE_INFINITY;

  constructor(private readonly now: () => number = () => performance.now()) {}

  /** The surface appeared or moved: wait again. */
  restart(): void {
    this.from = this.now() + SETTLE_MS;
  }

  get settled(): boolean {
    return this.now() >= this.from;
  }
}

/** Whether the middle of `part`, inside the surface on `host`, shows: no page content is over it. */
export function uncovered(host: Element, part: Element): boolean {
  return uncoveredAt(host, visibleMiddle(part));
}

/** Whether the surface on `host` is what shows at `point`. */
export function uncoveredAt(host: Element, point: Point): boolean {
  const doc = host.ownerDocument;
  // jsdom: no layout to ask.
  if (typeof doc.elementFromPoint !== 'function') return true;
  // Points in the closed shadow root come back as its host.
  return doc.elementFromPoint(point.x, point.y) === host;
}

/** The middle of the part of `part` inside the window. */
function visibleMiddle(part: Element): Point {
  const rect = part.getBoundingClientRect();
  const left = Math.max(rect.left, 0);
  const right = Math.min(rect.right, window.innerWidth);
  const top = Math.max(rect.top, 0);
  const bottom = Math.min(rect.bottom, window.innerHeight);
  return { x: (left + right) / 2, y: (top + bottom) / 2 };
}

/** An element in a closed shadow root, shown in the top layer where it can be. */
class Surface {
  readonly host: HTMLElement;
  protected readonly root: ShadowRoot;
  protected readonly settling = new Settling();
  /** The `style` attribute `place` wrote, and where it put the host. */
  private written: string | null = null;
  private parent: ParentNode | null = null;
  private placement: Placement = {};
  /** Whether the host made it into the top layer. */
  private inTopLayer = false;
  /** What IntersectionObserver v2 last said: shown with nothing over it, where it can tell. */
  private seen: boolean | null = null;
  private visibility: IntersectionObserver | null = null;
  /** When the surface last came back to the front. */
  private fronts: number[] = [];

  constructor() {
    // A built-in element: a page can define a custom element of any name
    // first, and reach the shadow root of one it defined.
    this.host = document.createElement('div');
    this.root = this.host.attachShadow({ mode: 'closed' });
    const style = element('style');
    style.textContent = STYLE;
    this.root.append(style);
    // The host is in the page's DOM, so the page can restyle, move or hide
    // it. Whatever it changes takes the surface down.
    new MutationObserver(() => {
      if (this.shown && !this.intact()) this.hide();
    }).observe(this.host, { attributes: true });
    this.host.addEventListener('toggle', () => {
      if (this.shown && !this.intact()) this.hide();
    });
    // Page content can't cover the top layer, but a popover, modal dialog or
    // full-screen element opened later joins it above this one: come back to
    // the front, and wait again.
    document.addEventListener(
      'toggle',
      (event) => {
        if (!this.shown || event.target === this.host) return;
        if ((event as Event & { newState?: string }).newState === 'open') this.front();
      },
      true,
    );
    document.addEventListener('fullscreenchange', () => {
      if (this.shown) this.front();
    });
  }

  protected place(styles: Record<string, string>, near: Element | null): void {
    const host = this.host;
    const appearing = !this.shown;
    if (appearing) this.seen = null;
    // Inside an open modal dialog, everything else is inert: join it.
    const parent = near?.closest('dialog[open]') ?? document.documentElement;
    host.removeAttribute('style');
    const all: Record<string, string> = {
      all: 'initial',
      position: 'fixed',
      'z-index': '2147483647',
      margin: '0',
      inset: 'auto',
      border: '0',
      padding: '0',
      background: 'transparent',
      overflow: 'visible',
      display: 'block',
      ...styles,
    };
    // A `zoom` on the page's root (or the dialog) scales the surface too:
    // undo it, so that it shows at its size, where it was put.
    const zoom = zoomOf(parent);
    if (Math.abs(zoom - 1) > 0.001) all.zoom = String(1 / zoom);
    for (const [name, value] of Object.entries(all))
      host.style.setProperty(name, value, 'important');
    this.written = host.getAttribute('style');
    this.placement = {
      left: pixels(styles.left),
      top: pixels(styles.top),
      width: pixels(styles.width),
    };
    if (host.parentNode !== parent) parent.append(host);
    this.parent = parent;
    this.inTopLayer = false;
    if ('showPopover' in host && typeof host.showPopover === 'function') {
      host.popover = 'manual';
      try {
        if (host.matches(':popover-open')) host.hidePopover();
        host.showPopover();
        this.inTopLayer = true;
      } catch {
        // Not connected yet, or the page forbids it: stay a fixed element.
      }
    }
    this.watchVisibility(appearing);
  }

  /**
   * Has IntersectionObserver v2 report on the host. Observed anew each time
   * the surface appears, so that a report comes even when nothing changed
   * since the last one.
   */
  private watchVisibility(anew: boolean): void {
    if (!TRACKS_VISIBILITY) return;
    if (!this.visibility) {
      this.visibility = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            this.seen =
              (entry as IntersectionObserverEntry & { isVisible?: boolean }).isVisible ?? null;
          }
        },
        { threshold: [0, 1], trackVisibility: true, delay: 100 } as IntersectionObserverInit,
      );
    } else if (anew) {
      this.visibility.unobserve(this.host);
    } else {
      return;
    }
    this.visibility.observe(this.host);
  }

  /** Brings the surface back above layers opened after it, and waits again. */
  private front(): void {
    const now = performance.now();
    this.fronts = this.fronts.filter((at) => now - at < 1000);
    this.fronts.push(now);
    if (this.fronts.length > MAX_FRONTS || !this.inTopLayer) {
      this.hide();
      return;
    }
    try {
      this.host.hidePopover();
      this.host.showPopover();
    } catch {
      this.hide();
      return;
    }
    this.settling.restart();
  }

  get shown(): boolean {
    return this.host.isConnected;
  }

  /** Whether the host is as `place` left it: same style, same place, still in the top layer. */
  private intact(): boolean {
    const host = this.host;
    if (!host.isConnected || host.parentNode !== this.parent) return false;
    if (host.getAttribute('style') !== this.written) return false;
    if (this.inTopLayer) {
      if (host.getAttribute('popover') !== 'manual') return false;
      try {
        if (!host.matches(':popover-open')) return false;
      } catch {
        // No `:popover-open` to ask (tests).
      }
    }
    // The inline `all: initial !important` keeps the page's style sheets
    // out; this is a second look.
    const style = getComputedStyle(host);
    const is = (value: string, normal: string) => value === '' || value === normal;
    return (
      is(style.opacity, '1') &&
      is(style.visibility, 'visible') &&
      is(style.transform, 'none') &&
      is(style.filter, 'none') &&
      is(style.clipPath, 'none') &&
      this.atItsPlace()
    );
  }

  /**
   * Whether the host shows unscaled, where and as wide as `place` put it,
   * whatever might scale it: the page's `zoom` on its root, or anything else.
   */
  private atItsPlace(): boolean {
    const host = this.host;
    const zoom = (host as HTMLElement & { currentCSSZoom?: number }).currentCSSZoom;
    if (typeof zoom === 'number' && Math.abs(zoom - 1) > 0.01) return false;
    // jsdom: no layout to ask.
    if (typeof host.ownerDocument.elementFromPoint !== 'function') return true;
    const rect = host.getBoundingClientRect();
    const near = (at: number, put: number | undefined) =>
      put === undefined || Math.abs(at - put) <= PLACE_SLACK;
    const { left, top, width } = this.placement;
    return (
      near(rect.left, left) &&
      near(rect.top, top) &&
      near(rect.width, width) &&
      rect.height >= MIN_HEIGHT
    );
  }

  /** Whether a real click or key press on `part` counts as the user's choice. */
  protected accepts(event: Event, part: Element): boolean {
    if (!event.isTrusted || !this.settling.settled) return false;
    if (!this.intact()) {
      // Restyled, moved or scaled since it was put: what the user sees isn't
      // what they'd choose. Shown again, it is put right.
      this.hide();
      return false;
    }
    // Where the browser tells (Chromium), only while it says nothing covers
    // the surface or fades it out, its frame included: for a key press as
    // for a click. A report comes soon after the surface appears, well
    // within the time it takes to settle.
    if (this.seen === false || (TRACKS_VISIBILITY && this.seen === null)) return false;
    // A click with the pointer counts where it landed; a key press, on what
    // of the part the window shows.
    if (event instanceof MouseEvent && event.detail > 0) {
      return uncoveredAt(this.host, { x: event.clientX, y: event.clientY });
    }
    return uncovered(this.host, part);
  }

  hide(): void {
    this.seen = null;
    this.host.remove();
  }

  /** Whether an event's target is this surface (events from inside are retargeted to the host). */
  contains(target: EventTarget | null): boolean {
    return target === this.host;
  }
}

export interface MenuHandlers {
  onPick: (login: LoginOffer) => void;
  onUnlock: () => void;
  /** Escape or Tab: give focus back to the field. */
  onLeave: () => void;
}

/**
 * The saved logins for a login field, under it. Its titles and usernames
 * are drawn (`drawText`), and it is as tall with one login as with many,
 * locked, or with a notice: the page can measure the element it lives on.
 */
export class LoginMenu extends Surface {
  private anchor: HTMLInputElement | null = null;
  /** What shows below the header, as tall whatever it holds. */
  private body: HTMLElement | null = null;
  /** Where the menu was put last. */
  private placed = '';
  private readonly reposition = () => this.position();

  constructor(private readonly handlers: MenuHandlers) {
    super();
  }

  showLogins(anchor: HTMLInputElement, logins: LoginOffer[]): void {
    const items = logins.map((login) => {
      const lines = element('span', 'lines');
      lines.append(drawText(element('span', 'title'), login.title));
      const user = drawText(
        element('span', login.username ? 'user' : 'user none'),
        login.username || t('noUsername'),
      );
      lines.append(user);
      return { lines, onChoose: () => this.handlers.onPick(login) };
    });
    this.render(anchor, items);
  }

  showLocked(anchor: HTMLInputElement): void {
    const lines = element('span', 'lines');
    lines.append(element('span', 'title', t('menuLocked')));
    this.render(anchor, [{ lines, icon: icon(LOCK, 'icon'), onChoose: this.handlers.onUnlock }], {
      state: true,
    });
  }

  /** A line of text in place of the logins: waiting for the app, or why nothing was filled. */
  showNotice(anchor: HTMLInputElement, text: string): void {
    const panel = this.panel();
    const body = element('div', 'body state');
    const notice = element('p', 'notice', text);
    notice.setAttribute('role', 'status');
    body.append(notice);
    panel.append(body);
    this.mount(anchor, panel, body);
  }

  /** Whether the menu shows a notice rather than logins. */
  get showsNotice(): boolean {
    return this.shown && this.root.querySelector('.notice') !== null;
  }

  /** A new, empty panel with the app's name at the top, in place of what was shown. */
  private panel(): HTMLDivElement {
    for (const node of [...this.root.childNodes]) if (node.nodeName !== 'STYLE') node.remove();
    const panel = element('div', 'panel');
    const head = element('div', 'head');
    head.setAttribute('aria-hidden', 'true');
    head.append(logo(), document.createTextNode(t('appName')));
    panel.append(head);
    return panel;
  }

  private mount(anchor: HTMLInputElement, panel: HTMLElement, body: HTMLElement): void {
    this.root.append(panel);
    this.anchor = anchor;
    this.body = body;
    this.placed = '';
    this.position();
    window.addEventListener('scroll', this.reposition, true);
    window.addEventListener('resize', this.reposition);
  }

  private render(
    anchor: HTMLInputElement,
    items: { lines: HTMLElement; icon?: SVGSVGElement; onChoose: () => void }[],
    { state = false } = {},
  ): void {
    const panel = this.panel();
    const body = element('div', state ? 'body state' : 'body');
    const list = element('ul', 'list');
    list.setAttribute('role', 'menu');
    list.setAttribute('aria-label', `${t('appName')}: ${t('menuLabel')}`);
    for (const item of items) {
      const li = element('li');
      li.setAttribute('role', 'none');
      const button = element('button', 'item');
      button.type = 'button';
      button.setAttribute('role', 'menuitem');
      button.tabIndex = -1;
      if (item.icon) button.append(item.icon);
      button.append(item.lines);
      button.addEventListener('click', (event) => {
        if (this.accepts(event, button)) item.onChoose();
      });
      li.append(button);
      list.append(li);
    }
    list.addEventListener('keydown', (event) => this.onKey(event));
    // The field is the page's, so it can't point at the menu: say it's there.
    const hint = element('p', 'sr-only');
    hint.setAttribute('role', 'status');
    body.append(list);
    panel.append(body, hint);
    setTimeout(() => {
      hint.textContent = t('menuHint');
    }, 50);
    this.mount(anchor, panel, body);
  }

  private position(): void {
    const anchor = this.anchor;
    if (!anchor?.isConnected) {
      this.hide();
      return;
    }
    const rect = anchor.getBoundingClientRect();
    const width = Math.min(Math.max(rect.width, 260), 360, window.innerWidth - 16);
    const left = Math.min(Math.max(8, rect.left), window.innerWidth - width - 8);
    const below = window.innerHeight - rect.bottom;
    const styles: Record<string, string> = { width: `${width}px`, left: `${left}px` };
    const above = below < 200 && rect.top > below;
    if (above) styles.bottom = `${window.innerHeight - rect.top + 4}px`;
    else styles.top = `${rect.bottom + 4}px`;
    // As tall whatever it shows, within the window; the list scrolls, so
    // every login can be reached.
    const room = (above ? rect.top : below) - 4 - 8 - HEAD_HEIGHT;
    if (this.body) this.body.style.height = `${Math.max(64, Math.min(BODY_HEIGHT, room))}px`;
    // A menu that moves may have moved under the pointer: it starts anew.
    const placed = JSON.stringify(styles);
    if (placed !== this.placed) this.settling.restart();
    this.placed = placed;
    this.place(styles, anchor);
  }

  /**
   * Moves focus into the menu, for the arrow keys. Only a key press the
   * browser marks as the user's own calls this, so it needn't wait again.
   */
  focusFirst(): void {
    this.buttons()[0]?.focus();
  }

  private buttons(): HTMLButtonElement[] {
    return [...this.root.querySelectorAll<HTMLButtonElement>('button.item')];
  }

  private onKey(event: KeyboardEvent): void {
    const buttons = this.buttons();
    const at = buttons.indexOf(this.root.activeElement as HTMLButtonElement);
    const go = (index: number) => {
      event.preventDefault();
      buttons[(index + buttons.length) % buttons.length]?.focus();
    };
    if (event.key === 'ArrowDown') go(at + 1);
    else if (event.key === 'ArrowUp') go(at - 1);
    else if (event.key === 'Home') go(0);
    else if (event.key === 'End') go(buttons.length - 1);
    else if (event.key === 'Escape' || event.key === 'Tab') {
      event.preventDefault();
      this.handlers.onLeave();
    }
  }

  override hide(): void {
    window.removeEventListener('scroll', this.reposition, true);
    window.removeEventListener('resize', this.reposition);
    this.anchor = null;
    super.hide();
  }
}

/**
 * The frame of a banner at the top right of the page, in place of what
 * `root` showed: the logo, a two-line title, a close button, a line for
 * what happened, the actions, and a line for screen readers.
 */
function bannerParts(root: ShadowRoot, title: string) {
  for (const node of [...root.childNodes]) if (node.nodeName !== 'STYLE') node.remove();
  const panel = element('div', 'panel banner');
  panel.setAttribute('role', 'dialog');
  panel.setAttribute('aria-label', title);
  const row = element('div', 'row');
  const text = element('div', 'text');
  const heading = drawText(element('h2'), title);
  // A title too long for two lines shows in full on hover.
  heading.title = title;
  text.append(heading);
  const close = element('button', 'close');
  close.type = 'button';
  close.setAttribute('aria-label', t('close'));
  close.append(icon(CLOSE));
  row.append(logo(), text, close);
  const status = element('p', 'status');
  status.setAttribute('role', 'status');
  const actions = element('div', 'actions');
  const announce = element('p', 'sr-only');
  announce.setAttribute('role', 'status');
  panel.append(row, status, actions, announce);
  return { panel, text, heading, close, status, actions, announce };
}

function actionButton(label: string, className = 'btn'): HTMLButtonElement {
  const button = element('button', className, label);
  button.type = 'button';
  return button;
}

/** Where a banner goes: the top right of the window. */
function bannerPlace(): Record<string, string> {
  const width = Math.max(0, Math.min(BANNER_WIDTH, window.innerWidth - 32));
  return { top: '16px', right: '16px', width: `${width}px` };
}

export interface SaveOffer {
  id: string;
  /** The page's host, to name it. */
  site: string;
  username: string;
  mode: 'save' | 'update';
  /** The login to update. */
  title?: string;
  /**
   * Typed on another site than this page's (a sign-in that sent you on, or
   * a sign-in frame): only that site's name is shown here, not the username
   * or the saved login's title.
   */
  elsewhere?: boolean;
  /**
   * The vault named the login (a password change on a form without a
   * username): its username isn't put in the field, which starts empty and
   * keeps it unless the user types another.
   */
  fromVault?: boolean;
}

export interface BannerHandlers {
  /**
   * Resolves with what to say: done, or why not. `username` is what the
   * banner's field holds, if it has one.
   */
  onSave: (offer: SaveOffer, username?: string) => Promise<{ ok: boolean; message: string }>;
  onDismiss: (offer: SaveOffer) => void;
}

/**
 * "Save login for example.com?", at the top right of the page.
 *
 * The page can't read its title (drawn, as `drawText` says), but it can
 * measure the element it lives on: the title always takes two lines, so the
 * banner's size doesn't tell whether it offers to save or to update, or the
 * saved login's title.
 *
 * The username is a field the user can change: a form with only a password
 * sent none, and one remembered from a two-step login's first step may be
 * the wrong one. It holds only what the user typed on the site, which the
 * page's `window.find` can match in a field: what they type is for the
 * site's own login, so the page learns nothing it wasn't told at sign-in.
 * Key presses in it stop at the banner all the same, so that the page's
 * keyboard shortcuts don't take them. A username the vault supplied isn't
 * put in it, and a login typed on another site gets no field: that page
 * isn't to see its username.
 */
export class SaveBanner extends Surface {
  constructor(private readonly handlers: BannerHandlers) {
    super();
  }

  show(offer: SaveOffer): void {
    const title =
      offer.mode === 'update'
        ? t('updateTitle', { title: offer.title ?? offer.site })
        : t('saveTitle', { site: offer.site });
    const { panel, text, close, status, actions, announce } = bannerParts(this.root, title);
    let username: HTMLInputElement | null = null;
    if (!offer.elsewhere) {
      username = element('input', 'input');
      username.value = offer.fromVault ? '' : offer.username;
      username.type = 'text';
      username.autocomplete = 'off';
      username.spellcheck = false;
      username.maxLength = 256;
      username.placeholder = t('usernamePlaceholder');
      username.setAttribute('aria-label', t('usernameLabel'));
      text.append(username);
    }
    const later = element('button', 'btn', t('notNow'));
    later.type = 'button';
    const save = element(
      'button',
      'btn primary',
      offer.mode === 'update' ? t('update') : t('save'),
    );
    save.type = 'button';
    actions.append(later, save);
    this.root.append(panel);
    // Shown without taking focus: announce it.
    setTimeout(() => {
      drawText(announce, title);
    }, 50);

    const dismiss = (event: Event) => {
      if (!event.isTrusted) return;
      this.hide();
      this.handlers.onDismiss(offer);
    };
    close.addEventListener('click', dismiss);
    later.addEventListener('click', dismiss);
    panel.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') dismiss(event);
    });
    const submit = async (event: Event) => {
      if (!this.accepts(event, save) || save.hasAttribute('aria-busy')) return;
      save.setAttribute('aria-busy', 'true');
      const result = await this.handlers.onSave(offer, username?.value.trim());
      save.removeAttribute('aria-busy');
      status.textContent = result.message;
      status.classList.toggle('ok', result.ok);
      if (result.ok) {
        actions.remove();
        if (username) username.disabled = true;
        setTimeout(() => this.hide(), 2500);
      }
    };
    save.addEventListener('click', (event) => void submit(event));
    if (username) {
      username.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          void submit(event);
        }
      });
      // Typing here is for the banner alone, not for the page's shortcuts.
      for (const type of ['keydown', 'keyup', 'keypress', 'beforeinput', 'input']) {
        panel.addEventListener(type, (event) => {
          if (event.composedPath()[0] === username) event.stopPropagation();
        });
      }
    }

    this.place(bannerPlace(), document.activeElement);
    this.settling.restart();
  }
}

/** The login a sign-in that seems to have failed was filled with. */
export interface SignInLogin {
  title: string;
  username: string;
}

export interface SignInHandlers {
  /** The user will type the right password: point them at the page's field. */
  onUpdate: () => void;
  /** Resolves with what to say: moved to the recycle bin, or why not. */
  onRemove: () => Promise<{ ok: boolean; message: string }>;
  onDismiss: () => void;
}

/** How long the banner stays once it said what happens next. */
const SIGN_IN_DONE_FOR = 12_000;

/**
 * "Couldn't sign in?", at the top right of the page, when the page's
 * sign-in form came back right after the user sent it filled with a saved
 * login: the saved password may be out of date. Update points the user at
 * the page's password field, whose new password the "Update password?"
 * banner then offers to save once they sign in. Remove moves the login to
 * the vault's recycle bin, after asking.
 */
export class SignInBanner extends Surface {
  private timer: ReturnType<typeof setTimeout> | undefined;

  constructor(private readonly handlers: SignInHandlers) {
    super();
  }

  show(login: SignInLogin): void {
    clearTimeout(this.timer);
    const title = t('signInFailedTitle');
    const { panel, text, heading, close, status, actions, announce } = bannerParts(
      this.root,
      title,
    );
    // One line, unlike the save banner's, whose height mustn't tell what it offers.
    heading.classList.add('short');
    const name = loginName(login);
    const failed = t('signInFailedText', { login: name });
    const detail = drawText(element('p', 'detail'), failed);
    text.append(detail);
    const remove = actionButton(t('signInRemove'), 'btn danger');
    const update = actionButton(t('update'), 'btn primary');
    actions.append(remove, update);
    this.root.append(panel);
    setTimeout(() => {
      drawText(announce, `${title} ${failed}`);
    }, 50);

    const finish = () => {
      actions.remove();
      this.timer = setTimeout(() => this.hide(), SIGN_IN_DONE_FOR);
    };
    const dismiss = (event: Event) => {
      if (!event.isTrusted) return;
      this.hide();
      this.handlers.onDismiss();
    };
    close.addEventListener('click', dismiss);
    panel.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') dismiss(event);
    });
    update.addEventListener('click', (event) => {
      if (!this.accepts(event, update)) return;
      status.textContent = t('signInUpdateHint');
      status.classList.add('ok');
      finish();
      this.handlers.onUpdate();
    });
    remove.addEventListener('click', (event) => {
      if (!this.accepts(event, remove)) return;
      // Ask first, in the banner: the login goes to the recycle bin.
      const question = t('moveToBinConfirm', { login: name });
      drawText(detail, question);
      const cancel = actionButton(t('keepLogin'));
      const confirm = actionButton(t('moveToBin'), 'btn danger');
      actions.replaceChildren(cancel, confirm);
      drawText(announce, question);
      // The safe choice has focus: Enter keeps the login.
      cancel.focus();
      this.settling.restart();
      cancel.addEventListener('click', (cancelled) => {
        if (!cancelled.isTrusted) return;
        drawText(detail, failed);
        actions.replaceChildren(remove, update);
        remove.focus();
      });
      confirm.addEventListener('click', async (confirmed) => {
        if (!this.accepts(confirmed, confirm) || confirm.hasAttribute('aria-busy')) return;
        confirm.setAttribute('aria-busy', 'true');
        const result = await this.handlers.onRemove();
        confirm.removeAttribute('aria-busy');
        status.textContent = result.message;
        status.classList.toggle('ok', result.ok);
        if (result.ok) finish();
      });
    });

    this.place(bannerPlace(), document.activeElement);
    this.settling.restart();
  }

  override hide(): void {
    clearTimeout(this.timer);
    super.hide();
  }
}
