// One session's xterm. It lives as long as the tab, outside React, so the
// scrollback survives page changes: its element moves into the Terminal page
// while that page shows the tab, and out again when it doesn't.

import { isTauri } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import { FitAddon } from '@xterm/addon-fit';
import { SearchAddon } from '@xterm/addon-search';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { type ILinkHandler, type ITheme, Terminal } from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import i18n from '@/i18n';
import { platform } from '@/lib/platform';
import { currentTheme, subscribeTheme, type Theme } from '@/lib/theme';

/**
 * The terminal's colours in each theme. xterm needs plain colour values, so
 * these are the one palette outside `src/styles/app.css`; the backgrounds
 * match `--color-terminal` there.
 */
export const THEMES: Record<Theme, ITheme> = {
  dark: {
    background: '#06080d',
    foreground: '#d7dde8',
    cursor: '#d7dde8',
    cursorAccent: '#06080d',
    selectionBackground: 'rgb(147 197 253 / 0.28)',
    black: '#1c2230',
    red: '#ff9b9b',
    green: '#86efac',
    yellow: '#ffc266',
    blue: '#93c5fd',
    magenta: '#c4b5fd',
    cyan: '#5eead4',
    white: '#d7dde8',
    // Dim text from programs: still 4.5:1 on the background.
    brightBlack: '#7c869a',
    brightRed: '#ffbdbd',
    brightGreen: '#bbf7d0',
    brightYellow: '#ffd699',
    brightBlue: '#bfdbfe',
    brightMagenta: '#ddd6fe',
    brightCyan: '#99f6e4',
    brightWhite: '#f2f4f8',
  },
  // Every colour at 5:1 or more on the background, the bright ones darker
  // still; white and bright white are greys, so text in them stays readable
  // and black text on them too.
  light: {
    background: '#fbfbfc',
    foreground: '#1f2430',
    cursor: '#1f2430',
    cursorAccent: '#fbfbfc',
    selectionBackground: 'rgb(37 99 235 / 0.2)',
    black: '#1f2430',
    red: '#c0262d',
    green: '#1a7a3a',
    yellow: '#8a5600',
    blue: '#1d5fd1',
    magenta: '#7c3aed',
    cyan: '#0e7490',
    white: '#5d6779',
    brightBlack: '#5f6878',
    brightRed: '#a21b22',
    brightGreen: '#116330',
    brightYellow: '#6f4500',
    brightBlue: '#1749a6',
    brightMagenta: '#6025c4',
    brightCyan: '#0b5d75',
    brightWhite: '#8a93a3',
  },
};

/**
 * In the light theme xterm darkens any text below 4.5:1, such as a program's
 * own pale truecolor; the dark theme shows programs' colours as they are.
 */
function themeOptions(theme: Theme) {
  return { theme: THEMES[theme], minimumContrastRatio: theme === 'light' ? 4.5 : 1 };
}

const FONT = '"Geist Mono Variable", ui-monospace, Menlo, Consolas, monospace';

export interface ScreenHandlers {
  /** Keystrokes and pastes for the PTY. */
  onInput: (data: string) => void;
  /** The terminal's size changed (after fitting). */
  onResize: (cols: number, rows: number) => void;
  /** ⌃Tab / ⌃⇧Tab. */
  onCycle: (step: 1 | -1) => void;
}

/**
 * The renderer: xterm's DOM renderer by default, WebGL where WebGL2 works.
 * On Linux, WebKitGTK often renders on the CPU (no GPU acceleration with
 * NVIDIA's EGL), where WebGL is slower than the DOM, so it stays off there.
 */
function wantsWebgl(): boolean {
  if (platform === 'linux') return false;
  try {
    return document.createElement('canvas').getContext('webgl2') !== null;
  } catch {
    return false;
  }
}

async function copy(text: string): Promise<void> {
  if (isTauri()) await writeText(text);
  else await navigator.clipboard?.writeText(text);
}

/** Opens an http(s) link in the browser; anything else is ignored. */
export function openLink(uri: string): void {
  if (!/^https?:\/\//i.test(uri)) return;
  if (isTauri()) void openUrl(uri);
  else window.open(uri, '_blank', 'noopener,noreferrer');
}

/** The key held to open a link: ⌘ on macOS, Ctrl elsewhere, as in native terminals. */
const LINK_KEY = platform === 'macos' ? '⌘' : 'Ctrl';

/** Whether a click opens the link under it: only with {@link LINK_KEY} held. */
export function opensLink(event: MouseEvent): boolean {
  return platform === 'macos' ? event.metaKey : event.ctrlKey;
}

/**
 * Where an http(s) link leads, as the browser will read it: international
 * host names in their `xn--` form and invisible characters escaped, so a
 * look-alike can't pass for another site. `null` for anything else.
 */
export function linkTarget(uri: string): string | null {
  if (!/^https?:\/\//i.test(uri)) return null;
  try {
    return new URL(uri).href;
  } catch {
    return null;
  }
}

/** Shows and hides where the link under the pointer leads. */
export interface LinkPreview {
  show: (target: string, event: MouseEvent) => void;
  hide: () => void;
}

/**
 * Links in the terminal: hyperlinks the server prints (OSC 8), whose text
 * need not show where they lead, and plain URLs. Pointing at one shows its
 * real target; it opens only on ⌘-click (Ctrl-click), http and https only,
 * so a click meant to focus the terminal opens nothing. Without this xterm
 * would open them itself, in the webview.
 */
export function linkHandler(preview: LinkPreview): ILinkHandler {
  return {
    activate: (event, uri) => {
      if (opensLink(event)) openLink(uri);
    },
    hover: (event, uri) => {
      const target = linkTarget(uri);
      if (target) preview.show(target, event);
    },
    leave: () => preview.hide(),
    allowNonHttpProtocols: false,
  };
}

/**
 * Pasted text as the shell gets it: without escape and other control
 * characters (C0, DEL and C1), but with tabs and line ends. Pasted text can
 * then neither end bracketed paste early, so that what follows runs as typed,
 * nor send keys of its own. Native terminals do the same.
 */
export function cleanPaste(text: string): string {
  let out = '';
  for (const ch of text.replace(/\r\n?/g, '\n')) {
    const code = ch.charCodeAt(0);
    const control = code < 0x20 || (code >= 0x7f && code <= 0x9f);
    if (!control || ch === '\t' || ch === '\n') out += ch;
  }
  return out;
}

/** For a plain URL's link, which has no buffer range to pass on. */
const NO_RANGE = { start: { x: 0, y: 0 }, end: { x: 0, y: 0 } };

/**
 * The box that shows where a link leads, styled as the app's tooltips: the
 * address, cut at the end so the host stays in view, and how to open it.
 * Built from text nodes only. Pointer events pass through it.
 */
function linkTipElement(): HTMLDivElement {
  const tip = document.createElement('div');
  tip.hidden = true;
  tip.setAttribute('aria-hidden', 'true');
  tip.className =
    'pointer-events-none absolute left-3 z-10 flex max-w-[calc(100%-24px)] items-center gap-2 rounded-md border border-line-strong bg-popover px-2 py-1 text-[12px] shadow-xl shadow-shade/40';
  const url = document.createElement('span');
  url.className = 'min-w-0 truncate font-mono text-fg';
  const hint = document.createElement('span');
  hint.className = 'shrink-0 text-subtle';
  tip.append(url, hint);
  return tip;
}

export class Screen {
  readonly term: Terminal;
  readonly search = new SearchAddon();
  private readonly fitAddon = new FitAddon();
  /** Moves between containers; xterm renders into it. */
  readonly element: HTMLDivElement;
  private opened = false;
  private resizeObserver: ResizeObserver | null = null;
  private fitTimer: ReturnType<typeof setTimeout> | undefined;
  private label = '';
  /** Where the link under the pointer leads, over a corner of the terminal. */
  private readonly linkTip: HTMLDivElement;
  private readonly unsubscribeTheme: () => void;

  constructor(handlers: ScreenHandlers) {
    this.element = document.createElement('div');
    this.element.className = 'relative h-full w-full';
    this.linkTip = linkTipElement();
    const preview: LinkPreview = {
      show: (target, event) => this.showLink(target, event),
      hide: () => {
        this.linkTip.hidden = true;
      },
    };
    const links = linkHandler(preview);
    this.term = new Terminal({
      ...themeOptions(currentTheme()),
      fontFamily: FONT,
      fontSize: 13,
      lineHeight: 1.25,
      scrollback: 5000,
      cursorBlink: true,
      allowProposedApi: true,
      macOptionIsMeta: false,
      linkHandler: links,
      // The terminal's text, not a screen reader's, by default; a setting
      // can turn this on later.
      screenReaderMode: false,
    });
    this.term.loadAddon(this.fitAddon);
    this.term.loadAddon(this.search);
    this.term.loadAddon(
      new WebLinksAddon((event, uri) => links.activate(event, uri, NO_RANGE), {
        hover: (event, uri, range) => links.hover?.(event, uri, range),
        leave: (event, uri) => links.leave?.(event, uri, NO_RANGE),
      }),
    );
    this.term.onData(handlers.onInput);
    this.term.onResize(({ cols, rows }) => handlers.onResize(cols, rows));
    this.term.attachCustomKeyEventHandler((event) => this.key(event, handlers));
    // Every paste (⌘V, Ctrl+V, the context menu, a middle click on Linux)
    // is a paste event that reaches xterm's text area through this element:
    // caught on the way down, it reaches the shell only cleaned.
    this.element.addEventListener('paste', (event) => this.paste(event), { capture: true });
    this.unsubscribeTheme = subscribeTheme(() => {
      Object.assign(this.term.options, themeOptions(currentTheme()));
    });
  }

  /** Sends the pasted text, cleaned, in xterm's stead. */
  private paste(event: ClipboardEvent): void {
    event.preventDefault();
    event.stopPropagation();
    const text = event.clipboardData?.getData('text/plain');
    if (text) this.term.paste(cleanPaste(text));
  }

  /** Shows `target` at the bottom of the terminal, or at its top when the pointer is down there. */
  private showLink(target: string, event: MouseEvent): void {
    const [url, hint] = this.linkTip.children;
    if (url) url.textContent = target;
    if (hint) hint.textContent = i18n.t('terminal.linkOpen', { key: LINK_KEY });
    const box = this.element.getBoundingClientRect();
    const low = event.clientY > box.bottom - 56;
    this.linkTip.classList.toggle('bottom-2', !low);
    this.linkTip.classList.toggle('top-2', low);
    this.linkTip.hidden = false;
    if (!this.linkTip.isConnected) this.element.appendChild(this.linkTip);
  }

  /**
   * Keys the app keeps rather than the PTY. Returning false lets the
   * event go on to the page (menus, the app's shortcuts, paste).
   */
  private key(event: KeyboardEvent, handlers: ScreenHandlers): boolean {
    if (event.type !== 'keydown') return true;
    if (event.ctrlKey && event.key === 'Tab') {
      event.preventDefault();
      handlers.onCycle(event.shiftKey ? -1 : 1);
      return false;
    }
    // ⌘ shortcuts belong to the app on macOS. ⌘V pastes through the paste
    // event; ⌘C copies xterm's selection here, as the webview may not see it
    // as a selection to copy.
    if (platform === 'macos') {
      if (event.metaKey && event.key.toLowerCase() === 'c' && this.term.hasSelection()) {
        void copy(this.term.getSelection());
      }
      return !event.metaKey;
    }
    if (!event.ctrlKey || event.altKey) return true;
    const key = event.key.toLowerCase();
    // Ctrl+C copies a selection, otherwise interrupts; Ctrl+Shift+C copies.
    if (key === 'c' && (event.shiftKey || this.term.hasSelection())) {
      event.preventDefault();
      const text = this.term.getSelection();
      if (text) void copy(text);
      this.term.clearSelection();
      return false;
    }
    // Ctrl+V and Ctrl+Shift+V paste through the browser's paste event.
    if (key === 'v') return false;
    // Ctrl+Shift+T opens the host picker, Ctrl+Shift+K the command palette (useAppEvents).
    if ((key === 't' || key === 'k') && event.shiftKey) return false;
    return true;
  }

  /** Shows the terminal inside `container`. */
  attach(container: HTMLElement, label: string): void {
    this.label = label;
    container.appendChild(this.element);
    if (!this.opened) {
      this.opened = true;
      this.term.open(this.element);
      if (wantsWebgl()) void this.loadWebgl();
      // Measure again once the web font is in.
      void document.fonts?.load(`13px ${FONT}`).then(() => {
        this.term.options.fontFamily = FONT;
        this.fit();
      });
    }
    this.term.textarea?.setAttribute('aria-label', label);
    this.resizeObserver = new ResizeObserver(() => this.scheduleFit());
    this.resizeObserver.observe(container);
    this.fit();
  }

  /** Takes the terminal out of the page; it keeps its content. */
  detach(): void {
    this.resizeObserver?.disconnect();
    this.resizeObserver = null;
    clearTimeout(this.fitTimer);
    this.element.remove();
  }

  setLabel(label: string): void {
    if (label === this.label) return;
    this.label = label;
    this.term.textarea?.setAttribute('aria-label', label);
  }

  focus(): void {
    this.term.focus();
  }

  write(data: Uint8Array | string): void {
    this.term.write(data);
  }

  /** Fits the terminal to its container, at most every 100 ms. */
  private scheduleFit(): void {
    clearTimeout(this.fitTimer);
    this.fitTimer = setTimeout(() => this.fit(), 100);
  }

  fit(): void {
    if (!this.element.isConnected || this.element.clientWidth === 0) return;
    try {
      this.fitAddon.fit();
    } catch {
      // Not rendered yet.
    }
  }

  /** The size the terminal would have in its container now. */
  proposedSize(): { cols: number; rows: number } | undefined {
    try {
      return this.fitAddon.proposeDimensions() ?? undefined;
    } catch {
      return undefined;
    }
  }

  private async loadWebgl(): Promise<void> {
    try {
      const { WebglAddon } = await import('@xterm/addon-webgl');
      const webgl = new WebglAddon();
      // Back to the DOM renderer if the GPU goes away.
      webgl.onContextLoss(() => webgl.dispose());
      this.term.loadAddon(webgl);
    } catch {
      // The DOM renderer stays.
    }
  }

  dispose(): void {
    this.unsubscribeTheme();
    this.detach();
    this.term.dispose();
  }
}
