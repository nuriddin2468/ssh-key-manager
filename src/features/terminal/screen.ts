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
import { platform } from '@/lib/platform';

export const THEME: ITheme = {
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
};

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

/**
 * Hyperlinks the server prints (OSC 8), whose text need not show where they
 * lead: they open the way plain URLs do, http and https only. Without this
 * xterm would open them itself, in the webview.
 */
export const LINK_HANDLER: ILinkHandler = {
  activate: (_event, uri) => openLink(uri),
  allowNonHttpProtocols: false,
};

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

  constructor(handlers: ScreenHandlers) {
    this.term = new Terminal({
      theme: THEME,
      fontFamily: FONT,
      fontSize: 13,
      lineHeight: 1.25,
      scrollback: 5000,
      cursorBlink: true,
      allowProposedApi: true,
      macOptionIsMeta: false,
      linkHandler: LINK_HANDLER,
      // The terminal's text, not a screen reader's, by default; a setting
      // can turn this on later.
      screenReaderMode: false,
    });
    this.element = document.createElement('div');
    this.element.className = 'h-full w-full';
    this.term.loadAddon(this.fitAddon);
    this.term.loadAddon(this.search);
    this.term.loadAddon(new WebLinksAddon((_event, uri) => openLink(uri)));
    this.term.onData(handlers.onInput);
    this.term.onResize(({ cols, rows }) => handlers.onResize(cols, rows));
    this.term.attachCustomKeyEventHandler((event) => this.key(event, handlers));
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
    // Ctrl+Shift+T opens the host picker (useAppEvents).
    if (key === 't' && event.shiftKey) return false;
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
    this.detach();
    this.term.dispose();
  }
}
