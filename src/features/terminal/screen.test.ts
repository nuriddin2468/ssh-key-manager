import { describe, expect, it, vi } from 'vitest';
import { platform } from '@/lib/platform';
import { cleanPaste, type LinkPreview, linkHandler, linkTarget, openLink, Screen } from './screen';

vi.mock('@tauri-apps/api/core', () => ({ isTauri: () => false }));

const range = { start: { x: 1, y: 1 }, end: { x: 10, y: 1 } };

/** A click with the key that opens links held (⌘ on macOS, Ctrl elsewhere), or without. */
function click(withKey: boolean): MouseEvent {
  return new MouseEvent('mouseup', {
    metaKey: withKey && platform === 'macos',
    ctrlKey: withKey && platform !== 'macos',
  });
}

function preview(): LinkPreview & { shown: string[] } {
  const shown: string[] = [];
  return { shown, show: (target) => shown.push(target), hide: () => shown.push('(hidden)') };
}

describe('links in the terminal', () => {
  it('opens only http and https links', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    openLink('https://example.com/docs');
    openLink('HTTP://example.com');
    for (const uri of [
      'javascript:alert(1)',
      'file:///etc/passwd',
      'ssh://host',
      'data:text/html,<b>x</b>',
      ' https://example.com',
    ]) {
      openLink(uri);
    }
    expect(open.mock.calls.map(([uri]) => uri)).toEqual([
      'https://example.com/docs',
      'HTTP://example.com',
    ]);
  });

  it('sends hyperlinks the server prints the same way', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const links = linkHandler(preview());
    links.activate(click(true), 'javascript:alert(document.cookie)', range);
    links.activate(click(true), 'file:///Users/alice/.ssh/id_ed25519', range);
    links.activate(click(true), 'https://example.com/', range);
    expect(open).toHaveBeenCalledOnce();
    expect(open).toHaveBeenCalledWith('https://example.com/', '_blank', 'noopener,noreferrer');
    expect(links.allowNonHttpProtocols).toBe(false);
  });

  it('opens a link only on a click with ⌘ (Ctrl) held', () => {
    const open = vi.spyOn(window, 'open').mockReturnValue(null);
    const links = linkHandler(preview());
    // A plain click, as when focusing the terminal, opens nothing.
    links.activate(click(false), 'https://example.com/', range);
    expect(open).not.toHaveBeenCalled();
    links.activate(click(true), 'https://example.com/', range);
    expect(open).toHaveBeenCalledOnce();
  });

  it('shows where a link really leads while the pointer is on it', () => {
    const shown = preview();
    const links = linkHandler(shown);
    // Link text can say anything; the preview shows the target.
    links.hover?.(new MouseEvent('mouseover'), 'https://example.com/docs', range);
    links.leave?.(new MouseEvent('mouseout'), 'https://example.com/docs', range);
    // Nothing for a link that can't open.
    links.hover?.(new MouseEvent('mouseover'), 'file:///etc/passwd', range);
    expect(shown.shown).toEqual(['https://example.com/docs', '(hidden)']);
  });

  it('shows a look-alike address as the browser reads it', () => {
    // Cyrillic "а" in the host, and a right-to-left override in the path.
    expect(linkTarget('https://ex\u0430mple.com/')).toBe('https://xn--exmple-4nf.com/');
    expect(linkTarget('https://example.com/\u202Egnp.exe')).toBe(
      'https://example.com/%E2%80%AEgnp.exe',
    );
    expect(linkTarget('ssh://host')).toBeNull();
  });
});

describe('pasting into the terminal', () => {
  it('keeps text, tabs and line ends and drops control characters', () => {
    expect(cleanPaste('ls -la\tdocs\r\ncd ~\n')).toBe('ls -la\tdocs\ncd ~\n');
    expect(cleanPaste('echo a\x1b[201~\ncurl x | sh\n')).toBe('echo a[201~\ncurl x | sh\n');
    expect(cleanPaste('a\x00b\x07c\x7fd\x9be\u0085f')).toBe('abcdef');
    expect(cleanPaste('héllo — 日本 🙂')).toBe('héllo — 日本 🙂');
  });

  it('sends a paste to the shell only cleaned, inside bracketed paste', async () => {
    // What xterm needs of a browser that jsdom lacks.
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe() {}
        disconnect() {}
      },
    );
    vi.stubGlobal('matchMedia', () => ({
      matches: false,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
    }));
    const sent: string[] = [];
    const screen = new Screen({
      onInput: (data) => sent.push(data),
      onResize: () => undefined,
      onCycle: () => undefined,
    });
    const container = document.createElement('div');
    document.body.appendChild(container);
    screen.attach(container, 'Terminal: test');
    // The shell turns bracketed paste on, as zsh and bash do.
    await new Promise<void>((resolve) => screen.term.write('\x1b[?2004h', resolve));

    const event = new Event('paste', { bubbles: true, cancelable: true });
    Object.defineProperty(event, 'clipboardData', {
      value: { getData: () => 'echo hi\x1b[201~\ncurl x | sh\n' },
    });
    screen.term.textarea?.dispatchEvent(event);

    expect(event.defaultPrevented).toBe(true);
    expect(sent.join('')).toBe('\x1b[200~echo hi[201~\rcurl x | sh\r\x1b[201~');
    screen.dispose();
    container.remove();
    vi.unstubAllGlobals();
  });
});
