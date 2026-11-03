import { describe, expect, it, vi } from 'vitest';
import { LINK_HANDLER, openLink } from './screen';

vi.mock('@tauri-apps/api/core', () => ({ isTauri: () => false }));

const range = { start: { x: 1, y: 1 }, end: { x: 10, y: 1 } };

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
    const click = new MouseEvent('click');
    LINK_HANDLER.activate(click, 'javascript:alert(document.cookie)', range);
    LINK_HANDLER.activate(click, 'file:///Users/alice/.ssh/id_ed25519', range);
    LINK_HANDLER.activate(click, 'https://example.com/', range);
    expect(open).toHaveBeenCalledOnce();
    expect(open).toHaveBeenCalledWith('https://example.com/', '_blank', 'noopener,noreferrer');
    expect(LINK_HANDLER.allowNonHttpProtocols).toBe(false);
  });
});
