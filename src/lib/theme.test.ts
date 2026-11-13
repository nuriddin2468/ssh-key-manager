import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const call = vi.fn((_command: string, _args?: Record<string, unknown>) => Promise.resolve(null));
vi.mock('@/lib/ipc', () => ({
  call: (command: string, args?: Record<string, unknown>) => call(command, args),
}));

/** A system appearance that tests can flip, as `prefers-color-scheme` would. */
function fakeSystem(light: boolean) {
  const listeners = new Set<() => void>();
  const query = {
    get matches() {
      return light;
    },
    addEventListener: (_type: string, listener: () => void) => listeners.add(listener),
    removeEventListener: (_type: string, listener: () => void) => listeners.delete(listener),
  };
  vi.stubGlobal(
    'matchMedia',
    vi.fn(() => query),
  );
  return {
    set(next: boolean) {
      light = next;
      for (const listener of listeners) listener();
    },
  };
}

const root = document.documentElement;

beforeEach(() => {
  localStorage.clear();
  delete root.dataset.theme;
  root.removeAttribute('style');
  call.mockClear();
  vi.resetModules();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('resolveTheme', () => {
  it('follows the system only for System', async () => {
    const { resolveTheme } = await import('./theme');
    expect(resolveTheme('system', true)).toBe('light');
    expect(resolveTheme('system', false)).toBe('dark');
    expect(resolveTheme('light', false)).toBe('light');
    expect(resolveTheme('dark', true)).toBe('dark');
    // A value an older or newer version saved: the system's.
    expect(resolveTheme('sepia' as never, true)).toBe('light');
  });
});

describe('startTheme', () => {
  it('shows the system’s theme by default and follows it live', async () => {
    const system = fakeSystem(true);
    const { startTheme, currentTheme, subscribeTheme } = await import('./theme');
    const changed = vi.fn();
    subscribeTheme(changed);
    const stop = startTheme();
    expect(root.dataset.theme).toBe('light');
    expect(root.style.colorScheme).toBe('light');
    expect(currentTheme()).toBe('light');

    system.set(false);
    expect(root.dataset.theme).toBe('dark');
    expect(changed).toHaveBeenCalledTimes(2);
    stop();
  });

  it('keeps a chosen theme whatever the system does', async () => {
    const system = fakeSystem(true);
    const { startTheme } = await import('./theme');
    const { updateSettings } = await import('./settings');
    const stop = startTheme();
    updateSettings({ appearance: 'dark' });
    expect(root.dataset.theme).toBe('dark');
    system.set(true);
    expect(root.dataset.theme).toBe('dark');
    updateSettings({ appearance: 'system' });
    expect(root.dataset.theme).toBe('light');
    stop();
  });

  it('follows a change made in another window', async () => {
    fakeSystem(false);
    const { startTheme } = await import('./theme');
    const stop = startTheme();
    expect(root.dataset.theme).toBe('dark');
    localStorage.setItem('sshkm.settings', JSON.stringify({ appearance: 'light' }));
    window.dispatchEvent(new StorageEvent('storage', { key: 'sshkm.settings' }));
    expect(root.dataset.theme).toBe('light');
    stop();
  });

  it('tells the app once per change, from the main window only', async () => {
    const system = fakeSystem(false);
    const { startTheme } = await import('./theme');
    const { updateSettings } = await import('./settings');
    const stopQuick = startTheme();
    expect(call).not.toHaveBeenCalled();
    stopQuick();

    const stop = startTheme({ native: true });
    expect(call).toHaveBeenLastCalledWith('set_appearance', { appearance: 'system', dark: true });
    system.set(true);
    expect(call).toHaveBeenLastCalledWith('set_appearance', { appearance: 'system', dark: false });
    updateSettings({ appearance: 'light' });
    expect(call).toHaveBeenLastCalledWith('set_appearance', { appearance: 'light', dark: false });
    // The window turning light because of it changes nothing more.
    system.set(true);
    expect(call).toHaveBeenCalledTimes(3);
    stop();
  });

  it('clears the boot script’s background once the styles take over', async () => {
    fakeSystem(false);
    root.style.backgroundColor = 'black';
    const { startTheme } = await import('./theme');
    startTheme()();
    expect(root.style.backgroundColor).toBe('');
  });
});

describe('theme-boot.js', () => {
  const script = readFileSync(join(__dirname, '..', '..', 'public', 'theme-boot.js'), 'utf8');
  const boot = () => new Function(script)();

  it('picks the system’s theme when nothing is saved', () => {
    fakeSystem(true);
    boot();
    expect(root.dataset.theme).toBe('light');
    expect(root.style.colorScheme).toBe('light');
    expect(root.style.backgroundColor).not.toBe('');
  });

  it('picks the saved theme over the system’s', () => {
    fakeSystem(true);
    localStorage.setItem('sshkm.settings', JSON.stringify({ appearance: 'dark' }));
    boot();
    expect(root.dataset.theme).toBe('dark');
  });

  it('stays dark when it can read neither', () => {
    vi.stubGlobal('matchMedia', undefined);
    localStorage.setItem('sshkm.settings', '{broken');
    boot();
    expect(root.dataset.theme).toBe('dark');
  });
});
