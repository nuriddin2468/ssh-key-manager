import i18n from 'i18next';
import { afterEach, describe, expect, it } from 'vitest';
import { queryClient } from '@/api/queries';
import type { ShellInfo } from '@/bindings/ShellInfo';
import { defaultShell, preferredShellId, shellDetail, shellName, shellsKey } from './shells';

const t = i18n.getFixedT('en');

const shell = (id: string, name: string, change: Partial<ShellInfo> = {}): ShellInfo => ({
  id,
  name,
  path: id,
  kind: 'unix',
  default: false,
  ...change,
});

const zsh = shell('/bin/zsh', 'Zsh', { default: true });
const bash = shell('/bin/bash', 'Bash');
const brewBash = shell('/opt/homebrew/bin/bash', 'Bash');
const ubuntu = shell('wsl:Ubuntu', 'Ubuntu', { kind: 'wsl', path: 'wsl.exe -d Ubuntu' });
const cmd = shell('cmd', 'Command Prompt', { kind: 'cmd', path: 'C:\\Windows\\System32\\cmd.exe' });

afterEach(() => queryClient.removeQueries({ queryKey: shellsKey }));

describe('shells', () => {
  it('show a path only where two shells share a name', () => {
    expect(shellDetail(zsh, [zsh, bash])).toBeNull();
    expect(shellDetail(bash, [zsh, bash, brewBash])).toBe('/bin/bash');
    expect(shellDetail(ubuntu, [ubuntu])).toBe('WSL');
  });

  it('name Command Prompt in the UI’s language', () => {
    expect(shellName(t, cmd)).toBe('Command Prompt');
    expect(shellName(i18n.getFixedT('ru'), cmd)).toBe('Командная строка');
    expect(shellName(i18n.getFixedT('ru'), zsh)).toBe('Zsh');
  });

  it('open the chosen shell while it is installed, else the system’s', () => {
    expect(defaultShell([zsh, bash], '/bin/bash')).toBe(bash);
    expect(defaultShell([zsh, bash], null)).toBe(zsh);
    expect(defaultShell([zsh, bash], '/usr/bin/fish')).toBe(zsh);
    expect(defaultShell(undefined, null)).toBeUndefined();
  });

  it('drop a chosen shell that is known to be gone', () => {
    expect(preferredShellId('/usr/bin/fish')).toBe('/usr/bin/fish');
    queryClient.setQueryData(shellsKey, [zsh, bash]);
    expect(preferredShellId('/usr/bin/fish')).toBeNull();
    expect(preferredShellId('/bin/bash')).toBe('/bin/bash');
    expect(preferredShellId(null)).toBeNull();
  });
});
