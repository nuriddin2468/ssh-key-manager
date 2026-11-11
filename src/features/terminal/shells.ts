// The shells a local session can run (terminal/shells.rs on the Rust side):
// the list, their names as the UI shows them, and which one opens when the
// user doesn't say.

import { useQuery } from '@tanstack/react-query';
import type { TFunction } from 'i18next';
import { api } from '@/api/commands';
import { queryClient } from '@/api/queries';
import type { ShellInfo } from '@/bindings/ShellInfo';

/**
 * Under `environment`, which `invalidateAll` leaves alone: listing the shells
 * may start `wsl.exe` on Windows, so vault changes don't refetch it.
 */
export const shellsKey = ['environment', 'shells'] as const;

export const useShells = () =>
  useQuery({ queryKey: shellsKey, queryFn: api.terminalShells, staleTime: 60_000 });

/** The shell's name in the UI's language: Command Prompt is the only one Windows translates. */
export function shellName(t: TFunction, shell: ShellInfo): string {
  return shell.kind === 'cmd' ? t('terminal.shells.cmd') : shell.name;
}

/**
 * What to show under each shell's name in a list: the program, but only for
 * shells whose names repeat (two Bashes), or a WSL distribution's `wsl.exe -d`.
 */
export function shellDetail(shell: ShellInfo, all: readonly ShellInfo[]): string | null {
  if (shell.kind === 'wsl') return 'WSL';
  const twin = all.some((other) => other !== shell && other.name === shell.name);
  return twin ? shell.path : null;
}

/** The shell that opens by default: the user's choice while it's installed, else the system's. */
export function defaultShell(
  shells: readonly ShellInfo[] | undefined,
  preferred: string | null,
): ShellInfo | undefined {
  return shells?.find((shell) => shell.id === preferred) ?? shells?.find((shell) => shell.default);
}

/**
 * The id to start for the user's default choice: `null` (the system's) when
 * the chosen one is known to be gone, so a removed shell doesn't block every
 * local session. Before the list has loaded, the choice goes as it is.
 */
export function preferredShellId(preferred: string | null): string | null {
  if (preferred === null) return null;
  const shells = queryClient.getQueryData<ShellInfo[]>(shellsKey);
  if (shells && !shells.some((shell) => shell.id === preferred)) return null;
  return preferred;
}
