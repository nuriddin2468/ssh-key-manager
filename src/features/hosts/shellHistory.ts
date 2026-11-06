import { useQuery } from '@tanstack/react-query';
import { api } from '@/api/commands';
import type { HostSuggestion } from '@/bindings/HostSuggestion';
import type { Shell } from '@/bindings/Shell';
import { EMPTY_FORM, type HostForm, optionRow } from './model';

/**
 * Hosts found in the shell history. The history is read in Rust, on this
 * computer, only once the user said yes; the UI gets only the suggestions.
 */
export const shellHistoryKeys = {
  status: ['shell-history', 'status'] as const,
  scan: ['shell-history', 'scan'] as const,
};

export const useShellHistoryStatus = () =>
  useQuery({ queryKey: shellHistoryKeys.status, queryFn: api.shellHistoryStatus });

/**
 * The suggestions, read when the Hosts page shows them and after a change
 * (adding a host hides its suggestion), not each time the window gets focus.
 */
export const useShellHistoryScan = (enabled: boolean) =>
  useQuery({
    queryKey: shellHistoryKeys.scan,
    queryFn: api.shellHistoryScan,
    enabled,
    refetchOnWindowFocus: false,
    staleTime: 60_000,
  });

/** How shells are named, in every language. */
export const SHELL_NAMES: Record<Shell, string> = {
  zsh: 'zsh',
  bash: 'bash',
  fish: 'fish',
  powerShell: 'PowerShell',
};

/** `root@10.0.0.5:2222`, `[2001:db8::1]:2222`: the target as people type it. */
export function suggestionTarget(suggestion: HostSuggestion): string {
  const host = suggestion.host.includes(':') ? `[${suggestion.host}]` : suggestion.host;
  const user = suggestion.user ? `${suggestion.user}@` : '';
  const port = suggestion.port ? `:${suggestion.port}` : '';
  return `${user}${host}${port}`;
}

/**
 * The Add Host form for a suggestion. `IdentitiesOnly` and `ForwardAgent`
 * from the commands' `-o` go to their own controls; other options to the
 * list.
 */
export function formFromSuggestion(suggestion: HostSuggestion): HostForm {
  let identitiesOnly = EMPTY_FORM.identitiesOnly;
  let forwardAgent = suggestion.forwardAgent;
  const other = suggestion.options.filter((option) => {
    const key = option.key.toLowerCase();
    const yes = option.value.toLowerCase() === 'yes';
    if (key === 'identitiesonly') identitiesOnly = yes;
    else if (key === 'forwardagent') forwardAgent ||= yes;
    else return true;
    return false;
  });
  return {
    ...EMPTY_FORM,
    patterns: suggestion.alias,
    hostName: suggestion.host,
    user: suggestion.user ?? '',
    port: suggestion.port ? String(suggestion.port) : '',
    identityFile: suggestion.identityFile ?? '',
    identitiesOnly,
    proxyJump: suggestion.proxyJump ?? '',
    forwardAgent,
    other: other.map((option) => optionRow(option.key, option.value)),
  };
}
