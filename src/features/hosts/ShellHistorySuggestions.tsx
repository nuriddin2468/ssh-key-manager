import { ChevronDown, History, Plus, RotateCw, Search, TriangleAlert, X } from 'lucide-react';
import { useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { queryClient, useEnvironment } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { HistoryScan } from '@/bindings/HistoryScan';
import type { HostSuggestion } from '@/bindings/HostSuggestion';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { displayPath, formatRelative } from '@/lib/format';
import { type HostForm, hostMonogram } from './model';
import {
  formFromSuggestion,
  SHELL_NAMES,
  shellHistoryKeys,
  suggestionTarget,
  useShellHistoryScan,
  useShellHistoryStatus,
} from './shellHistory';

/** Suggestions shown before "Show more". */
const SHOWN = 3;
/** Remembers, on this computer, that the user folded the list away. */
const COLLAPSED_KEY = 'sshkm.historyHosts.collapsed';

function storedCollapsed(): boolean {
  try {
    return localStorage.getItem(COLLAPSED_KEY) === '1';
  } catch {
    return false;
  }
}

function storeCollapsed(collapsed: boolean): void {
  try {
    if (collapsed) localStorage.setItem(COLLAPSED_KEY, '1');
    else localStorage.removeItem(COLLAPSED_KEY);
  } catch {
    // Without storage it stays folded until the page reloads.
  }
}

/**
 * Hosts found in the shell history, on the Hosts page: first the question
 * whether to look, then what was found. Nothing shows once the user said no,
 * or when there is nothing to suggest.
 */
export function ShellHistorySuggestions({ onAdd }: { onAdd: (form: HostForm) => void }) {
  const { t } = useTranslation();
  const status = useShellHistoryStatus().data;
  const scan = useShellHistoryScan(status?.consent === 'on');

  // The user asked, so say when nothing turns up.
  const look = async () => {
    try {
      const result = await queryClient.fetchQuery({
        queryKey: shellHistoryKeys.scan,
        queryFn: api.shellHistoryScan,
        staleTime: 0,
      });
      if (result.suggestions.length === 0) toast(t('historyHosts.noneFound'));
    } catch (error) {
      toastError(t, error);
    }
  };
  const answer = useAppMutation((enabled: boolean) => api.shellHistorySetEnabled(enabled), {
    success: (_, enabled) => (enabled ? undefined : t('historyHosts.declined')),
    onSuccess: (_, enabled) => {
      if (enabled) void look();
    },
  });

  if (!status || status.consent === 'off') return null;
  if (status.consent === 'unasked') {
    return (
      <OptIn
        busy={answer.isPending}
        onYes={() => answer.mutate(true)}
        onNo={() => answer.mutate(false)}
      />
    );
  }
  if (scan.isPending) {
    return (
      <p role="status" className="flex shrink-0 items-center gap-2 px-1 text-[12.5px] text-subtle">
        <Spinner className="size-3.5" />
        {t('historyHosts.looking')}
      </p>
    );
  }
  if (!scan.data) return null;
  const secrets = scan.data.files.filter((file) => file.secrets > 0);
  if (scan.data.suggestions.length === 0 && secrets.length === 0) return null;
  return (
    <Found
      scan={scan.data}
      refreshing={scan.isFetching}
      onRefresh={() => void look()}
      onAdd={onAdd}
    />
  );
}

function OptIn({ busy, onYes, onNo }: { busy: boolean; onYes: () => void; onNo: () => void }) {
  const { t } = useTranslation();
  const titleId = useId();
  const textId = useId();
  return (
    <section
      aria-labelledby={titleId}
      aria-describedby={textId}
      className="glass flex shrink-0 flex-wrap items-center gap-x-4 gap-y-3 rounded-2xl px-4 py-3.5"
    >
      <Tile tone="blue" size={36} glow>
        <History className="size-[18px]" strokeWidth={2} />
      </Tile>
      <div className="flex min-w-[240px] flex-1 flex-col gap-0.5">
        <h2 id={titleId} className="text-[13.5px] font-semibold">
          {t('historyHosts.askTitle')}
        </h2>
        <p id={textId} className="text-[12.5px] leading-[18px] text-muted">
          {t('historyHosts.askText')}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Button size="sm" variant="ghost" disabled={busy} onClick={onNo}>
          {t('historyHosts.decline')}
        </Button>
        <Button
          size="sm"
          // Soft: the page's own primary action stays "Add host".
          variant="soft"
          loading={busy}
          icon={<Search className="size-3.5" strokeWidth={2.25} />}
          onClick={onYes}
        >
          {t('historyHosts.find')}
        </Button>
      </div>
    </section>
  );
}

interface FoundProps {
  scan: HistoryScan;
  refreshing: boolean;
  onRefresh: () => void;
  onAdd: (form: HostForm) => void;
}

function Found({ scan, refreshing, onRefresh, onAdd }: FoundProps) {
  const { t, i18n } = useTranslation();
  const titleId = useId();
  const [expanded, setExpanded] = useState(false);
  const [collapsed, setCollapsed] = useState(storedCollapsed);
  const listId = useId();
  const home = useEnvironment().data?.paths.home;
  const listRef = useRef<HTMLUListElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  // Dismissed rows go at once; one comes back if saving that fails.
  const [gone, setGone] = useState<ReadonlySet<string>>(new Set());
  const dismiss = useAppMutation(
    (suggestion: HostSuggestion) => api.shellHistoryDismiss(suggestion.id),
    {
      success: (_, suggestion) =>
        t('historyHosts.dismissed', { target: suggestionTarget(suggestion) }),
      onError: (_, suggestion) => {
        setGone((ids) => new Set([...ids].filter((id) => id !== suggestion.id)));
        return undefined;
      },
    },
  );

  const shells = [...new Set(scan.suggestions.flatMap((s) => s.shells))].map(
    (shell) => SHELL_NAMES[shell],
  );
  const list = new Intl.ListFormat(i18n.language, { type: 'conjunction' });
  const secrets = scan.files.filter((file) => file.secrets > 0);
  const secretCount = secrets.reduce((sum, file) => sum + file.secrets, 0);
  const suggestions = scan.suggestions.filter((s) => !gone.has(s.id));
  const shown = expanded ? suggestions : suggestions.slice(0, SHOWN);
  const more = suggestions.length - shown.length;

  // Focus goes to the next row's dismiss button (or the one before, or the
  // heading), as the row the user was on goes away.
  const dismissRow = (suggestion: HostSuggestion, index: number) => {
    const next = shown[index + 1] ?? shown[index - 1];
    setGone((ids) => new Set(ids).add(suggestion.id));
    dismiss.mutate(suggestion);
    requestAnimationFrame(() => {
      const button =
        next && listRef.current?.querySelector<HTMLElement>(`[data-dismiss="${next.id}"]`);
      (button ?? headingRef.current)?.focus();
    });
  };

  if (suggestions.length === 0 && secretCount === 0) return null;
  return (
    <section
      aria-labelledby={titleId}
      aria-busy={refreshing || undefined}
      className="glass flex shrink-0 flex-col overflow-hidden rounded-2xl"
    >
      <header className="flex items-center gap-3 px-4 pt-3.5 pb-3">
        <Tile tone="blue" size={30}>
          <History className="size-4" strokeWidth={2} />
        </Tile>
        <div className="flex min-w-0 flex-1 flex-col">
          <h2 id={titleId} ref={headingRef} tabIndex={-1} className="text-[13.5px] font-semibold">
            {t('historyHosts.title')}
          </h2>
          <p className="text-[12px] leading-[18px] text-subtle">
            {collapsed
              ? t('historyHosts.waiting', { count: suggestions.length })
              : shells.length > 0
                ? t('historyHosts.sources', { shells: list.format(shells) })
                : t('historyHosts.local')}
          </p>
        </div>
        <IconButton
          label={t('historyHosts.lookAgain')}
          disabled={refreshing}
          icon={
            refreshing ? (
              <Spinner className="size-3.5" />
            ) : (
              <RotateCw className="size-[15px]" strokeWidth={1.9} />
            )
          }
          onClick={onRefresh}
        />
        <IconButton
          label={collapsed ? t('historyHosts.expand') : t('historyHosts.collapse')}
          aria-expanded={!collapsed}
          aria-controls={listId}
          icon={
            <ChevronDown
              className={cn('size-4 transition-transform', !collapsed && 'rotate-180')}
              strokeWidth={2}
            />
          }
          onClick={() => {
            storeCollapsed(!collapsed);
            setCollapsed(!collapsed);
          }}
        />
      </header>

      {secretCount > 0 ? (
        <div className="mx-4 mb-3 flex gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/10 px-3 py-2.5">
          <TriangleAlert
            aria-hidden="true"
            className="mt-0.5 size-4 shrink-0 text-warning"
            strokeWidth={2}
          />
          <div className="flex min-w-0 flex-col gap-0.5 text-[12.5px] leading-[18px]">
            <p className="font-medium text-warning">{t('historyHosts.secretsTitle')}</p>
            <p className="text-fg-2">
              {t('historyHosts.secretsText', {
                count: secretCount,
                files: list.format(secrets.map((file) => displayPath(file.path, home))),
              })}
            </p>
          </div>
        </div>
      ) : null}

      {shown.length > 0 && !collapsed ? (
        <ul
          id={listId}
          ref={listRef}
          className="flex flex-col divide-y divide-white/[0.06] border-t border-white/[0.06]"
        >
          {shown.map((suggestion, index) => (
            <SuggestionRow
              key={suggestion.id}
              suggestion={suggestion}
              lastUsed={
                suggestion.lastUsed
                  ? formatRelative(new Date(suggestion.lastUsed), i18n.language)
                  : null
              }
              onAdd={() => onAdd(formFromSuggestion(suggestion))}
              onDismiss={() => dismissRow(suggestion, index)}
            />
          ))}
        </ul>
      ) : null}

      {(more > 0 || expanded) && !collapsed ? (
        <div className="border-t border-white/[0.06] px-2 py-1.5">
          <Button
            size="sm"
            variant="ghost"
            aria-expanded={expanded}
            onClick={() => setExpanded((open) => !open)}
          >
            {expanded ? t('historyHosts.showLess') : t('historyHosts.showMore', { count: more })}
          </Button>
        </div>
      ) : null}
    </section>
  );
}

interface SuggestionRowProps {
  suggestion: HostSuggestion;
  lastUsed: string | null;
  onAdd: () => void;
  onDismiss: () => void;
}

function SuggestionRow({ suggestion, lastUsed, onAdd, onDismiss }: SuggestionRowProps) {
  const { t } = useTranslation();
  const target = suggestionTarget(suggestion);
  const mono = hostMonogram({ kind: 'host', patterns: [suggestion.alias], isWildcard: false });
  const uses = t('historyHosts.uses', { count: suggestion.uses });
  return (
    <li className="flex flex-wrap items-center gap-x-3 gap-y-2 px-4 py-2.5">
      <Tile tone={mono.tone} size={32}>
        <span className="font-mono text-[11.5px] font-semibold">{mono.text}</span>
      </Tile>
      <div className="flex min-w-[200px] flex-1 flex-col">
        <span className="selectable truncate font-mono text-[13px] font-medium" title={target}>
          {target}
        </span>
        <span className="truncate text-[12px] leading-[18px] text-subtle">
          {lastUsed ? t('historyHosts.usesAndLast', { uses, when: lastUsed }) : uses}
        </span>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        <Button
          size="sm"
          variant="soft"
          aria-label={t('historyHosts.addLabel', { target })}
          icon={<Plus className="size-3.5" strokeWidth={2.5} />}
          onClick={onAdd}
        >
          {t('historyHosts.add')}
        </Button>
        <IconButton
          label={t('historyHosts.dismiss', { target })}
          data-dismiss={suggestion.id}
          icon={<X className="size-[15px]" strokeWidth={2} />}
          onClick={onDismiss}
        />
      </div>
    </li>
  );
}
