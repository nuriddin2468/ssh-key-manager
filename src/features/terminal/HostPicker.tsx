import { Laptop, SquareTerminal } from 'lucide-react';
import { type KeyboardEvent, type ReactNode, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useConfig } from '@/api/queries';
import type { ShellInfo } from '@/bindings/ShellInfo';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Kbd } from '@/components/ui/Kbd';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { useSettings } from '@/lib/settings';
import { isConnectable } from './model';
import { defaultShell, shellDetail, shellName, useShells } from './shells';

type Choice =
  | { type: 'shell'; key: string; shell: ShellInfo; name: string; detail: string | null }
  /** `detail`: `user@hostname`, if the block says. */
  | { type: 'host'; key: string; alias: string; detail: string };

/**
 * "New session": the shells on this computer, then the config's hosts. The
 * search narrows both; Enter opens the highlighted one.
 */
export function HostPicker({
  onPick,
  onPickShell,
  onCancel,
}: {
  onPick: (alias: string) => void;
  onPickShell: (shell: string) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const config = useConfig();
  const shells = useShells();
  const settings = useSettings();
  const [query, setQuery] = useState('');
  const [highlight, setHighlight] = useState(0);
  const listId = useId();

  const opensByDefault = defaultShell(shells.data, settings.defaultShell);

  const hosts = useMemo(() => {
    const out: Choice[] = [];
    const seen = new Set<string>();
    for (const host of config.data?.view.hosts ?? []) {
      if (host.kind !== 'host' || host.isWildcard) continue;
      const detail = [host.user, host.hostName].filter(Boolean).join('@');
      for (const alias of host.patterns) {
        if (!isConnectable(alias) || seen.has(alias)) continue;
        seen.add(alias);
        out.push({ type: 'host', key: `host:${alias}`, alias, detail });
      }
    }
    return out;
  }, [config.data]);

  const local = useMemo(() => {
    const all = shells.data ?? [];
    // The one that opens by default first, the rest as the system lists them.
    const ordered = [
      ...all.filter((shell) => shell === opensByDefault),
      ...all.filter((shell) => shell !== opensByDefault),
    ];
    return ordered.map<Choice>((shell) => ({
      type: 'shell',
      key: `shell:${shell.id}`,
      shell,
      name: shellName(t, shell),
      detail: shellDetail(shell, all),
    }));
  }, [shells.data, opensByDefault, t]);

  const needle = query.trim().toLowerCase();
  const matches = (choice: Choice) =>
    !needle ||
    (choice.type === 'shell'
      ? choice.name.toLowerCase().includes(needle) ||
        choice.shell.path.toLowerCase().includes(needle)
      : choice.alias.toLowerCase().includes(needle) ||
        choice.detail.toLowerCase().includes(needle));
  const shownShells = local.filter(matches);
  const shownHosts = hosts.filter(matches);
  const shown = [...shownShells, ...shownHosts];
  const current = shown[Math.min(highlight, shown.length - 1)];
  const optionId = (index: number) => `${listId}-${index}`;

  const pick = (choice: Choice) =>
    choice.type === 'shell' ? onPickShell(choice.shell.id) : onPick(choice.alias);

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === 'ArrowDown') setHighlight((i) => Math.min(i + 1, shown.length - 1));
    else if (event.key === 'ArrowUp') setHighlight((i) => Math.max(i - 1, 0));
    else if (event.key === 'Enter' && current) pick(current);
    else return;
    event.preventDefault();
  };

  const option = (choice: Choice) => {
    const index = shown.indexOf(choice);
    return (
      // biome-ignore lint/a11y/useKeyWithClickEvents: the search field takes the keys (aria-activedescendant)
      <div
        key={choice.key}
        id={optionId(index)}
        role="option"
        aria-selected={choice === current}
        tabIndex={-1}
        onMouseEnter={() => setHighlight(index)}
        onClick={() => pick(choice)}
        className={cn(
          'flex h-[38px] min-w-0 shrink-0 items-center gap-2.5 rounded-[10px] px-2.5',
          choice === current ? 'selected-row' : 'hover:bg-white/[0.04]',
        )}
      >
        {choice.type === 'shell' ? (
          <>
            <span className="truncate text-[13px] text-fg">{choice.name}</span>
            {choice.detail ? (
              <span className="truncate font-mono text-[11.5px] text-subtle">{choice.detail}</span>
            ) : null}
            {choice.shell === opensByDefault ? (
              <span className="ml-auto shrink-0 text-[11.5px] text-subtle">
                {t('terminal.picker.default')}
              </span>
            ) : null}
          </>
        ) : (
          <>
            <span className="truncate font-mono text-[12.5px] text-fg">{choice.alias}</span>
            <span className="truncate text-[12px] text-subtle">{choice.detail}</span>
          </>
        )}
      </div>
    );
  };

  return (
    <DialogContent section="terminal" className="max-w-[480px]">
      <DialogHeader
        icon={
          <Tile tone="green" size={40} glow>
            <SquareTerminal className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('terminal.picker.title')}
        description={t('terminal.picker.description')}
      />
      <DialogBody className="gap-3">
        <TextField
          label={t('terminal.picker.search')}
          value={query}
          onChange={(event) => {
            setQuery(event.target.value);
            setHighlight(0);
          }}
          onKeyDown={onKeyDown}
          placeholder={t('terminal.picker.placeholder')}
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={shown.length > 0}
          aria-controls={listId}
          aria-activedescendant={current ? optionId(shown.indexOf(current)) : undefined}
          mono
        />
        {shown.length > 0 ? (
          <div
            id={listId}
            role="listbox"
            aria-label={t('terminal.picker.list')}
            className="flex max-h-[340px] flex-col gap-0.5 overflow-y-auto"
          >
            {shownShells.length > 0 ? (
              <Group
                label={t('terminal.picker.local')}
                icon={<Laptop className="size-3.5" strokeWidth={2} />}
              >
                {shownShells.map(option)}
              </Group>
            ) : null}
            {shownHosts.length > 0 ? (
              <Group
                label={t('terminal.picker.hosts')}
                icon={<SquareTerminal className="size-3.5" strokeWidth={2} />}
              >
                {shownHosts.map(option)}
              </Group>
            ) : null}
          </div>
        ) : (
          <p role="status" className="py-4 text-center text-[12.5px] text-muted">
            {needle
              ? t('terminal.picker.noMatches', { query: query.trim() })
              : t('terminal.picker.noHosts')}
          </p>
        )}
        {shown.length > 0 && hosts.length === 0 && !needle ? (
          <p className="px-2.5 text-[12px] text-subtle">{t('terminal.picker.noHosts')}</p>
        ) : null}
      </DialogBody>
      <DialogFooter>
        <span className="mr-auto flex items-center gap-1.5 text-[12px] text-subtle">
          <Kbd>↵</Kbd>
          {t('terminal.picker.hint')}
        </span>
        <Button size="lg" onClick={onCancel}>
          {t('common.cancel')}
        </Button>
        <Button
          variant="primary"
          size="lg"
          disabled={!current}
          onClick={() => current && pick(current)}
        >
          {current?.type === 'shell' ? t('terminal.picker.open') : t('terminal.picker.connect')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

/** A labelled part of the list: the shells, or the hosts. */
function Group({ label, icon, children }: { label: string; icon: ReactNode; children: ReactNode }) {
  const id = useId();
  return (
    // A fieldset is a group to assistive tech, as the listbox's sections should be.
    <fieldset aria-labelledby={id} className="flex min-w-0 flex-col gap-0.5 pb-1">
      <div
        id={id}
        role="presentation"
        className="flex items-center gap-1.5 px-2.5 pt-1.5 pb-1 text-[11.5px] font-semibold tracking-[0.02em] text-subtle"
      >
        <span aria-hidden="true" className="flex">
          {icon}
        </span>
        {label}
      </div>
      {children}
    </fieldset>
  );
}
