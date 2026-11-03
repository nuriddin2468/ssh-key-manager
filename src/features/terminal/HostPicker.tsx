import { SquareTerminal } from 'lucide-react';
import { type KeyboardEvent, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useConfig } from '@/api/queries';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Kbd } from '@/components/ui/Kbd';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { isConnectable } from './model';

interface Choice {
  alias: string;
  /** `user@hostname`, if the block says. */
  detail: string;
}

/** "Connect…": search the config's hosts, Enter connects to the highlighted one. */
export function HostPicker({
  onPick,
  onCancel,
}: {
  onPick: (alias: string) => void;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const config = useConfig();
  const [query, setQuery] = useState('');
  const [highlight, setHighlight] = useState(0);
  const listId = useId();

  const choices = useMemo<Choice[]>(() => {
    const out: Choice[] = [];
    const seen = new Set<string>();
    for (const host of config.data?.view.hosts ?? []) {
      if (host.kind !== 'host' || host.isWildcard) continue;
      const detail = [host.user, host.hostName].filter(Boolean).join('@');
      for (const alias of host.patterns) {
        if (!isConnectable(alias) || seen.has(alias)) continue;
        seen.add(alias);
        out.push({ alias, detail });
      }
    }
    return out;
  }, [config.data]);

  const needle = query.trim().toLowerCase();
  const shown = needle
    ? choices.filter(
        (choice) =>
          choice.alias.toLowerCase().includes(needle) ||
          choice.detail.toLowerCase().includes(needle),
      )
    : choices;
  const current = shown[Math.min(highlight, shown.length - 1)];
  const optionId = (index: number) => `${listId}-${index}`;

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === 'ArrowDown') setHighlight((i) => Math.min(i + 1, shown.length - 1));
    else if (event.key === 'ArrowUp') setHighlight((i) => Math.max(i - 1, 0));
    else if (event.key === 'Enter' && current) onPick(current.alias);
    else return;
    event.preventDefault();
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
            aria-label={t('terminal.picker.hosts')}
            className="flex max-h-[300px] flex-col gap-0.5 overflow-y-auto"
          >
            {shown.map((choice, index) => (
              // biome-ignore lint/a11y/useKeyWithClickEvents: the search field takes the keys (aria-activedescendant)
              <div
                key={choice.alias}
                id={optionId(index)}
                role="option"
                aria-selected={choice === current}
                tabIndex={-1}
                onMouseEnter={() => setHighlight(index)}
                onClick={() => onPick(choice.alias)}
                className={cn(
                  'flex h-[38px] min-w-0 items-center gap-2.5 rounded-[10px] px-2.5',
                  choice === current ? 'selected-row' : 'hover:bg-white/[0.04]',
                )}
              >
                <span className="truncate font-mono text-[12.5px] text-fg">{choice.alias}</span>
                <span className="truncate text-[12px] text-subtle">{choice.detail}</span>
              </div>
            ))}
          </div>
        ) : (
          <p role="status" className="py-4 text-center text-[12.5px] text-muted">
            {choices.length === 0
              ? t('terminal.picker.noHosts')
              : t('terminal.picker.noMatches', { query: query.trim() })}
          </p>
        )}
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
          onClick={() => current && onPick(current.alias)}
        >
          {t('terminal.picker.connect')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
