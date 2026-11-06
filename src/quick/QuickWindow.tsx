import { useQuery } from '@tanstack/react-query';
import { ArrowLeft, LockOpen } from 'lucide-react';
import { type FormEvent, useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { queryClient, useVaultStatus } from '@/api/queries';
import { errorMessage } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { VaultIcon } from '@/features/keys/VaultControls';
import {
  type EntryCopy,
  entryItems,
  hostItems,
  type PaletteEntry,
  type PaletteItem,
} from '@/features/palette/items';
import { PaletteSearch } from '@/features/palette/PaletteSearch';
import { rememberRecent, useRecent } from '@/features/palette/recent';
import { byRecent, parseQuery } from '@/features/palette/search';
import { buildSections, type Group, type Section } from '@/features/palette/sections';
import { DeviceIcon, METHOD_NAME } from '@/features/passwords/device';
import { useVaultUnlock } from '@/features/passwords/UnlockVaultDialog';
import { AppError } from '@/lib/ipc';

const itemsKey = ['quick', 'items'] as const;
const UNLOCK_ID = 'quick:unlock';

/** Closes the window; `back` gives the focus to the app the user came from. */
function close(back: boolean): void {
  api.quickClose(back).catch(() => undefined);
}

/**
 * Quick search, in a window of its own that the system-wide shortcut opens
 * (src-tauri/src/quick/mod.rs): connect to a host, copy a password, user
 * name or 2FA code through the backend (which clears the clipboard later),
 * or unlock the vault first. Escape, a copy and losing the focus close it.
 */
export function QuickWindow() {
  const { t } = useTranslation();
  const status = useVaultStatus().data;
  const data = useQuery({ queryKey: itemsKey, queryFn: api.quickItems }).data;
  const recent = useRecent();
  const [query, setQuery] = useState('');
  const [unlocking, setUnlocking] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const vault = useVaultUnlock({
    onUnlocked: () => {
      setUnlocking(false);
      setProblem(null);
    },
    inline: true,
  });
  // Touch ID or Windows Hello takes the focus while it asks: that's no
  // reason to close.
  const holding = useRef(false);
  holding.current = vault.busy;

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented) return;
      event.preventDefault();
      if (unlocking) setUnlocking(false);
      else close(true);
    };
    const onBlur = () => {
      if (!holding.current) close(false);
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('blur', onBlur);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('blur', onBlur);
    };
  }, [unlocking]);

  // Back in the search, the field has the focus.
  useEffect(() => {
    if (unlocking) return;
    const focus = () => input.current?.focus();
    focus();
    window.addEventListener('focus', focus);
    return () => window.removeEventListener('focus', focus);
  }, [unlocking]);

  const canUnlock =
    status?.state === 'locked' && (status.files.hasMasterPassword || status.device.enabled);

  const items = useMemo(() => {
    const copy = async (entry: PaletteEntry, field: EntryCopy) => {
      setBusy(`entry:${entry.id}:${field}`);
      setProblem(null);
      try {
        await api.vaultCopy(entry.id, field);
        close(true);
      } catch (error) {
        setBusy(null);
        if (AppError.from(error).code === 'vault_locked') {
          void queryClient.invalidateQueries();
        }
        setProblem(errorMessage(t, error));
      }
    };
    return [
      ...hostItems(
        t,
        (data?.hosts ?? []).map((host) => ({ ...host, connectable: true })),
        {
          connect: (alias) => {
            setBusy(`host:${alias}:connect`);
            api.quickConnect(alias).catch((error: unknown) => {
              setBusy(null);
              setProblem(errorMessage(t, error));
            });
          },
        },
      ),
      ...entryItems(t, data?.entries ?? [], { copy: (entry, field) => void copy(entry, field) }),
    ];
  }, [t, data]);

  const unlockItem = useMemo<PaletteItem | null>(
    () =>
      canUnlock
        ? {
            id: UNLOCK_ID,
            title: t('palette.quick.unlock'),
            detail: t('palette.quick.unlockDetail'),
            action: t('palette.verbs.unlock'),
            verbs: [t('palette.verbs.unlock'), 'unlock', 'vault'],
            scope: 'passwords',
            icon: LockOpen,
            tone: 'pink',
            run: () => {
              setProblem(null);
              setUnlocking(true);
              if (vault.device) vault.unlockWithDevice();
            },
          }
        : null,
    [canUnlock, t, vault],
  );

  const { scope, text } = parseQuery(query);
  const sections = useMemo<Section[]>(() => {
    const browse = (target: typeof scope): Group[] => {
      const hosts = {
        id: 'hosts',
        label: t('palette.groups.hosts'),
        items: byRecent(
          items.filter((item) => item.scope === 'hosts'),
          recent,
        ),
      };
      const passwords = {
        id: 'passwords',
        label: t('palette.groups.passwords'),
        items: byRecent(
          items.filter((item) => item.scope === 'passwords' && item.primary),
          recent,
        ),
      };
      if (target === 'hosts') return [hosts];
      if (target === 'passwords') return [passwords];
      return target === 'all' ? [hosts, passwords] : [];
    };
    const found = buildSections(items, query, {
      recent,
      recentLabel: t('palette.groups.recent'),
      browse,
    });
    if (!unlockItem || scope === 'hosts' || scope === 'actions') return found;
    const locked: Section = {
      id: 'locked',
      label: t('palette.groups.locked'),
      items: [{ item: unlockItem, tier: 0, score: 0, positions: [] }],
    };
    // With nothing typed, unlocking comes first: the passwords wait behind it.
    return text ? [...found, locked] : [locked, ...found];
  }, [items, query, recent, t, unlockItem, scope, text]);

  const run = (item: PaletteItem) => {
    if (busy) return;
    if (item.id !== UNLOCK_ID) rememberRecent(item.id);
    item.run();
  };

  const empty = text
    ? t('palette.noMatches', { query: text })
    : scope === 'hosts'
      ? t('palette.noHosts')
      : scope === 'passwords'
        ? status?.state === 'missing'
          ? t('palette.noVault')
          : t('palette.noPasswords')
        : null;

  return (
    <main
      data-section="overview"
      className="flex h-full flex-col overflow-hidden border border-white/10 bg-[linear-gradient(180deg,rgb(26_31_46),rgb(15_18_28))]"
    >
      <h1 className="sr-only">{t('palette.quick.title')}</h1>
      {unlocking ? (
        <UnlockForm vault={vault} onBack={() => setUnlocking(false)} />
      ) : (
        <PaletteSearch
          query={query}
          onQueryChange={(next) => {
            setQuery(next);
            setProblem(null);
          }}
          sections={sections}
          onRun={run}
          placeholder={t('palette.quick.placeholder')}
          empty={empty}
          prefixes={['@', '#']}
          busy={busy}
          notice={problem}
          inputRef={input}
          className="flex-1"
        />
      )}
    </main>
  );
}

/** The master password, and Touch ID or Windows Hello, as in the unlock window. */
function UnlockForm({
  vault,
  onBack,
}: {
  vault: ReturnType<typeof useVaultUnlock>;
  onBack: () => void;
}) {
  const { t } = useTranslation();
  const { device, master, password, wrong, failure, via, busy } = vault;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    vault.unlockWithMaster();
  };
  const problem = wrong
    ? t('passwords.wrongMaster')
    : failure
      ? errorMessage(t, failure)
      : undefined;

  return (
    <div data-section="passwords" className="flex min-h-0 flex-1 flex-col">
      <header className="flex h-[52px] shrink-0 items-center gap-3 border-b border-white/[0.07] px-3">
        <Button size="sm" variant="ghost" icon={<ArrowLeft className="size-4" />} onClick={onBack}>
          {t('palette.quick.back')}
        </Button>
      </header>
      <form
        onSubmit={submit}
        noValidate
        className="flex min-h-0 flex-1 flex-col gap-4 px-6 pt-5 pb-5"
      >
        <div className="flex items-center gap-3">
          <Tile tone="pink" size={36} glow>
            <VaultIcon className="size-[18px]" />
          </Tile>
          <h2 className="text-[15px] font-semibold">{t('passwords.unlockVaultTitle')}</h2>
        </div>
        {master ? (
          <TextField
            label={t('passwords.masterPassword')}
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => vault.setPassword(event.target.value)}
            error={problem}
            autoFocus
          />
        ) : (
          <p className="text-[12.5px] text-muted" role={failure ? 'alert' : undefined}>
            {problem}
          </p>
        )}
        <div className="mt-auto flex items-center gap-2">
          {device ? (
            <Button
              variant={master ? 'secondary' : 'primary'}
              icon={<DeviceIcon kind={device} className="size-[16px]" />}
              loading={busy && via === 'device'}
              disabled={busy}
              onClick={vault.unlockWithDevice}
            >
              {METHOD_NAME[device]}
            </Button>
          ) : null}
          {master ? (
            <Button
              type="submit"
              variant="primary"
              className="ml-auto"
              loading={busy && via === 'master'}
              disabled={!password || busy}
            >
              {t('passwords.unlock')}
            </Button>
          ) : null}
        </div>
      </form>
    </div>
  );
}
