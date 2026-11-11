import type { TFunction } from 'i18next';
import {
  Cpu,
  Download,
  FolderKanban,
  Globe,
  KeyRound,
  LayoutGrid,
  Lock,
  LockOpen,
  type LucideIcon,
  Network,
  Plus,
  Radar,
  RectangleEllipsis,
  RefreshCw,
  Server,
  Settings as SettingsIcon,
  ShieldCheck,
  Sparkle,
  SquareTerminal,
  Upload,
  User,
  Variable,
  Wrench,
} from 'lucide-react';
import { Dialog as RDialog } from 'radix-ui';
import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { invalidateAll, useConfig, useKeys, useVaultEntries, useVaultStatus } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { type Page, type Route, useRouter } from '@/app/router';
import { NAV_PAGES, PALETTE_EVENT } from '@/app/useAppEvents';
import type { Tone } from '@/components/ui/Tile';
import { toastVaultError } from '@/features/passwords/vault';
import { projectTone } from '@/features/projects/model';
import { useProjects } from '@/features/projects/queries';
import { useConnect } from '@/features/terminal/connect';
import { useTerminals } from '@/features/terminal/TerminalProvider';
import { TOOLS } from '@/features/tools/registry';
import { copyText } from '@/lib/clipboard';
import { platform } from '@/lib/platform';
import { checkForUpdates } from '@/lib/updater';
import {
  type EntryCopy,
  entryItems,
  hostItems,
  hostsOf,
  keyItems,
  type PaletteEntry,
  type PaletteItem,
} from './items';
import { PaletteSearch } from './PaletteSearch';
import { rememberRecent, useRecent } from './recent';
import { byRecent, parseQuery } from './search';
import { buildSections, type Group } from './sections';
import { shortcutLabel } from './shortcut';

const PAGE_LOOK: Record<Exclude<Page, 'tools' | 'project'>, { icon: LucideIcon; tone: Tone }> = {
  projects: { icon: LayoutGrid, tone: 'aurora' },
  personal: { icon: User, tone: 'slate' },
  suggestions: { icon: Sparkle, tone: 'aurora' },
  keys: { icon: KeyRound, tone: 'teal' },
  hosts: { icon: Server, tone: 'blue' },
  agent: { icon: Cpu, tone: 'violet' },
  known: { icon: Globe, tone: 'amber' },
  hostsFile: { icon: Network, tone: 'indigo' },
  passwords: { icon: RectangleEllipsis, tone: 'pink' },
  envs: { icon: Variable, tone: 'lime' },
  terminal: { icon: SquareTerminal, tone: 'green' },
  nearby: { icon: Radar, tone: 'orange' },
  audit: { icon: ShieldCheck, tone: 'rose' },
  settings: { icon: SettingsIcon, tone: 'slate' },
};

const EMPTY_PROJECTS: [] = [];

export const COPIED = {
  username: 'passwords.copiedUsername',
  password: 'passwords.copiedPassword',
  otp: 'passwords.copiedOtp',
} as const satisfies Record<EntryCopy, string>;

/** Copies a field of an entry through the backend, which clears the clipboard later. */
export async function copyEntry(t: TFunction, entry: PaletteEntry, field: EntryCopy) {
  try {
    const result = await api.vaultCopy(entry.id, field);
    toast.success(t(COPIED[field]), {
      id: 'vault-copy',
      description:
        result.clearsInSecs !== null
          ? t('passwords.clearsIn', { seconds: result.clearsInSecs })
          : undefined,
    });
  } catch (error) {
    toastVaultError(t, error);
  }
}

/**
 * The command palette, on ⌘K / Ctrl+K on every page (`PALETTE_EVENT`):
 * hosts, keys, the vault's entries while it is unlocked, pages, actions and
 * tools, in one search.
 */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  useEffect(() => {
    // Not over another dialog: what the palette runs belongs to the page.
    const toggle = () =>
      setOpen((value) => !value && !document.querySelector('[role=dialog], [role=alertdialog]'));
    window.addEventListener(PALETTE_EVENT, toggle);
    return () => window.removeEventListener(PALETTE_EVENT, toggle);
  }, []);
  return (
    <RDialog.Root open={open} onOpenChange={setOpen}>
      {open ? <PaletteDialog onClose={() => setOpen(false)} /> : null}
    </RDialog.Root>
  );
}

function PaletteDialog({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const { route, navigate } = useRouter();
  const dialogs = useDialogs();
  const connect = useConnect();
  const { setPickerOpen } = useTerminals();
  const config = useConfig().data;
  const keys = useKeys().data;
  const vaultState = useVaultStatus().data?.state;
  const entries = useVaultEntries().data;
  const recent = useRecent();
  const [query, setQuery] = useState('');
  const opener = useRef<HTMLElement | null>(null);
  const chosen = useRef<PaletteItem | null>(null);

  const actions = useMemo<PaletteItem[]>(() => {
    const action = (
      id: string,
      title: string,
      icon: LucideIcon,
      tone: Tone,
      run: () => void,
      shortcut?: string,
    ): PaletteItem => ({
      id: `action:${id}`,
      title,
      action: '',
      shortcut,
      verbs: [],
      scope: 'actions',
      icon,
      tone,
      run,
    });
    const list = [
      action(
        'new-key',
        t('palette.actions.newKey'),
        Plus,
        'teal',
        dialogs.generateKey,
        shortcutLabel('N'),
      ),
      action(
        'import-key',
        t('palette.actions.importKey'),
        Upload,
        'teal',
        () => void dialogs.importKey(),
        shortcutLabel('O'),
      ),
      action(
        'add-host',
        t('palette.actions.addHost'),
        Server,
        'blue',
        dialogs.addHost,
        shortcutLabel('N', true),
      ),
      action(
        'new-session',
        t('palette.actions.newSession'),
        SquareTerminal,
        'green',
        () => {
          navigate({ page: 'terminal' });
          setPickerOpen(true);
        },
        platform === 'macos' ? shortcutLabel('T') : shortcutLabel('T', true),
      ),
    ];
    if (vaultState === 'unlocked') {
      const lock = () =>
        api.vaultLock().then(invalidateAll, (error: unknown) => toastVaultError(t, error));
      list.push(
        action('lock-vault', t('palette.actions.lockVault'), Lock, 'pink', () => void lock()),
      );
    } else if (vaultState === 'locked') {
      list.push(
        action('unlock-vault', t('palette.actions.unlockVault'), LockOpen, 'pink', () =>
          dialogs.unlockVault(),
        ),
      );
    }
    list.push(
      action(
        'check',
        t('palette.actions.checkAgain'),
        RefreshCw,
        'slate',
        () => void invalidateAll(),
        shortcutLabel('R'),
      ),
      action(
        'updates',
        t('palette.actions.checkUpdates'),
        Download,
        'slate',
        () => void checkForUpdates(),
      ),
    );
    return list;
  }, [t, dialogs, navigate, setPickerOpen, vaultState]);

  const projects = useProjects().data ?? EMPTY_PROJECTS;
  const pages = useMemo<PaletteItem[]>(() => {
    const list: PaletteItem[] = (Object.keys(PAGE_LOOK) as (keyof typeof PAGE_LOOK)[]).map(
      (page) => {
        const digit = NAV_PAGES.indexOf(page);
        return {
          id: `page:${page}`,
          title: t(`nav.${page}`),
          action: t('palette.verbs.openPage'),
          shortcut:
            digit >= 0
              ? shortcutLabel(String(digit + 1))
              : page === 'settings'
                ? shortcutLabel(',')
                : undefined,
          verbs: [t('palette.verbs.openPage'), 'go', 'open', 'page'],
          scope: 'actions',
          ...PAGE_LOOK[page],
          run: () => navigate({ page } as Route),
        };
      },
    );
    // Projects first: they are where things are used.
    list.unshift(
      ...projects.map(
        (project): PaletteItem => ({
          id: `project:${project.id}`,
          title: project.name,
          action: t('palette.verbs.openProject'),
          verbs: [t('palette.verbs.openProject'), 'project', 'open'],
          scope: 'actions',
          icon: FolderKanban,
          tone: projectTone(project.color),
          run: () => navigate({ page: 'project', id: project.id }),
        }),
      ),
    );
    if (TOOLS.length > 0) {
      list.splice(list.length - 1, 0, {
        id: 'page:tools',
        title: t('nav.tools'),
        action: t('palette.verbs.openPage'),
        verbs: [t('palette.verbs.openPage'), 'go', 'open', 'page'],
        scope: 'actions',
        icon: Wrench,
        tone: 'cyan',
        run: () => navigate({ page: 'tools' }),
      });
    }
    return list;
  }, [t, navigate, projects]);

  const tools = useMemo<PaletteItem[]>(
    () =>
      TOOLS.map((tool) => {
        const { title, description } = tool.text(t);
        return {
          id: `tool:${tool.id}`,
          title,
          detail: description,
          action: t('palette.verbs.openTool'),
          verbs: [t('palette.verbs.openTool'), 'open', 'tool'],
          keywords: [description],
          scope: 'actions',
          icon: tool.icon,
          tone: tool.tone,
          run: () => navigate({ page: 'tools', tool: tool.id }),
        };
      }),
    [t, navigate],
  );

  const hosts = useMemo(
    () =>
      hostItems(t, hostsOf(config?.view.hosts ?? []), {
        connect,
        open: (hostId) => navigate({ page: 'hosts', hostId }),
      }),
    [t, config, connect, navigate],
  );

  const keyList = useMemo(
    () =>
      keyItems(t, keys?.keys ?? [], {
        open: (key) => navigate({ page: 'keys', keyId: key.id }),
        copyPublic: (key) => {
          copyText(key.publicKey ?? '').then(
            () => toast.success(t('keys.copiedPublic')),
            (error: unknown) => toastError(t, error),
          );
        },
        addToAgent: (key) => dialogs.unlockKey(key),
      }),
    [t, keys, navigate, dialogs],
  );

  const passwords = useMemo(
    () =>
      vaultState === 'unlocked'
        ? entryItems(
            t,
            (entries ?? []).filter((entry) => !entry.inTrash),
            {
              copy: (entry, field) => void copyEntry(t, entry, field),
              open: (entryId) => navigate({ page: 'passwords', entryId }),
            },
          )
        : [],
    [t, vaultState, entries, navigate],
  );

  const unlockItem = actions.find((item) => item.id === 'action:unlock-vault');
  const all = useMemo(
    () => [...actions, ...pages, ...tools, ...hosts, ...keyList, ...passwords],
    [actions, pages, tools, hosts, keyList, passwords],
  );
  const { scope, text } = parseQuery(query);
  const sections = useMemo(() => {
    if (scope === 'passwords' && unlockItem) {
      return [
        {
          id: 'locked',
          label: t('palette.groups.locked'),
          items: [{ item: unlockItem, tier: 0 as const, score: 0, positions: [] }],
        },
      ];
    }
    const browse = (target: typeof scope): Group[] => {
      if (target === 'hosts') {
        return [
          {
            id: 'hosts',
            label: t('palette.groups.hosts'),
            items: byRecent(
              hosts.filter((item) => item.primary),
              recent,
            ),
          },
        ];
      }
      if (target === 'passwords') {
        return [
          {
            id: 'passwords',
            label: t('palette.groups.passwords'),
            items: byRecent(
              passwords.filter((item) => item.primary),
              recent,
            ),
          },
        ];
      }
      return [
        { id: 'actions', label: t('palette.groups.actions'), items: actions },
        { id: 'pages', label: t('palette.groups.pages'), items: pages },
        ...(target === 'actions'
          ? [{ id: 'tools', label: t('palette.groups.tools'), items: tools }]
          : []),
      ];
    };
    return buildSections(all, query, {
      recent,
      recentLabel: t('palette.groups.recent'),
      browse,
    });
  }, [scope, unlockItem, all, query, recent, t, hosts, passwords, actions, pages, tools]);

  const run = (item: PaletteItem) => {
    rememberRecent(item.id);
    chosen.current = item;
    onClose();
  };

  const empty = text
    ? t('palette.noMatches', { query: text })
    : scope === 'hosts'
      ? t('palette.noHosts')
      : scope === 'passwords'
        ? vaultState === 'missing'
          ? t('palette.noVault')
          : t('palette.noPasswords')
        : null;

  return (
    <RDialog.Portal>
      <RDialog.Overlay className="fixed inset-0 z-40 bg-[rgb(4_6_11/0.62)] data-[state=open]:animate-fade-in" />
      <div className="pointer-events-none fixed inset-0 z-50 flex justify-center px-4 pt-[12vh] pb-4">
        <RDialog.Content
          data-section={route.page}
          onOpenAutoFocus={(event) => {
            const active = document.activeElement;
            opener.current =
              active instanceof HTMLElement && active !== document.body ? active : null;
            event.preventDefault();
            (event.currentTarget as HTMLElement).querySelector('input')?.focus();
          }}
          // The item runs once the palette has given the focus back (Radix
          // does that a moment after closing), so a dialog it opens keeps it.
          onCloseAutoFocus={(event) => {
            event.preventDefault();
            if (opener.current?.isConnected) opener.current.focus();
            const item = chosen.current;
            chosen.current = null;
            item?.run();
          }}
          className="pointer-events-auto relative flex h-fit max-h-[min(560px,calc(100vh-12vh-16px))] w-full max-w-[640px] flex-col overflow-clip rounded-[22px] border border-white/10 bg-[linear-gradient(180deg,rgb(26_31_46/0.98),rgb(15_18_28/0.98))] text-fg shadow-[0_40px_80px_-24px_rgb(0_0_0/0.8),inset_0_1px_0_rgb(255_255_255/0.06)] outline-none data-[state=open]:animate-dialog-in"
        >
          <RDialog.Title className="sr-only">{t('palette.title')}</RDialog.Title>
          <RDialog.Description className="sr-only">{t('palette.description')}</RDialog.Description>
          <PaletteSearch
            query={query}
            onQueryChange={setQuery}
            sections={sections}
            onRun={run}
            placeholder={t('palette.placeholder')}
            empty={empty}
            prefixes={['>', '@', '#']}
            className="max-h-[inherit]"
          />
        </RDialog.Content>
      </div>
    </RDialog.Portal>
  );
}
