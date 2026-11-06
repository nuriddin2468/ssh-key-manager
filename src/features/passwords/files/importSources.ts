// Where an import can come from, and how to get the export file out of each.
// Browsers and password managers keep their passwords to themselves: each
// writes them to a CSV file on request, which the import then reads. So the
// import asks where the passwords are now and says how to export them there;
// a CSV file of any other app comes last.

import { Compass, FileSpreadsheet, Flame, Globe, KeyRound, type LucideIcon } from 'lucide-react';
import type { Tone } from '@/components/ui/Tile';
import type { Platform } from '@/lib/platform';

export type SourceId =
  | 'chrome'
  | 'edge'
  | 'brave'
  | 'vivaldi'
  | 'firefox'
  | 'safari'
  | 'bitwarden'
  | 'onePassword'
  | 'keepassxc'
  | 'lastpass'
  | 'other';

/** A step of a source's export guide: its text's key under `vaultFiles.import.guide`. */
export type GuideStep =
  | 'open'
  | 'settingsOpen'
  | 'chromiumExport'
  | 'firefoxExport'
  | 'safariOpen'
  | 'safariExport'
  | 'bitwardenExport'
  | 'bitwardenFormat'
  | 'onePasswordExport'
  | 'onePasswordFormat'
  | 'keepassxcExport'
  | 'lastpassExport'
  | 'otherExport'
  | 'otherColumns';

export interface ImportSource {
  id: SourceId;
  kind: 'browser' | 'manager' | 'file';
  /** A product name, the same in every language; none for `other`. */
  name?: string;
  /** The name the app's browser detection gives it (`BrowserInstall.name`). */
  installName?: string;
  /** The page of saved passwords, to paste into the browser's address bar. */
  address?: string;
  /** Only on these systems. */
  only?: Platform[];
  /** Shown only when it is installed. */
  ifInstalled?: boolean;
  tone: Tone;
  icon: LucideIcon;
  steps: GuideStep[];
}

/** A Chromium browser; without `address`, the guide sends the user to its settings. */
const chromium = (
  id: SourceId,
  name: string,
  address: string | undefined,
  tone: Tone,
  ifInstalled = false,
): ImportSource => ({
  id,
  kind: 'browser',
  name,
  installName: name === 'Chrome' ? 'Google Chrome' : name,
  address,
  ifInstalled,
  tone,
  icon: Globe,
  steps: [address ? 'open' : 'settingsOpen', 'chromiumExport'],
});

export const SOURCES: ImportSource[] = [
  chromium('chrome', 'Chrome', 'chrome://password-manager/settings', 'blue'),
  chromium('edge', 'Microsoft Edge', 'edge://settings/passwords', 'teal'),
  chromium('brave', 'Brave', 'brave://settings/passwords', 'orange'),
  chromium('vivaldi', 'Vivaldi', undefined, 'rose', true),
  {
    id: 'firefox',
    kind: 'browser',
    name: 'Firefox',
    installName: 'Firefox',
    address: 'about:logins',
    tone: 'amber',
    icon: Flame,
    steps: ['open', 'firefoxExport'],
  },
  {
    id: 'safari',
    kind: 'browser',
    name: 'Safari',
    only: ['macos'],
    tone: 'blue',
    icon: Compass,
    steps: ['safariOpen', 'safariExport'],
  },
  {
    id: 'bitwarden',
    kind: 'manager',
    name: 'Bitwarden',
    tone: 'blue',
    icon: KeyRound,
    steps: ['bitwardenExport', 'bitwardenFormat'],
  },
  {
    id: 'onePassword',
    kind: 'manager',
    name: '1Password',
    tone: 'indigo',
    icon: KeyRound,
    steps: ['onePasswordExport', 'onePasswordFormat'],
  },
  {
    id: 'keepassxc',
    kind: 'manager',
    name: 'KeePassXC',
    tone: 'green',
    icon: KeyRound,
    steps: ['keepassxcExport'],
  },
  {
    id: 'lastpass',
    kind: 'manager',
    name: 'LastPass',
    tone: 'rose',
    icon: KeyRound,
    steps: ['lastpassExport'],
  },
  {
    id: 'other',
    kind: 'file',
    tone: 'slate',
    icon: FileSpreadsheet,
    steps: ['otherExport', 'otherColumns'],
  },
];

/**
 * The sources to offer on `platform`: browsers on this computer first (as
 * the app's browser detection found them), then the other browsers, the
 * password managers, and any CSV file last.
 */
export function sourcesFor(platform: Platform, installed: ReadonlySet<string>): ImportSource[] {
  const here = (source: ImportSource) =>
    source.installName !== undefined && installed.has(source.installName);
  const offered = SOURCES.filter(
    (source) =>
      (!source.only || source.only.includes(platform)) && (!source.ifInstalled || here(source)),
  );
  const rank = (source: ImportSource) =>
    source.kind === 'browser'
      ? here(source) || source.only
        ? 0
        : 1
      : source.kind === 'manager'
        ? 2
        : 3;
  return offered
    .map((source, at) => ({ source, at }))
    .sort((a, b) => rank(a.source) - rank(b.source) || a.at - b.at)
    .map(({ source }) => source);
}
