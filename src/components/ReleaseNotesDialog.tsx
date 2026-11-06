import { isTauri } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import {
  Download,
  ExternalLink,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  TriangleAlert,
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { Change } from '@/bindings/Change';
import type { ChangeKind } from '@/bindings/ChangeKind';
import type { Release } from '@/bindings/Release';
import { Badge, type BadgeTone } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import {
  Dialog,
  DialogBody,
  DialogClose,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { Tile } from '@/components/ui/Tile';
import { Callout } from '@/features/passwords/files/Callout';
import { noteText, RELEASES, showReleaseNotes, useReleaseNotes } from '@/lib/releaseNotes';
import { installUpdate, useUpdateState } from '@/lib/updater';

const RELEASES_URL = 'https://github.com/nuriddin2468/ssh-key-manager/releases';

/** The order a release lists its changes in, and each kind's badge. */
const KINDS: [ChangeKind, BadgeTone][] = [
  ['notice', 'warning'],
  ['security', 'critical'],
  ['new', 'info'],
  ['improved', 'violet'],
  ['fixed', 'neutral'],
];

/**
 * What each version changed: before an update (with the install button),
 * once after it, and from Settings. Before an update, what to know first
 * and security fixes come at the top.
 */
export function ReleaseNotesDialog() {
  const { t, i18n } = useTranslation();
  const view = useReleaseNotes();
  const update = useUpdateState();
  if (view === null) return null;

  const offer = view.kind === 'offer';
  const releases = view.kind === 'history' ? RELEASES : view.releases;
  const changes = releases.flatMap((release) => release.changes);
  const notices = offer ? changes.filter((change) => change.kind === 'notice') : [];
  const security = offer && changes.some((change) => change.kind === 'security');
  const close = () => showReleaseNotes(null);

  let title: string;
  let description: string;
  if (view.kind === 'offer') {
    title = t('updates.available', { version: view.version });
    description =
      releases.length > 1
        ? t('updates.offerSince', { count: releases.length })
        : t('updates.offerHint');
  } else if (view.kind === 'updated') {
    title = t('updates.updated', { version: view.version });
    description = t('updates.updatedHint');
  } else {
    title = t('updates.history');
    description = t('updates.historyHint');
  }

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : close())}>
      <DialogContent section="settings" className="max-w-[580px]">
        <DialogHeader
          icon={
            <Tile tone="teal" size={34}>
              {offer ? (
                <Download aria-hidden="true" className="size-4 text-white" strokeWidth={2.25} />
              ) : (
                <Sparkles aria-hidden="true" className="size-4 text-white" strokeWidth={2.25} />
              )}
            </Tile>
          }
          title={title}
          description={description}
        />
        <DialogBody>
          {security ? (
            <Callout tone="critical" icon={ShieldAlert} title={t('updates.securityTitle')}>
              {t('updates.securityHint')}
            </Callout>
          ) : null}
          {notices.length > 0 ? (
            <Callout tone="warning" icon={TriangleAlert} title={t('updates.beforeYouUpdate')}>
              <ul className="flex list-disc flex-col gap-1 pl-4">
                {notices.map((change) => (
                  <li key={change.en}>{noteText(change, i18n.language)}</li>
                ))}
              </ul>
            </Callout>
          ) : null}
          {releases.length === 0 ? (
            <p className="text-[13px] text-muted">{t('updates.noNotes')}</p>
          ) : (
            releases.map((release) => (
              <ReleaseSection
                key={release.version}
                release={release}
                // Before an update, the notices are already at the top.
                changes={release.changes.filter((change) => !offer || change.kind !== 'notice')}
              />
            ))
          )}
          {offer ? (
            <p className="flex gap-2 text-[12px] leading-[18px] text-muted">
              <ShieldCheck
                aria-hidden="true"
                className="mt-px size-[15px] shrink-0 text-success"
                strokeWidth={2}
              />
              {t('updates.backupHint')}
            </p>
          ) : null}
        </DialogBody>
        <DialogFooter>
          <Button
            variant="ghost"
            className="mr-auto"
            icon={<ExternalLink className="size-[15px]" strokeWidth={1.75} />}
            onClick={() => void openReleases()}
          >
            {t('updates.allVersions')}
          </Button>
          {offer ? (
            <>
              <DialogClose asChild>
                <Button variant="ghost">{t('updates.later')}</Button>
              </DialogClose>
              <Button
                variant="primary"
                loading={update.status === 'downloading'}
                disabled={update.status !== 'available' && update.status !== 'downloading'}
                onClick={() => {
                  close();
                  void installUpdate();
                }}
              >
                {t('updates.install')}
              </Button>
            </>
          ) : (
            <DialogClose asChild>
              <Button>{t('common.close')}</Button>
            </DialogClose>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ReleaseSection({ release, changes }: { release: Release; changes: Change[] }) {
  const { t, i18n } = useTranslation();
  if (changes.length === 0) return null;
  const order = KINDS.map(([kind]) => kind);
  const sorted = [...changes].sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind));
  return (
    <section aria-labelledby={`release-${release.version}`} className="flex flex-col gap-2.5">
      <h3 id={`release-${release.version}`} className="flex items-baseline gap-2">
        <span className="font-mono text-[13.5px] font-semibold text-fg">{release.version}</span>
        <span className="text-[12px] text-subtle">{releaseDate(release.date, i18n.language)}</span>
      </h3>
      <ul className="flex flex-col gap-2">
        {sorted.map((change) => (
          <li key={change.en} className="flex items-start gap-2.5 text-[13px] leading-[19px]">
            <Badge
              tone={KINDS.find(([kind]) => kind === change.kind)?.[1]}
              className="mt-[-1px] min-w-[6.5rem] justify-center"
            >
              {t(`updates.kind.${change.kind}`)}
            </Badge>
            <span className="min-w-0 text-fg-2">{noteText(change, i18n.language)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** `YYYY-MM-DD` as a date in the app's language, the same day everywhere. */
function releaseDate(date: string, language: string): string {
  const parsed = new Date(`${date}T00:00:00Z`);
  if (Number.isNaN(parsed.getTime())) return date;
  return new Intl.DateTimeFormat(language, { dateStyle: 'medium', timeZone: 'UTC' }).format(parsed);
}

/** The releases page has every version's installers, to go back to one. */
async function openReleases(): Promise<void> {
  if (isTauri()) await openUrl(RELEASES_URL);
  else window.open(RELEASES_URL, '_blank', 'noopener,noreferrer');
}
