import type { TFunction } from 'i18next';
import { useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { queryClient, useEnvironment } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { LeakFinding } from '@/bindings/LeakFinding';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { displayPath, formatDate } from '@/lib/format';
import { FindingRow } from './FindingRow';
import {
  baseName,
  type LeakGroup,
  placeNames,
  repositories,
  secretLabel,
  shortPath,
} from './leakModel';

/** Files listed before "Show all". */
const FILES_SHOWN = 3;

/** What the finding says: where the secret is, and to rotate it. */
export function leakText(t: TFunction, group: LeakGroup, language: string): string {
  const list = (items: string[]) =>
    new Intl.ListFormat(language, { type: 'conjunction' }).format(items);
  const count = group.findings.length;
  switch (group.kind) {
    case 'leakAi':
      return t('audit.leaks.kinds.leakAi.text', { count, tools: list(placeNames(group)) });
    case 'leakRepository':
      return t('audit.leaks.kinds.leakRepository.text', {
        count,
        repositories: list(repositories(group).map((repo) => baseName(repo))),
      });
    case 'leakLocalFile':
      return t('audit.leaks.kinds.leakLocalFile.text', { count });
    case 'leakHistory':
      return t('audit.leaks.kinds.leakHistory.text', { shells: list(placeNames(group)) });
  }
}

interface LeakRowProps {
  group: LeakGroup;
  muted: boolean;
  onIgnore?: () => void;
  onRestore?: () => void;
}

/**
 * One secret found in one kind of place: what to do (rotate it, where it
 * is kept), and each file it is in, with Show and, for AI sessions, Redact.
 */
export function LeakRow({ group, muted, onIgnore, onRestore }: LeakRowProps) {
  const { t, i18n } = useTranslation();
  const { navigate } = useRouter();
  const home = useEnvironment().data?.paths.home;
  const [allShown, setAllShown] = useState(false);
  const [redacting, setRedacting] = useState<LeakFinding[] | null>(null);
  const list = useRef<HTMLUListElement>(null);
  const secret = group.secret;
  const label = secretLabel(secret);
  const redactable = group.findings.filter((finding) => finding.redactable);

  const redact = useAppMutation((ids: string[]) => api.leaksRedact(ids), {
    success: (done) =>
      [
        done.files > 0 || (done.left === 0 && done.stale === 0)
          ? done.left > 0
            ? t('audit.leaks.redactedLeft', { count: done.files, left: done.left })
            : t('audit.leaks.redacted', { count: done.files })
          : null,
        done.stale > 0 ? t('audit.leaks.redactStale', { count: done.stale }) : null,
      ]
        .filter(Boolean)
        .join(' '),
    onSuccess: () => {
      setRedacting(null);
      void queryClient.invalidateQueries({ queryKey: ['leaks'] });
      // The Redact button that opened the dialog is gone with its file:
      // focus goes to the list, or the section if the row went too. After
      // the dialog's own focus return.
      setTimeout(() => {
        const target = list.current?.isConnected
          ? list.current
          : document.getElementById('audit-findings-h');
        target?.focus();
      }, 60);
    },
  });

  const reveal = (id: string) => {
    api.revealPlace({ kind: 'leak', id }).catch((error: unknown) => toastError(t, error));
  };

  const shown = allShown ? group.findings : group.findings.slice(0, FILES_SHOWN);
  const hiddenCount = group.findings.length - FILES_SHOWN;

  const details = (finding: LeakFinding) => {
    const parts: string[] = [];
    if (finding.occurrences > 1) {
      parts.push(t('audit.leaks.times', { count: finding.occurrences }));
    }
    for (const encoding of finding.encodings) parts.push(t(`audit.leaks.encodings.${encoding}`));
    if (finding.place.kind === 'file' && finding.place.git !== 'outside') {
      parts.push(t(`audit.leaks.git.${finding.place.git}`));
    }
    if (finding.place.kind === 'aiSession' && finding.modified) {
      parts.push(formatDate(finding.modified, i18n.language));
    }
    return parts.join(' · ');
  };

  const target = redacting?.[0];

  return (
    <>
      <FindingRow
        severity={group.severity}
        title={t(`audit.leaks.kinds.${group.kind}.title`)}
        text={leakText(t, group, i18n.language)}
        subject={label}
        actionLabel={
          secret.kind === 'variable' ? t('audit.leaks.openVariable') : t('audit.leaks.openEntry')
        }
        onAction={() =>
          navigate(
            secret.kind === 'variable'
              ? { page: 'envs', envId: secret.envId }
              : { page: 'passwords', entryId: secret.entryId },
          )
        }
        muted={muted}
        onIgnore={onIgnore}
        onRestore={onRestore}
        extraActions={
          redactable.length > 1 && !muted ? (
            <Button variant="ghost" size="sm" onClick={() => setRedacting(redactable)}>
              {t('audit.leaks.redactAll')}
            </Button>
          ) : null
        }
      >
        <ul
          ref={list}
          tabIndex={-1}
          aria-label={t('audit.leaks.filesLabel', { secret: label })}
          className="flex flex-col gap-0.5 rounded-md border-t border-line-soft pt-2 outline-none focus-visible:ring-2 focus-visible:ring-[rgb(var(--focus-rgb)/var(--ring-alpha-soft))]"
        >
          {shown.map((finding) => {
            const file = shortPath(finding.path);
            const extra = details(finding);
            return (
              <li
                key={finding.id}
                className="flex min-h-[30px] flex-wrap items-center gap-x-2.5 gap-y-0.5 text-[12px]"
              >
                <span className="flex min-w-0 flex-1 basis-[240px] flex-col">
                  <span className="truncate font-mono text-[11.5px] text-fg-2" title={finding.path}>
                    {displayPath(finding.path, home)}
                    <span className="text-subtle">
                      {t('audit.leaks.line', { line: finding.line })}
                    </span>
                  </span>
                  {extra ? <span className="text-subtle">{extra}</span> : null}
                </span>
                <span className="flex shrink-0 gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-[26px] px-2"
                    aria-label={t('audit.leaks.showLabel', { file })}
                    onClick={() => reveal(finding.id)}
                  >
                    {t('audit.leaks.show')}
                  </Button>
                  {finding.redactable && !muted ? (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-[26px] px-2"
                      aria-label={t('audit.leaks.redactLabel', { file })}
                      onClick={() => setRedacting([finding])}
                    >
                      {t('audit.leaks.redact')}
                    </Button>
                  ) : null}
                </span>
              </li>
            );
          })}
        </ul>
        {hiddenCount > 0 ? (
          <Button
            variant="ghost"
            size="sm"
            className="-ml-2 h-[26px] px-2 text-subtle"
            aria-expanded={allShown}
            onClick={() => setAllShown(!allShown)}
          >
            {allShown
              ? t('audit.leaks.showFewer')
              : t('audit.leaks.showAll', { count: group.findings.length })}
          </Button>
        ) : null}
      </FindingRow>

      <ConfirmDialog
        open={redacting !== null}
        onOpenChange={(open) => {
          if (!open && !redact.isPending) setRedacting(null);
        }}
        title={
          (redacting?.length ?? 0) > 1
            ? t('audit.leaks.redactTitleMany', { secret: label, count: redacting?.length ?? 0 })
            : t('audit.leaks.redactTitle', { secret: label })
        }
        description={
          (redacting?.length ?? 0) > 1
            ? t('audit.leaks.redactTextMany', { count: redacting?.length ?? 0 })
            : t('audit.leaks.redactText', { file: target ? displayPath(target.path, home) : '' })
        }
        confirmLabel={t('audit.leaks.redactConfirm')}
        destructive
        busy={redact.isPending}
        onConfirm={() => {
          if (redacting) redact.mutate(redacting.map((finding) => finding.id));
        }}
      />
    </>
  );
}
