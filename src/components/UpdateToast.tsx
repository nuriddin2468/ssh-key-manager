import { Download } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { Release } from '@/bindings/Release';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Tile } from '@/components/ui/Tile';

interface UpdateToastProps {
  version: string;
  /** The notes of each version since this one; flags what to read first. */
  releases: Release[];
  onShowNotes: () => void;
  onLater: () => void;
}

/**
 * The offer to install a new version. It opens the release notes, where the
 * update is installed. The buttons sit under the text rather than beside it,
 * so longer translations keep a readable width.
 */
export function UpdateToast({ version, releases, onShowNotes, onLater }: UpdateToastProps) {
  const { t } = useTranslation();
  const changes = releases.flatMap((release) => release.changes);
  const security = changes.some((change) => change.kind === 'security');
  const notice = changes.some((change) => change.kind === 'notice');
  return (
    <div className="flex w-[var(--width)] flex-col gap-3 rounded-xl border border-line-strong p-4">
      <div className="flex gap-3">
        <Tile tone="teal" size={32}>
          <Download aria-hidden="true" className="size-4 text-on-solid" strokeWidth={2.25} />
        </Tile>
        <div className="flex min-w-0 flex-col gap-0.5">
          <span className="font-semibold">{t('updates.available', { version })}</span>
          <span className="text-[12.5px] text-muted">{t('updates.availableHint')}</span>
          {security || notice ? (
            <span className="mt-1.5 flex flex-wrap gap-1.5">
              {security ? <Badge tone="critical">{t('updates.securityBadge')}</Badge> : null}
              {notice ? <Badge tone="warning">{t('updates.noticeBadge')}</Badge> : null}
            </span>
          ) : null}
        </div>
      </div>
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onLater}>
          {t('updates.later')}
        </Button>
        <Button size="sm" variant="primary" onClick={onShowNotes}>
          {t('updates.whatsNew')}
        </Button>
      </div>
    </div>
  );
}
