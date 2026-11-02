import { Download } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';
import { Tile } from '@/components/ui/Tile';

interface UpdateToastProps {
  version: string;
  onInstall: () => void;
  onLater: () => void;
}

/**
 * The offer to install a new version. The buttons sit under the text rather
 * than beside it, so longer translations keep a readable width.
 */
export function UpdateToast({ version, onInstall, onLater }: UpdateToastProps) {
  const { t } = useTranslation();
  return (
    <div className="flex w-[var(--width)] flex-col gap-3 rounded-xl border border-white/10 p-4">
      <div className="flex gap-3">
        <Tile tone="teal" size={32}>
          <Download aria-hidden="true" className="size-4 text-white" strokeWidth={2.25} />
        </Tile>
        <div className="flex min-w-0 flex-col gap-0.5">
          <span className="font-semibold">{t('updates.available', { version })}</span>
          <span className="text-[12.5px] text-muted">{t('updates.availableHint')}</span>
        </div>
      </div>
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onLater}>
          {t('updates.later')}
        </Button>
        <Button size="sm" variant="primary" onClick={onInstall}>
          {t('updates.install')}
        </Button>
      </div>
    </div>
  );
}
