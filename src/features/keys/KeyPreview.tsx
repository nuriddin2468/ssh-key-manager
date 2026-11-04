import { KeyRound } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useEnvironment } from '@/api/queries';
import { useRouter } from '@/app/router';
import type { KeyView } from '@/bindings/KeyView';
import { Button } from '@/components/ui/Button';
import { PopoverClose, PreviewPopover } from '@/components/ui/Popover';
import { Tile } from '@/components/ui/Tile';
import { displayPath, shortFingerprint } from '@/lib/format';
import { algorithmDescription, hasPrivate, keyTone, passphraseLabel } from './model';

/**
 * What a chip naming a key opens: its type, how it is protected and whether
 * ssh-agent holds it, with a way to the key itself. Render it inside a
 * `Popover` whose trigger is the chip.
 */
export function KeyPreview({ keyView: key }: { keyView: KeyView }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const home = useEnvironment().data?.paths.home;
  const pass = passphraseLabel(key);
  const path = key.privatePath ?? key.publicPath;

  return (
    <PreviewPopover
      icon={
        <Tile tone={keyTone(key)} size={34}>
          <KeyRound className="size-4" strokeWidth={1.9} />
        </Tile>
      }
      title={key.name}
      subtitle={key.comment || undefined}
      facts={[
        {
          label: t('keys.algorithm'),
          value: algorithmDescription(key, (bits) => t('keys.bits', { bits })),
        },
        {
          label: t('keys.fingerprint'),
          value: key.fingerprint ? (
            <span className="font-mono text-[11.5px]">{shortFingerprint(key.fingerprint)}</span>
          ) : null,
        },
        { label: t('keys.passphrase'), value: pass ? t(pass) : null },
        {
          label: t('keys.peek.agent'),
          value: hasPrivate(key)
            ? t(key.inAgent ? 'keys.statusUnlocked' : 'keys.statusLocked')
            : null,
        },
        {
          label: t('keys.location'),
          value: path ? (
            <span className="font-mono text-[11.5px]">{displayPath(path, home)}</span>
          ) : null,
        },
      ]}
      action={
        <PopoverClose asChild>
          <Button size="sm" onClick={() => navigate({ page: 'keys', keyId: key.id })}>
            {t('keys.peek.open')}
          </Button>
        </PopoverClose>
      }
    />
  );
}
