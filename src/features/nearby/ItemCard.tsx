import { FolderTree, KeyRound, type LucideIcon, RectangleEllipsis, Server } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { ItemSummary } from '@/bindings/ItemSummary';
import { Badge } from '@/components/ui/Badge';
import { Tile, type Tone } from '@/components/ui/Tile';
import { keyTypeBadge } from '@/features/keys/model';
import { cn } from '@/lib/cn';

interface CardParts {
  /** The section the item goes to gives the tile its colour. */
  tone: Tone;
  Icon: LucideIcon;
  label: string;
  title: string;
  /** Aliases, key and file names are set in monospace. */
  monoTitle: boolean;
  details: string;
  /** Fingerprints wrap instead of being cut, so both sides can compare them. */
  wrapDetails?: boolean;
  badge: ReactNode;
}

/** What is being sent: a login, a host, a hosts file group or a public key, without secrets. */
export function ItemCard({ item }: { item: ItemSummary }) {
  const { t } = useTranslation();
  const parts = ((): CardParts => {
    switch (item.type) {
      case 'password':
        return {
          tone: 'pink',
          Icon: RectangleEllipsis,
          label: t('nearby.item.password'),
          title: item.title,
          monoTitle: false,
          details: [item.username, item.url].filter(Boolean).join(' · '),
          badge: item.otp ? <Badge tone="violet">{t('nearby.item.otp')}</Badge> : null,
        };
      case 'host':
        return {
          tone: 'blue',
          Icon: Server,
          label: t('nearby.item.host'),
          title: item.alias,
          monoTitle: true,
          details: item.address,
          badge:
            item.hostKeys > 0 ? (
              <Badge>{t('nearby.item.hostKeys', { count: item.hostKeys })}</Badge>
            ) : null,
        };
      case 'hostsGroup':
        return {
          tone: 'indigo',
          Icon: FolderTree,
          label: t('nearby.item.hostsGroup'),
          title: item.name,
          monoTitle: false,
          details: `${item.names.join(', ')}${item.entries > item.names.length ? ', …' : ''}`,
          badge: <Badge>{t('nearby.item.entries', { count: item.entries })}</Badge>,
        };
      case 'publicKey':
        return {
          tone: 'teal',
          Icon: KeyRound,
          label: item.comment
            ? `${t('nearby.item.publicKey')} · ${item.comment}`
            : t('nearby.item.publicKey'),
          title: item.name,
          monoTitle: true,
          details: item.fingerprint,
          wrapDetails: true,
          badge: item.keyType ? <Badge mono>{keyTypeBadge(item.keyType)}</Badge> : null,
        };
    }
  })();
  return (
    <div className="glass flex items-center gap-3 rounded-[14px] px-3.5 py-3">
      <Tile tone={parts.tone} size={34}>
        <parts.Icon className="size-4" strokeWidth={2} />
      </Tile>
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span className="truncate text-[12px] text-subtle">{parts.label}</span>
        <span className={cn('truncate font-medium', parts.monoTitle && 'font-mono')}>
          {parts.title}
        </span>
        {parts.details ? (
          <span
            className={cn(
              'font-mono text-[11.5px] text-subtle',
              parts.wrapDetails ? 'selectable [overflow-wrap:anywhere]' : 'truncate',
            )}
          >
            {parts.details}
          </span>
        ) : null}
      </div>
      {parts.badge}
    </div>
  );
}
