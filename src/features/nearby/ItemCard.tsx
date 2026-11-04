import { RectangleEllipsis, Server } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import type { ItemSummary } from '@/bindings/ItemSummary';
import { Badge } from '@/components/ui/Badge';
import { Tile } from '@/components/ui/Tile';

/** What is being sent: a login or a host, without its secrets. */
export function ItemCard({ item }: { item: ItemSummary }) {
  const { t } = useTranslation();
  const password = item.type === 'password';
  const details = password ? [item.username, item.url].filter(Boolean).join(' · ') : item.address;
  return (
    <div className="glass flex items-center gap-3 rounded-[14px] px-3.5 py-3">
      <Tile tone={password ? 'pink' : 'blue'} size={34}>
        {password ? (
          <RectangleEllipsis className="size-4" strokeWidth={2} />
        ) : (
          <Server className="size-4" strokeWidth={2} />
        )}
      </Tile>
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <span className="text-[12px] text-subtle">
          {password ? t('nearby.item.password') : t('nearby.item.host')}
        </span>
        <span className={password ? 'truncate font-medium' : 'truncate font-mono font-medium'}>
          {password ? item.title : item.alias}
        </span>
        {details ? (
          <span className="truncate font-mono text-[11.5px] text-subtle">{details}</span>
        ) : null}
      </div>
      {password && item.otp ? <Badge tone="violet">{t('nearby.item.otp')}</Badge> : null}
      {!password && item.hostKeys > 0 ? (
        <Badge>{t('nearby.item.hostKeys', { count: item.hostKeys })}</Badge>
      ) : null}
    </div>
  );
}
