import { Laptop, MessageSquare, RefreshCw, Trash2 } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { MyDevice } from '@/bindings/MyDevice';
import type { NearbyStatus } from '@/bindings/NearbyStatus';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { IconButton } from '@/components/ui/IconButton';
import { Spinner } from '@/components/ui/Spinner';
import { SwitchRow } from '@/components/ui/Switch';
import { Tile } from '@/components/ui/Tile';
import { formatRelative } from '@/lib/format';
import { isActive } from './model';
import { setStatus, useMyDevices } from './queries';

/**
 * The user's own computers: they share the vault and sync hosts. Each can
 * be synced with while it is on this network, and removed.
 */
export function MyDevices({ status }: { status: NearbyStatus | undefined }) {
  const { t, i18n } = useTranslation();
  const devices = useMyDevices();
  const [toRemove, setToRemove] = useState<MyDevice | null>(null);
  const [deleteChat, setDeleteChat] = useState(true);
  const { navigate } = useRouter();

  const sync = useAppMutation((key: string | null) => api.nearbySync(key));
  const reachable = useAppMutation((on: boolean) => api.nearbySetReachable(on), {
    onSuccess: setStatus,
  });
  const remove = useAppMutation(
    (device: MyDevice) => api.nearbyRemoveDevice(device.key, deleteChat),
    {
      success: (_, device) => t('nearby.devices.removed', { name: device.name }),
      onSuccess: () => setToRemove(null),
    },
  );

  const list = devices.data ?? [];
  const others = list.filter((device) => !device.this);
  const found = new Set(status?.ownFound ?? []);
  const busy = isActive(status?.pairing) || sync.isPending;
  const anyFound = others.some((device) => found.has(device.key));

  return (
    <section aria-labelledby="nearby-mine" className="flex flex-col gap-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex min-w-0 flex-1 flex-wrap items-baseline gap-2">
          <h2 id="nearby-mine" className="text-[14px] leading-5 font-semibold">
            {t('nearby.devices.title')}
          </h2>
          <span className="text-[12.5px] text-subtle">{t('nearby.devices.hint')}</span>
        </div>
        {others.length > 0 ? (
          <Button
            size="sm"
            variant="soft"
            disabled={!anyFound || busy}
            loading={sync.isPending}
            icon={<RefreshCw aria-hidden="true" className="size-3.5" strokeWidth={2} />}
            onClick={() => sync.mutate(null)}
          >
            {t('nearby.devices.syncAll')}
          </Button>
        ) : null}
      </div>

      {devices.isPending ? (
        <div className="grid place-items-center py-4 text-subtle">
          <Spinner className="size-5" />
        </div>
      ) : others.length > 0 ? (
        <ul className="glass flex flex-col overflow-hidden rounded-2xl">
          {list.map((device) => {
            const here = found.has(device.key);
            return (
              <li
                key={device.key}
                className="flex items-center gap-3 border-b border-white/[0.06] px-4 py-3 last:border-b-0"
              >
                <Tile tone="orange" size={34}>
                  <Laptop className="size-4" strokeWidth={2} />
                </Tile>
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="truncate font-medium">{device.name}</span>
                  <span className="flex flex-wrap items-center gap-x-1.5 text-[12px] text-subtle">
                    {device.this ? (
                      t('nearby.devices.this')
                    ) : (
                      <>
                        <span className="flex items-center gap-1.5">
                          <span
                            aria-hidden="true"
                            className={`size-1.5 rounded-full ${here ? 'bg-ok' : 'bg-white/25'}`}
                          />
                          {here ? t('nearby.devices.here') : t('nearby.devices.away')}
                        </span>
                        <span aria-hidden="true">·</span>
                        <span>
                          {device.lastSync
                            ? t('nearby.devices.synced', {
                                time: formatRelative(new Date(device.lastSync), i18n.language),
                              })
                            : t('nearby.devices.never')}
                        </span>
                      </>
                    )}
                  </span>
                </span>
                {device.this ? null : (
                  <>
                    <Button
                      size="sm"
                      variant="soft"
                      disabled={!here || busy}
                      aria-label={t('nearby.devices.syncWith', { name: device.name })}
                      onClick={() => sync.mutate(device.key)}
                    >
                      {t('nearby.devices.sync')}
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      icon={
                        <MessageSquare aria-hidden="true" className="size-3.5" strokeWidth={2} />
                      }
                      aria-label={t('nearby.chat.messageTo', { name: device.name })}
                      onClick={() => navigate({ page: 'nearby', tab: 'chats', chat: device.key })}
                    >
                      {t('nearby.chat.message')}
                    </Button>
                    <IconButton
                      label={t('nearby.devices.remove', { name: device.name })}
                      icon={<Trash2 className="size-[15px]" strokeWidth={1.9} />}
                      onClick={() => setToRemove(device)}
                    />
                  </>
                )}
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="text-[12.5px] leading-[18px] text-subtle">{t('nearby.devices.empty')}</p>
      )}

      {others.length > 0 && !anyFound ? (
        <p className="text-[12.5px] leading-[18px] text-subtle">
          {t('nearby.devices.unreachable')}
        </p>
      ) : null}

      <div className="glass rounded-2xl px-1.5 py-1">
        <SwitchRow
          label={t('nearby.devices.reachable')}
          hint={t('nearby.devices.reachableHint')}
          checked={status?.reachable ?? true}
          disabled={reachable.isPending}
          onCheckedChange={(on) => reachable.mutate(on)}
        />
      </div>
      <p className="text-[12.5px] leading-[18px] text-subtle">{t('nearby.devices.what')}</p>

      <ConfirmDialog
        open={toRemove !== null}
        onOpenChange={(open) => open || setToRemove(null)}
        title={t('nearby.devices.removeTitle', { name: toRemove?.name ?? '' })}
        description={t('nearby.devices.removeText')}
        confirmLabel={t('nearby.devices.removeConfirm')}
        destructive
        busy={remove.isPending}
        onConfirm={() => toRemove && remove.mutate(toRemove)}
      >
        <Checkbox
          checked={deleteChat}
          onCheckedChange={setDeleteChat}
          label={t('nearby.chat.removeChat')}
        />
      </ConfirmDialog>
    </section>
  );
}
