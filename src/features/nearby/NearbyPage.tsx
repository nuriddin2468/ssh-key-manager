import {
  Download,
  Eye,
  EyeOff,
  Laptop,
  Lock,
  MoreHorizontal,
  Pencil,
  Plug,
  Radar,
  Trash2,
  UserPlus,
} from 'lucide-react';
import { type FormEvent, useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { Contact } from '@/bindings/Contact';
import { PageBody, Toolbar } from '@/components/layout/Toolbar';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuTrigger } from '@/components/ui/Menu';
import { Spinner } from '@/components/ui/Spinner';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { formatDate } from '@/lib/format';
import { MyDevices } from './MyDevices';
import { clock, isActive, isAddress, secondsLeft } from './model';
import { setStatus, useContacts, useNearby } from './queries';

/**
 * Other copies of the app on the local network: this device's name and
 * visibility, the devices found, the user's own devices and the contacts
 * pairing made. A computer without a vault waits here to be given one.
 */
export function NearbyPage() {
  const { t, i18n } = useTranslation();
  const { navigate } = useRouter();
  const dialogs = useDialogs();
  const status = useNearby();
  const contacts = useContacts();
  const vault = useVaultStatus().data?.state;
  const unlocked = vault === 'unlocked';
  const [renaming, setRenaming] = useState(false);
  const [byAddress, setByAddress] = useState(false);
  const [toRemove, setToRemove] = useState<Contact | null>(null);
  const left = useCountdown(status.data?.visibleUntil ?? null);

  // Look for others while the page is open.
  useEffect(() => {
    api
      .nearbySetLooking(true)
      .then(setStatus)
      .catch(() => undefined);
    return () => {
      api
        .nearbySetLooking(false)
        .then(setStatus)
        .catch(() => undefined);
    };
  }, []);

  const visibility = useAppMutation((on: boolean) => api.nearbySetVisible(on), {
    onSuccess: setStatus,
  });
  const join = useAppMutation((on: boolean) => api.nearbyJoin(on), { onSuccess: setStatus });
  const pair = useAppMutation((target: string) => api.nearbyPair(target));
  const addDevice = useAppMutation((target: string) => api.nearbyAddDevice(target));
  const remove = useAppMutation((contact: Contact) => api.nearbyRemoveContact(contact.key), {
    success: (_, contact) => t('nearby.contacts.removed', { name: contact.name }),
    onSuccess: () => setToRemove(null),
  });

  const data = status.data;
  const visible = left !== null && left > 0;
  const joining = visible && (data?.joining ?? false);
  const busy = isActive(data?.pairing) || pair.isPending || addDevice.isPending;
  const devices = data?.devices ?? [];

  return (
    <>
      <Toolbar title={t('nearby.title')} meta={t('nearby.meta')} />

      <PageBody className="gap-[18px]">
        {vault !== undefined && !unlocked ? (
          <section className="flex flex-wrap items-center gap-3 rounded-2xl border border-warning-solid/30 bg-warning-solid/[0.08] px-4 py-3.5">
            <Lock aria-hidden="true" className="size-4 shrink-0 text-warning" strokeWidth={2} />
            <p className="min-w-[240px] flex-1 text-[13px] leading-5 text-fg-2">
              {vault === 'missing' ? t('nearby.vaultMissing') : t('nearby.vaultLocked')}
            </p>
            {vault === 'missing' && !joining ? (
              <Button
                size="sm"
                variant="primary"
                loading={join.isPending}
                icon={<Download aria-hidden="true" className="size-3.5" strokeWidth={2} />}
                onClick={() => join.mutate(true)}
              >
                {t('nearby.getVault')}
              </Button>
            ) : null}
            {vault === 'locked' ? (
              <Button
                size="sm"
                onClick={() => dialogs.unlockVault({ description: t('nearby.vaultLocked') })}
              >
                {t('passwords.unlock')}
              </Button>
            ) : (
              <Button size="sm" onClick={() => navigate({ page: 'passwords' })}>
                {t('nearby.openPasswords')}
              </Button>
            )}
          </section>
        ) : null}

        <section
          aria-labelledby="nearby-device"
          className="relative flex shrink-0 flex-wrap items-center gap-[18px] overflow-hidden rounded-[20px] border border-orange-400/20 bg-[linear-gradient(135deg,rgb(234_88_12/0.18),rgb(255_255_255/0.03)_60%)] px-6 py-5 shadow-[inset_0_1px_0_rgb(255_255_255/0.06)]"
        >
          <Tile tone="orange" size={56} glow>
            <Laptop className="size-[26px]" strokeWidth={1.8} />
          </Tile>
          <div className="flex min-w-[240px] flex-1 flex-col gap-1">
            <span className="text-[12.5px] font-medium text-[var(--accent-text)]">
              {t('nearby.thisDevice')}
            </span>
            {renaming && data ? (
              <RenameForm initial={data.name} onDone={() => setRenaming(false)} />
            ) : (
              <div className="flex min-w-0 items-center gap-1.5">
                <h2
                  id="nearby-device"
                  className="truncate text-[22px] leading-7 font-semibold tracking-[-0.02em]"
                >
                  {data?.name ?? ''}
                </h2>
                <IconButton
                  label={t('nearby.rename')}
                  icon={<Pencil className="size-[14px]" strokeWidth={2} />}
                  onClick={() => setRenaming(true)}
                />
              </div>
            )}
            <p className="text-[12.5px] leading-[18px] text-muted">
              {joining ? (
                t('nearby.join.waiting', { time: clock(left) })
              ) : visible ? (
                <>
                  {t('nearby.visibleFor', { time: clock(left) })}
                  {data?.address ? (
                    <>
                      {' · '}
                      <span className="selectable font-mono text-fg-2">{data.address}</span>
                    </>
                  ) : null}
                </>
              ) : (
                t('nearby.hidden')
              )}
            </p>
          </div>
          {joining ? (
            <Button size="lg" loading={join.isPending} onClick={() => join.mutate(false)}>
              {t('nearby.join.stop')}
            </Button>
          ) : (
            <Button
              size="lg"
              variant={visible ? 'secondary' : 'primary'}
              disabled={!unlocked && !visible}
              loading={visibility.isPending}
              icon={
                visible ? (
                  <EyeOff aria-hidden="true" className="size-4" strokeWidth={2} />
                ) : (
                  <Eye aria-hidden="true" className="size-4" strokeWidth={2} />
                )
              }
              onClick={() => visibility.mutate(!visible)}
            >
              {visible ? t('nearby.hide') : t('nearby.show')}
            </Button>
          )}
          {joining ? (
            <p className="w-full rounded-xl border border-orange-400/20 bg-black/10 px-3.5 py-2.5 text-[13px] leading-5 text-fg-2">
              {t('nearby.join.steps', { name: data?.name ?? '' })}
            </p>
          ) : null}
        </section>

        {unlocked ? <MyDevices status={data} /> : null}

        <section aria-labelledby="nearby-found" className="flex flex-col gap-2.5">
          <div className="flex flex-wrap items-baseline gap-2">
            <h2 id="nearby-found" className="text-[14px] leading-5 font-semibold">
              {t('nearby.found')}
            </h2>
            <span className="text-[12.5px] text-subtle">{t('nearby.foundHint')}</span>
          </div>
          {devices.length > 0 ? (
            <ul className="glass flex flex-col overflow-hidden rounded-2xl">
              {devices.map((device) => (
                <li
                  key={device.id}
                  className="flex items-center gap-3 border-b border-white/[0.06] px-4 py-3 last:border-b-0"
                >
                  <Tile tone="slate" size={34}>
                    <Laptop className="size-4" strokeWidth={2} />
                  </Tile>
                  <span className="min-w-0 flex-1 truncate font-medium">{device.name}</span>
                  {device.joining ? (
                    <Button
                      size="sm"
                      variant="soft"
                      disabled={!unlocked || busy}
                      icon={<UserPlus aria-hidden="true" className="size-3.5" strokeWidth={2} />}
                      aria-label={t('nearby.devices.addWith', { name: device.name })}
                      onClick={() => addDevice.mutate(device.id)}
                    >
                      {t('nearby.devices.add')}
                    </Button>
                  ) : (
                    <>
                      <Button
                        size="sm"
                        variant="soft"
                        disabled={!unlocked || busy}
                        icon={<Plug aria-hidden="true" className="size-3.5" strokeWidth={2} />}
                        aria-label={t('nearby.pairWith', { name: device.name })}
                        onClick={() => pair.mutate(device.id)}
                      >
                        {t('nearby.pair')}
                      </Button>
                      <Menu>
                        <MenuTrigger asChild>
                          <IconButton
                            label={t('nearby.devices.more', { name: device.name })}
                            icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
                            disabled={!unlocked || busy}
                          />
                        </MenuTrigger>
                        <MenuContent align="end">
                          <MenuItem
                            icon={<UserPlus className="size-4" strokeWidth={2} />}
                            onSelect={() => addDevice.mutate(device.id)}
                          >
                            {t('nearby.devices.add')}
                          </MenuItem>
                        </MenuContent>
                      </Menu>
                    </>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <div className="flex flex-col items-center gap-1.5 rounded-2xl border border-dashed border-white/[0.14] px-4 py-6 text-center">
              <span className="flex items-center gap-2 text-[13px] font-medium text-fg-2">
                <Radar
                  aria-hidden="true"
                  className="size-4 text-[var(--accent-text)]"
                  strokeWidth={2}
                />
                {t('nearby.looking')}
              </span>
              <span className="max-w-[440px] text-[12.5px] leading-[18px] text-subtle">
                {t('nearby.lookingHint')}
              </span>
            </div>
          )}
          <Button
            variant="ghost"
            size="sm"
            className="self-start text-[var(--accent-text)]"
            disabled={!unlocked || busy}
            onClick={() => setByAddress(true)}
          >
            {t('nearby.byAddress')}
          </Button>
        </section>

        {unlocked ? (
          <section aria-labelledby="nearby-contacts" className="flex flex-col gap-2.5">
            <div className="flex flex-wrap items-baseline gap-2">
              <h2 id="nearby-contacts" className="text-[14px] leading-5 font-semibold">
                {t('nearby.contacts.title')}
              </h2>
              <span className="text-[12.5px] text-subtle">{t('nearby.contacts.hint')}</span>
            </div>
            {contacts.isPending ? (
              <div className="grid place-items-center py-4 text-subtle">
                <Spinner className="size-5" />
              </div>
            ) : (contacts.data ?? []).length > 0 ? (
              <ul className="glass flex flex-col overflow-hidden rounded-2xl">
                {(contacts.data ?? []).map((contact) => (
                  <li
                    key={contact.key}
                    className="flex items-center gap-3 border-b border-white/[0.06] px-4 py-3 last:border-b-0"
                  >
                    <Tile tone="orange" size={34}>
                      <Laptop className="size-4" strokeWidth={2} />
                    </Tile>
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate font-medium">{contact.name}</span>
                      <span className="text-[12px] text-subtle">
                        {t('nearby.contacts.paired', {
                          date: formatDate(contact.paired, i18n.language),
                        })}
                      </span>
                    </span>
                    <IconButton
                      label={t('nearby.contacts.remove', { name: contact.name })}
                      icon={<Trash2 className="size-[15px]" strokeWidth={1.9} />}
                      onClick={() => setToRemove(contact)}
                    />
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-[12.5px] text-subtle">{t('nearby.contacts.empty')}</p>
            )}
          </section>
        ) : null}

        <p className="mt-auto text-[12.5px] leading-[19px] text-subtle">{t('nearby.note')}</p>
      </PageBody>

      <Dialog open={byAddress} onOpenChange={setByAddress}>
        {byAddress ? (
          <AddressDialog
            onConnect={(address) => {
              setByAddress(false);
              pair.mutate(address);
            }}
          />
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={toRemove !== null}
        onOpenChange={(open) => open || setToRemove(null)}
        title={t('nearby.contacts.removeTitle', { name: toRemove?.name ?? '' })}
        description={t('nearby.contacts.removeText')}
        confirmLabel={t('nearby.contacts.removeConfirm')}
        destructive
        busy={remove.isPending}
        onConfirm={() => toRemove && remove.mutate(toRemove)}
      />
    </>
  );
}

/** Seconds left until `until`, ticking every second; `null` without one. */
function useCountdown(until: string | null): number | null {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!until) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [until]);
  return secondsLeft(until, now);
}

function RenameForm({ initial, onDone }: { initial: string; onDone: () => void }) {
  const { t } = useTranslation();
  const [name, setName] = useState(initial);
  const rename = useAppMutation((value: string) => api.nearbySetName(value), {
    onSuccess: (status) => {
      setStatus(status);
      onDone();
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (name.trim()) rename.mutate(name);
  };
  return (
    <form onSubmit={submit} className="flex flex-wrap items-end gap-2">
      <TextField
        label={t('nearby.nameLabel')}
        value={name}
        maxLength={64}
        autoFocus
        onChange={(event) => setName(event.target.value)}
        onKeyDown={(event) => event.key === 'Escape' && onDone()}
        className="min-w-[220px] flex-1"
      />
      <Button onClick={onDone}>{t('common.cancel')}</Button>
      <Button type="submit" variant="primary" loading={rename.isPending} disabled={!name.trim()}>
        {t('common.save')}
      </Button>
    </form>
  );
}

function AddressDialog({ onConnect }: { onConnect: (address: string) => void }) {
  const { t } = useTranslation();
  const hintId = useId();
  const [address, setAddress] = useState('');
  const [tried, setTried] = useState(false);
  const valid = isAddress(address);
  const submit = (event: FormEvent) => {
    event.preventDefault();
    setTried(true);
    if (valid) onConnect(address.trim());
  };
  return (
    <DialogContent section="nearby" className="max-w-[440px]">
      <form onSubmit={submit} className="contents">
        <DialogHeader
          icon={
            <Tile tone="orange" size={44} glow>
              <Plug className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('nearby.address.title')}
          description={t('nearby.address.description')}
        />
        <DialogBody>
          <TextField
            label={t('nearby.address.label')}
            placeholder="192.168.1.24:48213"
            mono
            value={address}
            aria-describedby={hintId}
            error={tried && !valid ? t('nearby.address.invalid') : undefined}
            onChange={(event) => setAddress(event.target.value)}
          />
          <p id={hintId} className="text-[12.5px] leading-[18px] text-subtle">
            {t('nearby.address.hint')}
          </p>
        </DialogBody>
        <DialogFooter>
          <Button type="submit" variant="primary" size="lg">
            {t('nearby.pair')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
