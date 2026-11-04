import { Laptop, Lock, Radar, Send } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import type { SendRequest } from '@/bindings/SendRequest';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogHeader } from '@/components/ui/Dialog';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { Tile } from '@/components/ui/Tile';
import { isActive } from './model';
import { setStatus, useNearby } from './queries';

/** What to send, as the page that opens the dialog knows it. */
export type Sendable =
  | { type: 'password'; entryId: string; hasOtp: boolean }
  | { type: 'host'; alias: string }
  | { type: 'hostsGroup'; name: string }
  | { type: 'publicKey'; keyId: string };

const DESCRIPTIONS = {
  password: 'nearby.send.passwordText',
  host: 'nearby.send.hostText',
  hostsGroup: 'nearby.send.groupText',
  publicKey: 'nearby.send.keyText',
} as const satisfies Record<Sendable['type'], string>;

interface SendDialogProps {
  what: Sendable;
  /** How it is named in the title: the entry's title, the host's alias, the group's or the key's name. */
  name: string;
  /** Sending started; the pairing dialog shows the rest. */
  onStarted: () => void;
}

/**
 * Picks a computer on this network to send a password, a host, a hosts file
 * group or a public key to. The backend reads what is sent; the app-wide
 * pairing dialog then shows the pairing code if the two aren't paired yet,
 * and how the sending went.
 */
export function SendDialog({ what, name, onStarted }: SendDialogProps) {
  const { t } = useTranslation();
  const status = useNearby();
  const unlocked = useVaultStatus().data?.state === 'unlocked';
  const [otp, setOtp] = useState(false);

  // Look for others while the dialog is open.
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

  const request: SendRequest =
    what.type === 'password'
      ? { type: 'password', entryId: what.entryId, otp: what.hasOtp && otp }
      : what;
  const send = useAppMutation((target: string) => api.nearbySend(target, request), {
    onSuccess: onStarted,
  });
  const devices = status.data?.devices ?? [];
  const busy = send.isPending || isActive(status.data?.pairing);

  return (
    <DialogContent section="nearby" className="max-w-[480px]">
      <DialogHeader
        icon={
          <Tile tone="orange" size={44} glow>
            <Send className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('nearby.send.title', { name })}
        description={t(DESCRIPTIONS[what.type])}
      />
      <DialogBody>
        {what.type === 'password' && what.hasOtp ? (
          <SwitchGroup>
            <SwitchRow
              label={t('nearby.send.otp')}
              hint={t('nearby.send.otpHint')}
              checked={otp}
              onCheckedChange={setOtp}
            />
          </SwitchGroup>
        ) : null}

        {!unlocked ? (
          <p className="flex gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.08] px-3 py-2.5 text-[12.5px] leading-[18px] text-fg-2">
            <Lock
              aria-hidden="true"
              className="mt-0.5 size-4 shrink-0 text-warning"
              strokeWidth={2}
            />
            {t('nearby.send.vaultLocked')}
          </p>
        ) : null}

        <section aria-labelledby="send-to" className="flex flex-col gap-2">
          <h3 id="send-to" className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
            {t('nearby.send.to')}
          </h3>
          {devices.length > 0 ? (
            <ul className="glass flex flex-col overflow-hidden rounded-[14px]">
              {devices.map((device) => (
                <li
                  key={device.id}
                  className="flex items-center gap-3 border-b border-white/[0.06] px-3.5 py-2.5 last:border-b-0"
                >
                  <Tile tone="slate" size={30}>
                    <Laptop className="size-[15px]" strokeWidth={2} />
                  </Tile>
                  <span className="min-w-0 flex-1 truncate font-medium">{device.name}</span>
                  <Button
                    size="sm"
                    variant="primary"
                    disabled={!unlocked || busy}
                    loading={send.isPending && send.variables === device.id}
                    aria-label={t('nearby.send.sendTo', { name: device.name })}
                    onClick={() => send.mutate(device.id)}
                  >
                    {t('nearby.send.send')}
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <div className="flex flex-col items-center gap-1.5 rounded-[14px] border border-dashed border-white/[0.14] px-4 py-5 text-center">
              <span className="flex items-center gap-2 text-[13px] font-medium text-fg-2">
                <Radar
                  aria-hidden="true"
                  className="size-4 text-[var(--accent-text)]"
                  strokeWidth={2}
                />
                {t('nearby.looking')}
              </span>
              <span className="max-w-[380px] text-[12.5px] leading-[18px] text-subtle">
                {t('nearby.send.lookingHint')}
              </span>
            </div>
          )}
          <p className="text-[12px] leading-[18px] text-subtle">{t('nearby.send.pairNote')}</p>
        </section>
      </DialogBody>
    </DialogContent>
  );
}
