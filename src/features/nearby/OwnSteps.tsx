// The steps of adding one of the user's devices, inside the pairing dialog.

import { AlertTriangle } from 'lucide-react';
import { type FormEvent, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { Button } from '@/components/ui/Button';
import { TextField } from '@/components/ui/TextField';
import { DeviceIcon, METHOD_NAME } from '@/features/passwords/device';
import { MasterPasswordFields, masterReady } from '@/features/passwords/MasterPasswordFields';
import { useSecretCall } from '@/features/passwords/vault';
import { AppError } from '@/lib/ipc';
import { percent } from './model';

/**
 * This user's yes to the other computer becoming one of their devices:
 * Touch ID or Windows Hello where there is one, else the master password.
 */
export function AuthorizeStep({ id, peer, vault }: { id: number; peer: string; vault: boolean }) {
  const { t } = useTranslation();
  const status = useVaultStatus().data;
  const kind = status?.device.kind ?? null;
  const [master, setMaster] = useState('');
  const [wrong, setWrong] = useState(false);
  const authorize = useSecretCall(api.nearbyAuthorize);

  const confirm = async (password: string | null) => {
    setWrong(false);
    try {
      await authorize.call(id, password);
    } catch (raw) {
      const error = AppError.from(raw);
      if (error.code === 'wrong_passphrase') setWrong(true);
      else if (error.code !== 'cancelled') toastError(t, error);
    }
  };
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (master) void confirm(master);
  };

  return (
    <div className="flex flex-col gap-3">
      <p className="text-[13px] leading-5 text-fg-2">
        {vault ? t('nearby.own.authorizeVault', { peer }) : t('nearby.own.authorize', { peer })}
      </p>
      {vault && status?.settings.database ? (
        <p className="flex gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5 text-[12.5px] leading-[18px] text-fg-2">
          <AlertTriangle
            aria-hidden="true"
            className="mt-0.5 size-4 shrink-0 text-warning"
            strokeWidth={2}
          />
          {t('nearby.own.location', { path: status.settings.database, peer })}
        </p>
      ) : null}
      {kind ? (
        <Button
          variant="primary"
          size="lg"
          className="w-full"
          icon={<DeviceIcon kind={kind} className="size-[18px]" />}
          loading={authorize.pending && !master}
          disabled={authorize.pending}
          onClick={() => void confirm(null)}
        >
          {t('nearby.own.confirmWith', { method: METHOD_NAME[kind] })}
        </Button>
      ) : null}
      <form onSubmit={submit} className="flex flex-col gap-2.5">
        <TextField
          label={kind ? t('nearby.own.orMaster') : t('passwords.masterPassword')}
          type="password"
          autoComplete="current-password"
          autoFocus={!kind}
          value={master}
          error={wrong ? t('nearby.own.wrongMaster') : undefined}
          onChange={(event) => {
            setMaster(event.target.value);
            setWrong(false);
          }}
        />
        <Button
          type="submit"
          variant={kind ? 'secondary' : 'primary'}
          size="lg"
          className="w-full"
          loading={authorize.pending && Boolean(master)}
          disabled={!master || authorize.pending}
        >
          {t('nearby.own.confirm')}
        </Button>
      </form>
    </div>
  );
}

/** The vault on its way: how far along. */
export function TransferStep({ done, total }: { done: number; total: number }) {
  const { t } = useTranslation();
  const labelId = useId();
  const value = percent(done, total);
  return (
    <div className="flex flex-col gap-2 py-2">
      <span id={labelId} className="text-[13px] text-fg-2">
        {t('nearby.own.transfer', { percent: value })}
      </span>
      <div
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
        aria-labelledby={labelId}
        className="h-1.5 overflow-hidden rounded-full bg-ink/[0.08]"
      >
        <div
          className="h-full rounded-full bg-[var(--accent-2)] transition-[width] duration-200"
          style={{ width: `${value}%` }}
        />
      </div>
    </div>
  );
}

/** The vault came: a master password for this computer, then it opens. */
export function SetMasterStep({ id, peer }: { id: number; peer: string }) {
  const { t } = useTranslation();
  const [master, setMaster] = useState('');
  const [repeat, setRepeat] = useState('');
  const finish = useSecretCall(api.nearbyFinishJoin);
  const ready = masterReady(master, repeat);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!ready || finish.pending) return;
    try {
      await finish.call(id, master);
      setMaster('');
      setRepeat('');
    } catch (error) {
      toastError(t, error);
    }
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-3">
      <p className="text-[13px] leading-5 text-fg-2">{t('nearby.own.setMaster', { peer })}</p>
      <MasterPasswordFields
        value={master}
        repeat={repeat}
        onChange={setMaster}
        onRepeatChange={setRepeat}
        autoFocus
      />
      <Button
        type="submit"
        variant="primary"
        size="lg"
        className="w-full"
        loading={finish.pending}
        disabled={!ready}
      >
        {t('nearby.own.finish')}
      </Button>
    </form>
  );
}
