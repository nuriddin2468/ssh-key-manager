import { KeyRound, LockKeyhole } from 'lucide-react';
import { type RefObject, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';
import { ChoiceCards, type ChoiceOption } from '@/components/ui/ChoiceCards';
import { SwitchRow } from '@/components/ui/Switch';
import { algorithmBadge } from '@/features/keys/model';
import { useVaultKey } from '@/features/keys/vaultKey';
import { KeyPicker, useKeyForFile } from './HostFields';
import { MethodCard, PasswordCard } from './HostPassword';
import { chooseKey, type HostForm, type SignInMethod } from './model';
import type { HostVault } from './vault';

/** A key with a small padlock: the "Key and password" card's icon. */
function KeyAndLock({ className, strokeWidth = 2 }: { className?: string; strokeWidth?: number }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      className={className}
    >
      <circle cx="7" cy="16" r="3" />
      <path d="M9.5 13.5 15 8M13 10l2 2" />
      <rect x="14" y="14" width="7" height="6" rx="1.5" />
      <path d="M15.5 14v-1a2 2 0 0 1 4 0v1" />
    </svg>
  );
}

const NOTE = {
  key: 'hosts.signIn.noteKey',
  password: 'hosts.signIn.notePassword',
  both: 'hosts.signIn.noteBoth',
} as const;

interface SignInSectionProps {
  form: HostForm & { method: SignInMethod };
  update: (change: (form: HostForm) => HostForm) => void;
  /** The method the host was saved with, for the switch from Password to a key. */
  savedMethod: SignInMethod;
  vault: HostVault;
  /** The alias the password is (or would be) saved for. */
  alias: string;
  /** Saving moves the saved password to the recycle bin (the Key method). */
  trashPending: boolean;
  /** The form has changes besides sign-in, which installing a key would lose. */
  otherDirty: boolean;
  onEditPassword: (focus: 'edit' | 'otp') => void;
  /** Opens the switch to a key: install it with the saved password, check it, keep or recycle the password. */
  onInstallKey: () => void;
  onCreateKey: () => void;
  ref: RefObject<HTMLFieldSetElement | null>;
}

/** "How you sign in": Key, Password, or both, with a card for each part. */
export function SignInSection({
  form,
  update,
  savedMethod,
  vault,
  alias,
  trashPending,
  otherDirty,
  onEditPassword,
  onInstallKey,
  onCreateKey,
  ref,
}: SignInSectionProps) {
  const { t } = useTranslation();
  const { method } = form;
  const [calloutDismissed, setCalloutDismissed] = useState(false);
  const entry = vault.vault === 'unlocked' ? vault.entry : undefined;
  const showKey = method !== 'password';
  const showPassword = method !== 'key';
  const callout = savedMethod === 'password' && method !== 'password' && !calloutDismissed;

  const options: ChoiceOption<SignInMethod>[] = [
    {
      value: 'key',
      tone: 'teal',
      icon: KeyRound,
      title: t('hosts.signIn.key'),
      hint: t('hosts.signIn.keyHint'),
    },
    {
      value: 'password',
      tone: 'indigo',
      icon: LockKeyhole,
      title: t('hosts.signIn.password'),
      hint: t('hosts.signIn.passwordHint'),
    },
    {
      value: 'both',
      tone: 'blue',
      icon: KeyAndLock,
      title: t('hosts.signIn.both'),
      hint: t('hosts.signIn.bothHint'),
    },
  ];

  return (
    <fieldset ref={ref} className="m-0 flex min-w-0 flex-col gap-2.5 border-0 p-0">
      <ChoiceCards
        legend={t('hosts.signIn.legend')}
        value={method}
        onValueChange={(next) => {
          if (next === 'password') setCalloutDismissed(false);
          update((f) => ({ ...f, method: next }));
        }}
        options={options}
      />

      {/* Mounted before the callout, so screen readers hear it appear. */}
      <div aria-live="polite" className="flex flex-col empty:hidden">
        {callout ? (
          <SwitchCallout
            keyName={form.identityFile}
            passwordSaved={Boolean(entry)}
            otherDirty={otherDirty}
            onInstall={onInstallKey}
            onSavePassword={vault.vault === 'unlocked' ? () => onEditPassword('edit') : undefined}
            onDismiss={() => {
              setCalloutDismissed(true);
              // The button that had focus goes with the callout.
              requestAnimationFrame(() =>
                ref.current
                  ?.querySelector<HTMLElement>('[role=radio][data-state=checked]')
                  ?.focus(),
              );
            }}
          />
        ) : null}
      </div>

      <div
        className="grid gap-2.5"
        style={{
          gridTemplateColumns:
            showKey && showPassword ? 'repeat(auto-fit, minmax(220px, 1fr))' : 'minmax(0, 1fr)',
        }}
      >
        {showKey ? (
          <KeyCard
            form={form}
            update={update}
            canInstall={Boolean(entry)}
            otherDirty={otherDirty}
            onInstall={onInstallKey}
            onCreate={onCreateKey}
          />
        ) : null}
        {showPassword ? (
          <PasswordCard vault={vault} user={form.user.trim()} onEdit={onEditPassword} />
        ) : null}
      </div>

      {/* What the chosen method does, read out when the choice changes. */}
      <div aria-live="polite" className="flex flex-col gap-1 text-[12px] leading-[18px]">
        <p className="text-muted">{t(NOTE[method])}</p>
        {trashPending ? (
          <p className="text-warning">{t('hosts.signIn.trashNote', { alias })}</p>
        ) : null}
      </div>
    </fieldset>
  );
}

interface KeyCardProps {
  form: HostForm;
  update: (change: (form: HostForm) => HostForm) => void;
  /** A password is saved, so the app can sign in with it and install the key. */
  canInstall: boolean;
  otherDirty: boolean;
  onInstall: () => void;
  onCreate: () => void;
}

/** The key ssh offers: any, or one of yours, and whether to offer only that one. */
function KeyCard({ form, update, canInstall, otherDirty, onInstall, onCreate }: KeyCardProps) {
  const { t } = useTranslation();
  const hintId = useId();
  const { key, missing } = useKeyForFile(form.identityFile);
  const vaultKey = useVaultKey(key?.fingerprint);
  const passphraseSaved =
    (vaultKey.vault === 'unlocked' && Boolean(vaultKey.entry)) ||
    (vaultKey.vault === 'locked' && vaultKey.saved);

  let status: string | null = null;
  if (!form.identityFile) status = t('hosts.signIn.anyKeyStatus');
  else if (missing) status = t('hosts.missingKey');
  else if (key) {
    const state = key.hardware
      ? t('hosts.signIn.securityKey')
      : key.inAgent
        ? t('hosts.signIn.inAgent')
        : passphraseSaved
          ? t('hosts.signIn.passphraseSaved')
          : key.encrypted
            ? t('hosts.signIn.passphraseAsks')
            : t('hosts.signIn.noPassphrase');
    status = `${algorithmBadge(key)} · ${state}`;
  }

  return (
    <MethodCard title={t('hosts.signIn.keyTitle')} data-card="key">
      <KeyPicker
        aria-label={t('hosts.signIn.keyLabel')}
        value={form.identityFile}
        onChange={(file) => update((f) => chooseKey(f, file))}
        onCreate={onCreate}
      />
      {status ? (
        <p className={missing ? 'text-[12px] text-warning' : 'text-[12px] text-muted'}>{status}</p>
      ) : null}
      {form.identityFile ? (
        <div className="-mx-2.5 -my-1">
          <SwitchRow
            label={t('hosts.identitiesOnly')}
            hint={t('hosts.identitiesOnlyHint')}
            checked={form.identitiesOnly}
            onCheckedChange={(value) => update((f) => ({ ...f, identitiesOnly: value }))}
          />
        </div>
      ) : null}
      {canInstall ? (
        <div className="flex flex-col items-start gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="-ml-3 text-[var(--accent-text)] aria-disabled:opacity-50"
            aria-disabled={otherDirty || undefined}
            aria-describedby={otherDirty ? hintId : undefined}
            onClick={() => otherDirty || onInstall()}
          >
            {t('hosts.signIn.installKey')}
          </Button>
          {otherDirty ? (
            <p id={hintId} className="text-[12px] text-warning">
              {t('hosts.signIn.otherDirty')}
            </p>
          ) : null}
        </div>
      ) : null}
    </MethodCard>
  );
}

interface SwitchCalloutProps {
  /** The key picked in the key card, as the config spells it; empty for any key. */
  keyName: string;
  passwordSaved: boolean;
  otherDirty: boolean;
  onInstall: () => void;
  /** Without a saved password: save one, so the app can install the key with it. */
  onSavePassword?: () => void;
  onDismiss: () => void;
}

/** Right after switching from Password to a key: the key has to reach the server first. */
function SwitchCallout({
  keyName,
  passwordSaved,
  otherDirty,
  onInstall,
  onSavePassword,
  onDismiss,
}: SwitchCalloutProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const hintId = useId();
  const name = keyName.split(/[\\/]/).pop() ?? keyName;
  return (
    <section
      aria-labelledby={titleId}
      className="flex flex-col gap-2.5 rounded-[14px] border border-warning/[0.28] bg-warning/[0.07] px-3.5 py-3"
    >
      <h3 id={titleId} className="font-semibold text-warning">
        {t('hosts.signIn.calloutTitle')}
      </h3>
      <p className="text-fg-2">
        {passwordSaved
          ? name
            ? t('hosts.signIn.calloutText', { key: name })
            : t('hosts.signIn.calloutTextAnyKey')
          : t('hosts.signIn.calloutNoPassword')}
      </p>
      {otherDirty && passwordSaved ? (
        <p id={hintId} className="text-[12px] text-warning">
          {t('hosts.signIn.otherDirty')}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        {passwordSaved ? (
          <Button
            size="sm"
            variant="primary"
            className="aria-disabled:opacity-50"
            aria-disabled={otherDirty || undefined}
            aria-describedby={otherDirty ? hintId : undefined}
            onClick={() => otherDirty || onInstall()}
          >
            {t('hosts.signIn.installKeyShort')}
          </Button>
        ) : onSavePassword ? (
          <Button size="sm" className="text-fg" onClick={onSavePassword}>
            {t('hosts.signIn.savePassword')}
          </Button>
        ) : null}
        <Button size="sm" onClick={onDismiss}>
          {t('hosts.signIn.keyThere')}
        </Button>
      </div>
    </section>
  );
}
