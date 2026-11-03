import { Check } from 'lucide-react';
import { type ReactNode, useId } from 'react';
import { useTranslation } from 'react-i18next';
import { useRouter } from '@/app/router';
import { Button } from '@/components/ui/Button';
import { Spinner } from '@/components/ui/Spinner';
import type { HostVault } from './vault';

/** A card of the sign-in answer (the key, the password): a title over its controls. */
export function MethodCard({
  title,
  children,
  ...rest
}: {
  title: string;
  children: ReactNode;
  'data-card'?: string;
}) {
  const id = useId();
  return (
    // biome-ignore lint/a11y/useSemanticElements: a fieldset's legend would sit in the card's border
    <div
      role="group"
      aria-labelledby={id}
      className="flex min-w-0 flex-col gap-2.5 rounded-[14px] border border-white/[0.08] bg-white/[0.03] px-3.5 py-3"
      {...rest}
    >
      <div id={id} className="font-semibold">
        {title}
      </div>
      {children}
    </div>
  );
}

interface PasswordCardProps {
  vault: HostVault;
  /** The host's `User`, the user the password is for. */
  user: string;
  /** Opens the dialog that saves the password (or edits it, `otp`: at its 2FA field). */
  onEdit: (focus: 'edit' | 'otp') => void;
}

/** The host's password in the vault: saved, not saved, the vault locked, or no vault yet. */
export function PasswordCard({ vault, user, onEdit }: PasswordCardProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const openPasswords = () => navigate({ page: 'passwords' });

  let body: ReactNode;
  switch (vault.vault) {
    case 'unknown':
      body = (
        <div className="grid place-items-center py-2 text-subtle">
          <Spinner className="size-4" />
        </div>
      );
      break;
    case 'missing':
      body = (
        <State text={t('hosts.signIn.missing')} hint={t('hosts.signIn.missingHint')}>
          <Button size="sm" className="self-start text-fg" onClick={openPasswords}>
            {t('hosts.signIn.createVault')}
          </Button>
        </State>
      );
      break;
    case 'locked':
      body = (
        <State text={t('hosts.signIn.locked')} hint={t('hosts.signIn.lockedHint')}>
          {/* The vault's own accent, as on the Passwords page it leads to. */}
          <div data-section="passwords" className="self-start">
            <Button size="sm" variant="primary" onClick={openPasswords}>
              {t('hosts.signIn.unlock')}
            </Button>
          </div>
        </State>
      );
      break;
    case 'unlocked': {
      const { entry } = vault;
      if (!entry) {
        body = (
          <State
            text={user ? t('hosts.signIn.notSaved', { user }) : t('hosts.signIn.notSavedNoUser')}
            hint={t('hosts.signIn.notSavedHint')}
          >
            <Button size="sm" className="self-start text-fg" onClick={() => onEdit('edit')}>
              {t('hosts.signIn.savePassword')}
            </Button>
          </State>
        );
        break;
      }
      const otp = entry.hasOtp ? t('hosts.signIn.otpOn') : t('hosts.signIn.otpOff');
      body = (
        <>
          <div className="flex h-[34px] items-center gap-2 rounded-[10px] border border-ok/25 bg-ok/[0.08] px-2.5 text-teal-200">
            <Check aria-hidden="true" className="size-[15px] text-ok" strokeWidth={2.4} />
            {t('hosts.signIn.saved')}
          </div>
          <p className="text-[12px] text-muted">
            {user ? `${t('hosts.signIn.savedFor', { user })} · ${otp}` : otp}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button
              size="sm"
              aria-label={t('hosts.vault.editLabel')}
              onClick={() => onEdit('edit')}
            >
              {t('hosts.vault.edit')}
            </Button>
            {entry.hasOtp ? null : (
              <Button size="sm" variant="ghost" onClick={() => onEdit('otp')}>
                {t('hosts.signIn.addOtp')}
              </Button>
            )}
            <Button
              size="sm"
              variant="ghost"
              onClick={() => navigate({ page: 'passwords', entryId: entry.id })}
            >
              {t('hosts.vault.openInPasswords')}
            </Button>
          </div>
        </>
      );
      break;
    }
  }

  return (
    <MethodCard title={t('hosts.signIn.passwordTitle')} data-card="password">
      {body}
    </MethodCard>
  );
}

function State({ text, hint, children }: { text: string; hint: string; children: ReactNode }) {
  return (
    <>
      <p className="text-fg-2">{text}</p>
      <p className="text-[12px] text-muted">{hint}</p>
      {children}
    </>
  );
}
