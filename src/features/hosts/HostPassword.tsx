import { KeyRound, Lock, Plus } from 'lucide-react';
import { type ReactNode, type Ref, useId } from 'react';
import { useTranslation } from 'react-i18next';
import { useRouter } from '@/app/router';
import { Button } from '@/components/ui/Button';
import { VaultIcon } from '@/features/keys/VaultControls';
import { cn } from '@/lib/cn';
import type { HostVault } from './vault';

interface HostPasswordProps {
  vault: HostVault;
  /** The form has unsaved changes, which the switch to a key would lose. */
  dirty: boolean;
  /** Opens the dialog that saves or edits the password. */
  onEdit: () => void;
  onSwitch: () => void;
  ref?: Ref<HTMLElement>;
}

/** Whether the vault holds this host's password, and what can be done with it. */
export function HostPassword({ vault, dirty, onEdit, onSwitch, ref }: HostPasswordProps) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const titleId = useId();
  const switchHintId = useId();

  if (vault.vault === 'unknown') return null;
  if (vault.vault === 'missing') {
    return (
      <p className="flex items-start gap-2 text-[12px] leading-[18px] text-subtle">
        <VaultIcon className="mt-0.5 size-3.5 shrink-0" />
        <span>
          {t('hosts.vault.missing')}{' '}
          <button
            type="button"
            onClick={() => navigate({ page: 'passwords' })}
            className="rounded-sm text-[var(--accent-text)] underline-offset-2 hover:underline"
          >
            {t('hosts.vault.setUp')}
          </button>
        </span>
      </p>
    );
  }

  const entry = vault.vault === 'unlocked' ? vault.entry : undefined;
  return (
    <section ref={ref} aria-labelledby={titleId} className="flex flex-col gap-2">
      <h3 id={titleId} className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
        {t('hosts.vault.title')}
      </h3>
      <div className="glass flex flex-col gap-1 rounded-[14px] p-1.5">
        {vault.vault === 'locked' ? (
          <Row
            icon={<Lock aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />}
            label={t('hosts.vault.lockedLabel')}
            hint={t('hosts.vault.lockedHint')}
          >
            <Button size="sm" onClick={() => navigate({ page: 'passwords' })}>
              {t('hosts.vault.unlock')}
            </Button>
          </Row>
        ) : (
          <>
            {/* One row for both states, so the button that opened the dialog
                is still there to take focus back once the password is saved. */}
            <Row
              icon={
                <VaultIcon
                  className={cn('size-3.5', entry ? 'text-[var(--accent-text)]' : 'text-subtle')}
                />
              }
              label={entry ? t('hosts.vault.savedLabel') : t('hosts.vault.noneLabel')}
              hint={
                entry
                  ? [entry.username, entry.hasOtp ? t('hosts.vault.otpSaved') : '']
                      .filter(Boolean)
                      .join(' · ') || t('hosts.vault.savedHint')
                  : t('hosts.vault.noneHint')
              }
            >
              <Button
                size="sm"
                variant={entry ? 'secondary' : 'soft'}
                aria-label={entry ? t('hosts.vault.editLabel') : undefined}
                icon={
                  entry ? undefined : (
                    <Plus aria-hidden="true" className="size-3.5" strokeWidth={2.25} />
                  )
                }
                onClick={onEdit}
              >
                {entry ? t('hosts.vault.edit') : t('hosts.vault.save')}
              </Button>
              {entry ? (
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => navigate({ page: 'passwords', entryId: entry.id })}
                >
                  {t('hosts.vault.openInPasswords')}
                </Button>
              ) : null}
            </Row>
            {entry ? (
              <Row
                icon={
                  <KeyRound aria-hidden="true" className="size-3.5 text-subtle" strokeWidth={2} />
                }
                label={t('hosts.vault.switchLabel')}
                hint={dirty ? t('hosts.vault.switchDirty') : t('hosts.vault.switchHint')}
                hintId={switchHintId}
                warning={dirty}
              >
                <Button
                  size="sm"
                  variant="soft"
                  disabled={dirty}
                  aria-describedby={switchHintId}
                  onClick={onSwitch}
                >
                  {t('hosts.vault.switchAction')}
                </Button>
              </Row>
            ) : null}
          </>
        )}
      </div>
    </section>
  );
}

interface RowProps {
  icon: ReactNode;
  label: string;
  hint: string;
  hintId?: string;
  warning?: boolean;
  children: ReactNode;
}

/** Laid out like a `SwitchRow`, with buttons where the switch would be. */
function Row({ icon, label, hint, hintId, warning, children }: RowProps) {
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-2 rounded-[10px] px-2.5 py-[9px]">
      <div className="flex min-w-[180px] flex-1 flex-col">
        <span className="flex items-center gap-1.5 font-medium text-fg">
          {icon}
          {label}
        </span>
        <span
          id={hintId}
          className={warning ? 'text-[12px] text-warning' : 'text-[12px] text-subtle'}
        >
          {hint}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-1.5">{children}</div>
    </div>
  );
}
