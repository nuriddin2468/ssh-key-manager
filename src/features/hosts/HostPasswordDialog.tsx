import { Eye, EyeOff, WandSparkles } from 'lucide-react';
import { type FormEvent, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { EntrySummary } from '@/bindings/EntrySummary';
import type { GenerateOptions } from '@/bindings/GenerateOptions';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { VaultIcon } from '@/features/keys/VaultControls';
import { cn } from '@/lib/cn';
import { AppError } from '@/lib/ipc';
import { hostEntryInput, isOtpSecret, type PasswordForm, vaultErrorMessage } from './vault';

/** Long and varied; it reaches ssh through askpass, never a shell, so any symbol is fine. */
const GENERATE: GenerateOptions = {
  mode: 'password',
  length: 24,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: true,
};

/** The passphrase meter's colours, by zxcvbn score. */
const SEGMENT_COLORS = [
  'var(--color-strength-1)',
  'var(--color-strength-1)',
  'var(--color-strength-2)',
  'var(--color-strength-3)',
  'var(--color-strength-4)',
];

interface HostPasswordDialogProps {
  alias: string;
  /**
   * The host's `User`. It is the user everywhere, so the entry takes it (and
   * follows it when the host is saved with another one).
   */
  user: string;
  /** The entry to edit; without it a new one is made. */
  entry?: EntrySummary;
  /** Start in the 2FA field (opened to add a 2FA secret). */
  focusOtp?: boolean;
  onDone: () => void;
}

type OtpChange = 'keep' | 'replace' | 'remove';

/** Saves a host's password (and 2FA secret) in the vault, or edits the saved one. */
export function HostPasswordDialog({
  alias,
  user,
  entry,
  focusOtp = false,
  onDone,
}: HostPasswordDialogProps) {
  const { t } = useTranslation();
  const username = user;
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [strength, setStrength] = useState<number | null>(null);
  const [otp, setOtp] = useState('');
  const [otpChange, setOtpChange] = useState<OtpChange>('keep');
  const [otpBlurred, setOtpBlurred] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const passwordId = useId();

  // Replace, Remove, Undo and Keep current swap the controls under the
  // pointer; focus moves to the first of the new ones.
  const otpArea = useRef<HTMLDivElement>(null);
  const [moveFocus, setMoveFocus] = useState(false);
  const changeOtp = (next: OtpChange) => {
    setOtpChange(next);
    setMoveFocus(true);
  };
  useEffect(() => {
    if (!moveFocus) return;
    otpArea.current?.querySelector<HTMLElement>('input, button')?.focus();
    setMoveFocus(false);
  }, [moveFocus]);

  const editing = Boolean(entry);
  const otpSaved = entry?.hasOtp ?? false;
  const otpField = !otpSaved || otpChange === 'replace';

  // zxcvbn runs in Rust; ask once typing pauses.
  useEffect(() => {
    if (!password) {
      setStrength(null);
      return;
    }
    let current = true;
    const timer = setTimeout(() => {
      api
        .vaultStrength(password, [alias, username])
        .then((result) => current && setStrength(result.score))
        .catch(() => current && setStrength(null));
    }, 250);
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, [password, alias, username]);

  const passwordError =
    submitted && !editing && !password ? t('hosts.vault.dialog.passwordRequired') : undefined;
  const otpInvalid = otpField && otp.trim() !== '' && !isOtpSecret(otp);
  const otpError =
    otpInvalid && (submitted || otpBlurred) ? t('hosts.vault.dialog.otpInvalid') : undefined;

  const save = useAppMutation(
    async (form: PasswordForm) => {
      if (!entry) return api.vaultAdd(hostEntryInput(alias, form));
      const current = await api.vaultEntry(entry.id);
      return api.vaultUpdate(entry.id, hostEntryInput(alias, form, current));
    },
    {
      success: () =>
        editing
          ? t('hosts.vault.dialog.updated', { alias })
          : t('hosts.vault.dialog.added', { alias }),
      onSuccess: onDone,
      onError: (error) => {
        const code = AppError.from(error).code;
        if (code !== 'vault_locked' && code !== 'conflict') return false;
        toast.error(vaultErrorMessage(t, error));
        return true;
      },
    },
  );

  const generate = async () => {
    setGenerating(true);
    try {
      setPassword(await api.vaultGenerate(GENERATE));
      setVisible(true);
      setGenerated(true);
    } catch (error) {
      toastError(t, error);
    } finally {
      setGenerating(false);
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    // Opened from the host editor's form: React would bubble this submit to it.
    event.stopPropagation();
    setSubmitted(true);
    if (save.isPending || (!editing && !password) || otpInvalid) return;
    save.mutate({
      username,
      password: password || null,
      otp: otpChange === 'remove' ? '' : otpField && otp.trim() ? otp.trim() : null,
    });
  };

  return (
    <DialogContent section="hosts" className="max-w-[500px]">
      <form onSubmit={submit} noValidate className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="blue" size={44} glow>
              <VaultIcon className="size-5" />
            </Tile>
          }
          title={
            editing
              ? t('hosts.vault.dialog.editTitle', { alias })
              : t('hosts.vault.dialog.addTitle', { alias })
          }
          description={t('hosts.vault.dialog.description')}
        />
        <DialogBody>
          <div className="flex min-w-0 flex-col gap-1.5">
            <label htmlFor={passwordId} className="text-[12px] font-semibold text-fg-2">
              {t('hosts.vault.dialog.password')}
            </label>
            <div
              className={cn(
                'field flex h-9 items-center overflow-hidden rounded-[10px] pr-[3px] transition-colors focus-within:border-[rgb(var(--accent-rgb)/var(--edge-alpha))] focus-within:shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.15)]',
                passwordError && 'border-critical-solid/60',
              )}
            >
              <input
                id={passwordId}
                type={visible ? 'text' : 'password'}
                value={password}
                onChange={(event) => {
                  setPassword(event.target.value);
                  setGenerated(false);
                }}
                autoComplete="new-password"
                spellCheck={false}
                aria-invalid={passwordError ? true : undefined}
                aria-describedby={`${passwordId}-hint`}
                className="h-full min-w-0 flex-1 bg-transparent px-[11px] font-mono text-[12.5px] text-fg outline-none"
              />
              <IconButton
                label={visible ? t('hosts.vault.dialog.hide') : t('hosts.vault.dialog.show')}
                icon={
                  visible ? (
                    <EyeOff className="size-[15px]" strokeWidth={1.75} />
                  ) : (
                    <Eye className="size-[15px]" strokeWidth={1.75} />
                  )
                }
                onClick={() => setVisible((v) => !v)}
              />
            </div>
            <div id={`${passwordId}-hint`} className="flex flex-col gap-1.5">
              {passwordError ? (
                <p className="text-[12px] text-critical">{passwordError}</p>
              ) : editing && !password ? (
                <p className="text-[12px] text-subtle">{t('hosts.vault.dialog.keepHint')}</p>
              ) : null}
              {password && strength !== null ? <StrengthMeter score={strength} /> : null}
            </div>
            <Button
              variant="ghost"
              size="sm"
              className="self-start"
              loading={generating}
              icon={<WandSparkles aria-hidden="true" className="size-[15px]" strokeWidth={1.9} />}
              onClick={() => void generate()}
            >
              {t('hosts.vault.dialog.generate')}
            </Button>
            <p aria-live="polite" className="text-[12px] leading-[18px] text-warning empty:hidden">
              {generated ? t('hosts.vault.dialog.generatedNote') : ''}
            </p>
          </div>

          <div ref={otpArea}>
            {otpSaved && otpChange !== 'replace' ? (
              <div className="glass flex flex-wrap items-center gap-x-3 gap-y-2 rounded-[14px] px-4 py-3">
                <div className="flex min-w-[180px] flex-1 flex-col">
                  <span className={cn('font-medium', otpChange === 'remove' && 'line-through')}>
                    {t('hosts.vault.dialog.otpSaved')}
                  </span>
                  <span
                    aria-live="polite"
                    className={cn(
                      'text-[12px]',
                      otpChange === 'remove' ? 'text-warning' : 'text-subtle',
                    )}
                  >
                    {otpChange === 'remove'
                      ? t('hosts.vault.dialog.otpRemoving')
                      : t('hosts.vault.dialog.otpSavedHint')}
                  </span>
                </div>
                {otpChange === 'remove' ? (
                  <Button size="sm" onClick={() => changeOtp('keep')}>
                    {t('hosts.vault.dialog.otpUndo')}
                  </Button>
                ) : (
                  <div className="flex gap-1.5">
                    <Button size="sm" onClick={() => changeOtp('replace')}>
                      {t('hosts.vault.dialog.otpReplace')}
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => changeOtp('remove')}>
                      {t('hosts.vault.dialog.otpRemove')}
                    </Button>
                  </div>
                )}
              </div>
            ) : (
              <div className="flex flex-col gap-1.5">
                <TextField
                  label={otpSaved ? t('hosts.vault.dialog.otpNew') : t('hosts.vault.dialog.otp')}
                  mono
                  value={otp}
                  onChange={(event) => setOtp(event.target.value)}
                  onBlur={() => setOtpBlurred(true)}
                  error={otpError}
                  hint={t('hosts.vault.dialog.otpHint')}
                  placeholder="otpauth://totp/…"
                  // Taken before the dialog would focus its first field.
                  autoFocus={focusOtp}
                />
                {otpSaved ? (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="self-start"
                    onClick={() => {
                      setOtp('');
                      setOtpBlurred(false);
                      changeOtp('keep');
                    }}
                  >
                    {t('hosts.vault.dialog.otpKeep')}
                  </Button>
                ) : null}
              </div>
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" size="lg" loading={save.isPending}>
            {editing ? t('common.save') : t('hosts.vault.dialog.submitAdd')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

function StrengthMeter({ score }: { score: number }) {
  const { t } = useTranslation();
  const level = Math.max(0, Math.min(4, Math.round(score))) as 0 | 1 | 2 | 3 | 4;
  const color = SEGMENT_COLORS[level];
  const label = t(`hosts.vault.dialog.strength${level}`);
  return (
    <div className="flex items-center gap-2">
      <div aria-hidden="true" className="grid flex-1 grid-cols-4 gap-1">
        {[1, 2, 3, 4].map((segment) => (
          <span
            key={segment}
            className="h-1 rounded-sm bg-ink/10"
            style={segment <= Math.max(level, 1) ? { background: color } : undefined}
          />
        ))}
      </div>
      <span className="text-[12px] font-medium" style={{ color }}>
        <span className="sr-only">{t('hosts.vault.dialog.strength', { level: label })}</span>
        <span aria-hidden="true">{label}</span>
      </span>
    </div>
  );
}
