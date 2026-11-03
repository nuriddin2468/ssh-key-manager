import { Eye, EyeOff, KeyRound, LogIn, type LucideIcon, Server, ShieldCheck } from 'lucide-react';
import { type FormEvent, useEffect, useId, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useConfig, useKeys } from '@/api/queries';
import type { EntryDetail } from '@/bindings/EntryDetail';
import type { EntryKind } from '@/bindings/EntryKind';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { Select, type SelectOption } from '@/components/ui/Select';
import { TextField } from '@/components/ui/TextField';
import { Tile, type Tone } from '@/components/ui/Tile';
import { shortFingerprint } from '@/lib/format';
import {
  EMPTY_FORM,
  type EntryForm,
  formFromEntry,
  hasErrors,
  inputFromForm,
  strengthContext,
  validateForm,
} from './model';
import { PasswordGenerator } from './PasswordGenerator';
import { StrengthMeter, useStrength } from './StrengthMeter';
import { useVaultMutation } from './vault';

const KINDS: { kind: EntryKind; tone: Tone; icon: LucideIcon }[] = [
  { kind: 'login', tone: 'pink', icon: LogIn },
  { kind: 'host', tone: 'blue', icon: Server },
  { kind: 'key', tone: 'teal', icon: KeyRound },
];

const KIND_LABEL = { login: 'kindLogin', host: 'kindHost', key: 'kindKey' } as const;
const KIND_HINT = { login: 'kindLoginHint', host: 'kindHostHint', key: 'kindKeyHint' } as const;

interface EntryEditorProps {
  /** The entry to edit, or `null` for a new one. */
  entry: EntryDetail | null;
  onDone: (savedId?: string) => void;
}

/** Adds or edits an entry. Secrets are never prefilled: an empty password keeps the current one. */
export function EntryEditor({ entry, onDone }: EntryEditorProps) {
  const { t } = useTranslation();
  const config = useConfig();
  const keys = useKeys();
  const [form, setForm] = useState<EntryForm>(() => (entry ? formFromEntry(entry) : EMPTY_FORM));
  const [showPassword, setShowPassword] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [otpRejected, setOtpRejected] = useState(false);
  const titleInput = useRef<HTMLInputElement>(null);
  const otpInput = useRef<HTMLInputElement>(null);
  const otpBox = useRef<HTMLDivElement>(null);
  const otpModeShown = useRef(form.otpMode);

  useEffect(() => {
    if (otpModeShown.current === form.otpMode) return;
    otpModeShown.current = form.otpMode;
    otpBox.current?.querySelector<HTMLElement>('input, button')?.focus();
  }, [form.otpMode]);
  const notesId = useId();

  const hadOtp = entry?.hasOtp ?? false;
  const keepsPassword = Boolean(entry?.hasPassword);
  const errors = validateForm(form, hadOtp);
  const shown = submitted ? errors : {};
  const strength = useStrength(form.password, strengthContext(form));
  const set = (patch: Partial<EntryForm>) => setForm((current) => ({ ...current, ...patch }));

  const hostOptions = useMemo<SelectOption[]>(() => {
    const aliases = new Set<string>();
    for (const host of config.data?.view.hosts ?? []) {
      if (host.kind !== 'host') continue;
      for (const pattern of host.patterns) {
        if (!/[*?!]/.test(pattern)) aliases.add(pattern);
      }
    }
    const options: SelectOption[] = [...aliases].map((alias) => ({
      value: alias,
      label: <span className="font-mono text-[12.5px]">{alias}</span>,
    }));
    if (form.host && !aliases.has(form.host)) {
      options.unshift({
        value: form.host,
        label: (
          <span className="font-mono text-[12.5px]">
            {t('passwords.notFound', { name: form.host })}
          </span>
        ),
      });
    }
    return options;
  }, [config.data, form.host, t]);

  const keyOptions = useMemo<SelectOption[]>(() => {
    const seen = new Set<string>();
    const options: SelectOption[] = [];
    for (const key of keys.data?.keys ?? []) {
      if (!key.fingerprint || !key.privatePath || seen.has(key.fingerprint)) continue;
      seen.add(key.fingerprint);
      options.push({
        value: key.fingerprint,
        label: key.name,
        hint: <span className="font-mono">{shortFingerprint(key.fingerprint)}</span>,
      });
    }
    if (form.keyFingerprint && !seen.has(form.keyFingerprint)) {
      options.unshift({
        value: form.keyFingerprint,
        label: t('passwords.notFound', { name: shortFingerprint(form.keyFingerprint) }),
      });
    }
    return options;
  }, [keys.data, form.keyFingerprint, t]);

  const save = useVaultMutation(
    (input: ReturnType<typeof inputFromForm>) =>
      entry ? api.vaultUpdate(entry.id, input) : api.vaultAdd(input),
    {
      success: (saved) =>
        entry
          ? t('passwords.saved', { name: saved.title })
          : t('passwords.added', { name: saved.title }),
      onSuccess: (saved) => onDone(saved.id),
      onError: (error) => {
        // The backend's last word on a 2FA secret the quick check let through.
        if (error.code !== 'invalid_input' || !/2FA/i.test(error.message)) return false;
        setOtpRejected(true);
        return true;
      },
    },
  );

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (save.isPending) return;
    if (hasErrors(errors)) {
      setSubmitted(true);
      if (errors.title) titleInput.current?.focus();
      else if (errors.otp) otpInput.current?.focus();
      return;
    }
    save.mutate(inputFromForm(form, hadOtp));
  };

  const pickHost = (alias: string) =>
    set({ host: alias, title: form.title.trim() ? form.title : alias });
  const pickKey = (fingerprint: string) => {
    const name = keys.data?.keys.find((key) => key.fingerprint === fingerprint)?.name ?? '';
    set({ keyFingerprint: fingerprint, title: form.title.trim() ? form.title : name });
  };

  const otpError =
    shown.otp === 'invalid' || otpRejected
      ? t('passwords.otpInvalid')
      : shown.otp === 'required'
        ? t('passwords.otpRequired')
        : undefined;
  const otpField = (
    <TextField
      ref={otpInput}
      label={t('passwords.otpField')}
      type="password"
      autoComplete="off"
      mono
      placeholder={t('passwords.otpPlaceholder')}
      value={form.otp}
      onChange={(event) => {
        set({ otp: event.target.value });
        setOtpRejected(false);
      }}
      hint={t('passwords.otpHint')}
      error={otpError}
      autoFocus={hadOtp}
    />
  );

  return (
    <DialogContent section="passwords" className="max-w-[560px]">
      <form onSubmit={submit} noValidate className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="pink" size={44} glow>
              <ShieldCheck className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={entry ? t('passwords.editTitle', { name: entry.title }) : t('passwords.newTitle')}
          description={t('passwords.editorDescription')}
        />
        <DialogBody>
          <ChoiceCards
            legend={t('passwords.kind')}
            value={form.kind}
            onValueChange={(kind) => set({ kind })}
            options={KINDS.map(({ kind, tone, icon }) => ({
              value: kind,
              tone,
              icon,
              title: t(`passwords.${KIND_LABEL[kind]}`),
              hint: t(`passwords.${KIND_HINT[kind]}`),
            }))}
          />

          {form.kind === 'host' ? (
            hostOptions.length > 0 ? (
              <Select
                label={t('passwords.hostField')}
                value={form.host}
                onValueChange={pickHost}
                placeholder={t('passwords.hostPlaceholder')}
                options={hostOptions}
                hint={
                  shown.host ? (
                    <span className="text-critical">{t('passwords.hostRequired')}</span>
                  ) : (
                    t('passwords.hostHint')
                  )
                }
              />
            ) : (
              <p className="rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5 text-[12.5px] text-warning">
                {t('passwords.noHosts')}
              </p>
            )
          ) : null}

          {form.kind === 'key' ? (
            keyOptions.length > 0 ? (
              <Select
                label={t('passwords.keyField')}
                value={form.keyFingerprint}
                onValueChange={pickKey}
                placeholder={t('passwords.keyPlaceholder')}
                options={keyOptions}
                hint={
                  shown.key ? (
                    <span className="text-critical">{t('passwords.keyRequired')}</span>
                  ) : (
                    t('passwords.keyHint')
                  )
                }
              />
            ) : (
              <p className="rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5 text-[12.5px] text-warning">
                {t('passwords.noKeys')}
              </p>
            )
          ) : null}

          <div className="grid grid-cols-2 gap-3.5">
            <TextField
              ref={titleInput}
              label={t('passwords.titleField')}
              placeholder={t('passwords.titlePlaceholder')}
              value={form.title}
              onChange={(event) => set({ title: event.target.value })}
              error={shown.title ? t('passwords.titleRequired') : undefined}
              required
            />
            <TextField
              label={t('passwords.usernameField')}
              value={form.username}
              onChange={(event) => set({ username: event.target.value })}
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <TextField
              label={form.kind === 'key' ? t('passwords.passphrase') : t('passwords.password')}
              type={showPassword ? 'text' : 'password'}
              autoComplete="new-password"
              mono={showPassword}
              placeholder={keepsPassword ? t('passwords.passwordUnchanged') : undefined}
              value={form.password}
              onChange={(event) => set({ password: event.target.value })}
              hint={keepsPassword ? t('passwords.passwordKeepHint') : undefined}
              suffix={
                <>
                  <IconButton
                    label={showPassword ? t('passwords.hidePassword') : t('passwords.showPassword')}
                    icon={
                      showPassword ? (
                        <EyeOff className="size-[15px]" strokeWidth={1.9} />
                      ) : (
                        <Eye className="size-[15px]" strokeWidth={1.9} />
                      )
                    }
                    className="size-7 rounded-md"
                    onClick={() => setShowPassword((shownNow) => !shownNow)}
                  />
                  <PasswordGenerator
                    onUse={(password) => {
                      set({ password });
                      setShowPassword(true);
                    }}
                  />
                </>
              }
            />
            {form.password ? <StrengthMeter strength={strength} /> : null}
          </div>

          {form.kind === 'login' || form.url ? (
            <TextField
              label={t('passwords.websiteField')}
              type="url"
              inputMode="url"
              placeholder={t('passwords.websitePlaceholder')}
              value={form.url}
              onChange={(event) => set({ url: event.target.value })}
            />
          ) : null}

          {hadOtp ? (
            <div ref={otpBox} className="contents">
              {form.otpMode === 'keep' ? (
                <div className="flex flex-col gap-1.5">
                  <span className="text-[12px] font-semibold text-fg-2">
                    {t('passwords.otpField')}
                  </span>
                  <div className="field flex min-h-11 items-center gap-2.5 rounded-[10px] py-1.5 pr-1.5 pl-3">
                    <ShieldCheck aria-hidden="true" className="size-4 text-ok" strokeWidth={2} />
                    <span className="flex-1">{t('passwords.otpSaved')}</span>
                    <Button size="sm" variant="ghost" onClick={() => set({ otpMode: 'replace' })}>
                      {t('passwords.otpReplace')}
                    </Button>
                    <Button size="sm" variant="danger" onClick={() => set({ otpMode: 'remove' })}>
                      {t('passwords.otpRemove')}
                    </Button>
                  </div>
                </div>
              ) : form.otpMode === 'replace' ? (
                <div className="flex flex-col gap-2">
                  {otpField}
                  <Button
                    size="sm"
                    variant="ghost"
                    className="self-start"
                    onClick={() => set({ otpMode: 'keep', otp: '' })}
                  >
                    {t('passwords.otpKeep')}
                  </Button>
                </div>
              ) : (
                <div className="flex flex-col gap-1.5">
                  <span className="text-[12px] font-semibold text-fg-2">
                    {t('passwords.otpField')}
                  </span>
                  <div
                    role="status"
                    className="flex min-h-11 items-center gap-2.5 rounded-[10px] border border-warning-solid/30 bg-warning-solid/[0.09] py-1.5 pr-1.5 pl-3 text-warning"
                  >
                    <span className="flex-1 text-[12.5px]">{t('passwords.otpRemoving')}</span>
                    <Button size="sm" variant="ghost" onClick={() => set({ otpMode: 'keep' })}>
                      {t('passwords.otpKeep')}
                    </Button>
                  </div>
                </div>
              )}
            </div>
          ) : form.kind !== 'key' ? (
            otpField
          ) : null}

          <div className="flex flex-col gap-1.5">
            <label htmlFor={notesId} className="text-[12px] font-semibold text-fg-2">
              {t('passwords.notesField')}
            </label>
            <textarea
              id={notesId}
              value={form.notes}
              onChange={(event) => set({ notes: event.target.value })}
              rows={3}
              className="field min-h-[76px] resize-y rounded-[10px] px-[11px] py-2 text-fg outline-none focus:border-[rgb(var(--accent-rgb)/0.55)] focus:shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.15)]"
            />
          </div>
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={() => onDone()}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" size="lg" loading={save.isPending}>
            {entry ? t('common.save') : t('passwords.add')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
