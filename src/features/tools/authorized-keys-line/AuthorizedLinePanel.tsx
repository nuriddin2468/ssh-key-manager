import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { CircleCheck, CircleX, Copy, Upload } from 'lucide-react';
import { useDeferredValue, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useKeys } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { KeyInstall } from '@/bindings/KeyInstall';
import { Button } from '@/components/ui/Button';
import { Select } from '@/components/ui/Select';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { copyText } from '@/lib/clipboard';
import { cn } from '@/lib/cn';
import { OutputBox, Section, useHostAliases } from '../ssh/parts';
import { type LineForm, optionsOf, problemsByField } from './model';

const FLAGS = ['noPortForwarding', 'noAgentForwarding', 'noPty', 'noX11Forwarding'] as const;

/**
 * The `authorized_keys` line builder: a public key and the options that
 * limit it, the line as the core builds and checks it, and installing it on
 * a host through the app's install flow.
 */
export function AuthorizedLinePanel() {
  const { t } = useTranslation();
  const keys = useKeys();
  const withPublic = (keys.data?.keys ?? []).filter((key) => key.publicKey);
  const [picked, setPicked] = useState('');
  const [form, setForm] = useState<LineForm>({
    publicKey: '',
    restrict: false,
    from: '',
    command: '',
    expiry: '',
    noPortForwarding: false,
    noAgentForwarding: false,
    noPty: false,
    noX11Forwarding: false,
  });
  const set = (patch: Partial<LineForm>) => setForm((current) => ({ ...current, ...patch }));
  const deferred = useDeferredValue(form);
  const built = useQuery({
    queryKey: ['authorized-line', deferred],
    queryFn: () => api.authorizedLine(deferred.publicKey, optionsOf(deferred)),
    placeholderData: keepPreviousData,
    gcTime: 0,
  });
  const problems = problemsByField(t, built.data?.problems ?? []);
  const touched = form.publicKey.trim() !== '';
  const line = built.data?.line ?? null;
  const keyId = useId();
  const keyError = touched ? problems.key : undefined;

  const copy = () =>
    line &&
    copyText(line)
      .then(() => toast.success(t('toolSsh.line.copied')))
      .catch((error: unknown) => toastError(t, error));

  return (
    <div className="flex flex-col gap-3.5">
      <p className="text-[12.5px] text-muted">{t('toolSsh.line.description')}</p>
      <Section title={t('toolSsh.line.key')}>
        <Select
          label={t('toolSsh.line.fromSsh')}
          value={picked}
          onValueChange={(name) => {
            setPicked(name);
            const key = withPublic.find((k) => k.name === name);
            if (key?.publicKey) set({ publicKey: key.publicKey });
          }}
          options={withPublic.map((key) => ({
            value: key.name,
            label: key.name,
            hint: key.keyType,
          }))}
          placeholder={t('toolSsh.line.fromSshPlaceholder')}
          mono
          className="max-w-[360px]"
        />
        <div className="flex flex-col gap-1.5">
          <label htmlFor={keyId} className="text-[12px] font-semibold text-fg-2">
            {t('toolSsh.line.paste')}
          </label>
          <textarea
            id={keyId}
            value={form.publicKey}
            onChange={(event) => {
              setPicked('');
              set({ publicKey: event.target.value });
            }}
            placeholder={t('toolSsh.line.pastePlaceholder')}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            rows={3}
            aria-invalid={keyError ? true : undefined}
            aria-describedby={keyError ? `${keyId}-error` : undefined}
            className={cn(
              'field resize-none rounded-[10px] bg-black/30 px-[11px] py-2 font-mono text-[12px] leading-[18px] break-all text-fg outline-none focus:border-[rgb(var(--accent-rgb)/0.55)] focus:shadow-[0_0_0_3px_rgb(var(--accent-rgb)/0.15)]',
              keyError && 'border-critical-solid/60',
            )}
          />
          {keyError ? (
            <p id={`${keyId}-error`} className="text-[12px] text-critical">
              {keyError}
            </p>
          ) : built.data?.fingerprint ? (
            <p className="font-mono text-[11.5px] text-subtle">{built.data.fingerprint}</p>
          ) : null}
        </div>
      </Section>

      <Section title={t('toolSsh.line.limits')}>
        <SwitchGroup>
          <SwitchRow
            label={t('toolSsh.line.restrict')}
            hint={t('toolSsh.line.restrictHint')}
            checked={form.restrict}
            onCheckedChange={(restrict) => set({ restrict })}
          />
          {FLAGS.map((flag) => (
            <SwitchRow
              key={flag}
              label={t(`toolSsh.line.${flag}`)}
              hint={
                form.restrict
                  ? t('toolSsh.line.inRestrict')
                  : flag === 'noPty'
                    ? t('toolSsh.line.noPtyHint')
                    : undefined
              }
              checked={form.restrict || form[flag]}
              disabled={form.restrict}
              onCheckedChange={(on) => set({ [flag]: on })}
            />
          ))}
        </SwitchGroup>
        <div className="grid gap-3 md:grid-cols-2">
          <TextField
            label={t('toolSsh.line.from')}
            value={form.from}
            onChange={(event) => set({ from: event.target.value })}
            placeholder="10.0.0.0/8, *.example.com"
            mono
            hint={t('toolSsh.line.fromHint')}
            error={problems.from}
            className="md:col-span-2"
          />
          <TextField
            label={t('toolSsh.line.command')}
            value={form.command}
            onChange={(event) => set({ command: event.target.value })}
            placeholder="/usr/local/bin/backup"
            mono
            hint={t('toolSsh.line.commandHint')}
            error={problems.command}
          />
          <TextField
            label={t('toolSsh.line.expiry')}
            type="date"
            value={form.expiry}
            onChange={(event) => set({ expiry: event.target.value })}
            hint={t('toolSsh.line.expiryHint')}
            error={problems.expiry}
          />
        </div>
      </Section>

      <Section
        title={t('toolSsh.line.result')}
        action={
          <Button
            size="sm"
            variant="soft"
            icon={<Copy className="size-3.5" strokeWidth={2} />}
            onClick={() => void copy()}
            disabled={!line}
          >
            {t('toolSsh.line.copy')}
          </Button>
        }
      >
        <code
          aria-live="polite"
          className={cn(
            'selectable min-h-[44px] rounded-[11px] border border-white/[0.07] bg-terminal px-3 py-2.5 font-mono text-[12px] leading-[1.6] break-all',
            line ? 'text-fg' : 'text-subtle',
          )}
        >
          {line ??
            (touched
              ? (problems.key ?? problems.from ?? problems.command ?? problems.expiry)
              : null) ??
            t('toolSsh.line.problem.keyMissing')}
        </code>
      </Section>

      <Install line={line} />
    </div>
  );
}

function Install({ line }: { line: string | null }) {
  const { t } = useTranslation();
  const aliases = useHostAliases();
  const [alias, setAlias] = useState('');
  const [result, setResult] = useState<{ alias: string; install: KeyInstall } | null>(null);
  const install = useAppMutation(() => api.installAuthorizedLine(alias, line ?? ''), {
    onSuccess: (done) => setResult({ alias, install: done }),
  });
  return (
    <Section title={t('toolSsh.line.install')} description={t('toolSsh.line.installHint')}>
      <div className="flex flex-wrap items-end gap-3">
        <Select
          label={t('toolSsh.line.host')}
          value={alias}
          onValueChange={(next) => {
            setAlias(next);
            setResult(null);
          }}
          options={aliases.map((value) => ({ value, label: value }))}
          placeholder={t('toolSsh.line.hostPlaceholder')}
          mono
          className="min-w-[240px] flex-1"
        />
        <Button
          variant="primary"
          icon={<Upload className="size-4" strokeWidth={2} />}
          onClick={() => install.mutate(undefined)}
          disabled={!line || !alias}
          loading={install.isPending}
        >
          {t('toolSsh.line.installAction')}
        </Button>
      </div>
      {result ? (
        <div aria-live="polite" className="flex flex-col gap-1.5">
          <p
            className={cn(
              'flex items-start gap-2 text-[12.5px]',
              result.install.ok ? 'text-ok' : 'text-critical',
            )}
          >
            {result.install.ok ? (
              <CircleCheck
                aria-hidden="true"
                className="mt-px size-4 shrink-0"
                strokeWidth={2.25}
              />
            ) : (
              <CircleX aria-hidden="true" className="mt-px size-4 shrink-0" strokeWidth={2.25} />
            )}
            {result.install.added
              ? t('toolSsh.line.added', { alias: result.alias })
              : result.install.ok
                ? t('toolSsh.line.present', { alias: result.alias })
                : t('toolSsh.line.installFailed', { alias: result.alias })}
          </p>
          {!result.install.ok && result.install.output ? (
            <OutputBox text={result.install.output} />
          ) : null}
        </div>
      ) : null}
    </Section>
  );
}
