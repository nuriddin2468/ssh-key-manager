import { AlertTriangle, ArrowRight, CornerDownRight, KeyRound, Plus } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useConfig, useEnvironment, useKeys } from '@/api/queries';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyView } from '@/bindings/KeyView';
import { Select, type SelectOption } from '@/components/ui/Select';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { algorithmBadge, keyTone } from '@/features/keys/model';
import { cn } from '@/lib/cn';
import { displayPath } from '@/lib/format';
import { chooseKey, type HostForm, type PreviewLine, validatePort } from './model';

/** Radix Select reserves the empty string, so "none" needs its own value. */
const NONE = '__none__';
/** The "Create a new key…" item of the key picker. */
const NEW_KEY = '__new__';

/** Validation shared by the add dialog and the editor. */
export function useHostErrors(
  form: HostForm,
  edit: HostEdit,
  hosts: readonly HostEntry[],
): { alias?: string; port?: string } {
  const { t } = useTranslation();
  const others = hosts.filter((h) => h.kind === 'host' && h.id !== edit.id);
  const taken = edit.patterns.find((pattern) => others.some((h) => h.patterns.includes(pattern)));
  return {
    alias:
      edit.patterns.length === 0
        ? t('hosts.aliasRequired')
        : /["']/.test(form.patterns)
          ? t('hosts.aliasInvalid')
          : taken
            ? t('hosts.aliasTaken', { alias: taken })
            : undefined,
    port: validatePort(form.port) ? undefined : t('hosts.portInvalid'),
  };
}

type SetField = <K extends keyof HostForm>(key: K, value: HostForm[K]) => void;

interface ServerFieldsProps {
  form: HostForm;
  set: SetField;
  errors: { alias?: string; port?: string };
  aliasHint: string;
  autoFocus?: boolean;
}

/** Alias, address, user and port, two by two. */
export function ServerFields({ form, set, errors, aliasHint, autoFocus }: ServerFieldsProps) {
  const { t } = useTranslation();
  return (
    <div className="grid grid-cols-2 gap-x-3 gap-y-2.5">
      <TextField
        label={t('hosts.alias')}
        mono
        value={form.patterns}
        onChange={(e) => set('patterns', e.target.value)}
        error={errors.alias}
        hint={aliasHint}
        autoFocus={autoFocus}
        placeholder="prod"
      />
      <TextField
        label={t('hosts.editor.address')}
        mono
        value={form.hostName}
        onChange={(e) => set('hostName', e.target.value)}
        hint={t('hosts.editor.addressHint')}
        placeholder="203.0.113.10"
      />
      <TextField
        label={t('hosts.user')}
        mono
        value={form.user}
        onChange={(e) => set('user', e.target.value)}
        placeholder="ubuntu"
      />
      <TextField
        label={t('hosts.port')}
        mono
        inputMode="numeric"
        value={form.port}
        onChange={(e) => set('port', e.target.value)}
        error={errors.port}
        placeholder="22"
      />
    </div>
  );
}

/**
 * The key a host file names, if it is one of the keys found: by the
 * `IdentityFile` value as written (`~/.ssh/id_work`) or by its expanded path.
 * `missing`: the file isn't there.
 */
export function useKeyForFile(file: string): { key: KeyView | undefined; missing: boolean } {
  const keys = useKeys();
  const config = useConfig();
  const home = useEnvironment().data?.paths.home;
  if (!file) return { key: undefined, missing: false };
  const usage = (config.data?.usage ?? []).find((u) => u.raw === file);
  const key = (keys.data?.keys ?? []).find(
    (k) =>
      k.privatePath &&
      (displayPath(k.privatePath, home) === file ||
        k.privatePath === file ||
        k.privatePath === usage?.path),
  );
  return { key, missing: !key && Boolean(usage?.resolved && !usage.exists) };
}

interface KeyPickerProps {
  /** The `IdentityFile` value; empty for any key. */
  value: string;
  onChange: (file: string) => void;
  /** Adds "Create a new key…" to the list. */
  onCreate?: () => void;
  label?: string;
  'aria-label'?: string;
}

/** "Any key", the keys in `~/.ssh` (tile, name, type) and optionally "Create a new key…". */
export function KeyPicker({
  value,
  onChange,
  onCreate,
  label,
  'aria-label': ariaLabel,
}: KeyPickerProps) {
  const { t } = useTranslation();
  const keys = useKeys();
  const home = useEnvironment().data?.paths.home;
  const { key: current, missing } = useKeyForFile(value);

  const options: SelectOption[] = [
    {
      value: NONE,
      label: <span className="font-sans">{t('hosts.signIn.anyKey')}</span>,
      icon: <KeyRound aria-hidden="true" className="size-3.5 text-subtle" />,
    },
  ];
  const keyOptions = (keys.data?.keys ?? [])
    .filter((key) => key.privatePath)
    .map((key) => ({
      // The value as the config spells it, so choosing the saved key changes nothing.
      value: key === current ? value : displayPath(key.privatePath ?? '', home),
      label: key.name,
      hint: algorithmBadge(key),
      icon: (
        <Tile tone={keyTone(key)} size={18}>
          <KeyRound className="size-[11px]" strokeWidth={2.5} />
        </Tile>
      ),
    }));
  if (value && !current) {
    // A key outside ~/.ssh is fine; only warn when the file really is gone.
    options.push({
      value,
      label: value,
      hint: missing ? t('hosts.missingKey') : undefined,
      icon: missing ? (
        <AlertTriangle aria-hidden="true" className="size-3.5 text-warning" strokeWidth={2} />
      ) : (
        <KeyRound aria-hidden="true" className="size-3.5 text-subtle" />
      ),
    });
  }
  options.push(...keyOptions);
  if (onCreate) {
    options.push({
      value: NEW_KEY,
      label: <span className="font-sans">{t('hosts.signIn.newKey')}</span>,
      icon: <Plus aria-hidden="true" className="size-3.5 text-[var(--accent-text)]" />,
    });
  }

  return (
    <Select
      label={label}
      aria-label={ariaLabel}
      mono
      value={value || NONE}
      onValueChange={(next) => {
        if (next === NEW_KEY) onCreate?.();
        else onChange(next === NONE ? '' : next);
      }}
      options={options}
    />
  );
}

interface JumpHostSelectProps {
  value: string;
  onChange: (jump: string) => void;
  hosts: readonly HostEntry[];
  /** The host being edited, so it is not offered as its own jump host. */
  hostId: number | null;
}

/** ProxyJump: connect directly, or through one of the other hosts. */
export function JumpHostSelect({ value, onChange, hosts, hostId }: JumpHostSelectProps) {
  const { t } = useTranslation();
  const jumpOptions = hosts
    .filter((h) => h.kind === 'host' && !h.isWildcard && h.id !== hostId)
    .map((h) => h.patterns[0] ?? '')
    .filter(Boolean);
  if (value && !jumpOptions.includes(value)) jumpOptions.unshift(value);
  return (
    <Select
      label={t('hosts.proxyJump')}
      mono
      value={value || NONE}
      onValueChange={(next) => onChange(next === NONE ? '' : next)}
      options={[
        {
          value: NONE,
          label: <span className="font-sans">{t('hosts.proxyNone')}</span>,
          icon: <ArrowRight aria-hidden="true" className="size-3.5 text-subtle" />,
        },
        ...jumpOptions.map((jump) => ({
          value: jump,
          label: jump,
          icon: <CornerDownRight aria-hidden="true" className="size-3.5 text-subtle" />,
        })),
      ]}
    />
  );
}

interface HostFieldsProps {
  form: HostForm;
  set: SetField;
  hosts: readonly HostEntry[];
  errors: { alias?: string; port?: string };
  autoFocus?: boolean;
}

/** The add dialog's fields: server, key and jump host, plus the two common switches. */
export function HostFields({ form, set, hosts, errors, autoFocus }: HostFieldsProps) {
  const { t } = useTranslation();
  return (
    <>
      <ServerFields
        form={form}
        set={set}
        errors={errors}
        aliasHint={t('hosts.aliasHint')}
        autoFocus={autoFocus}
      />
      <div className="grid grid-cols-2 gap-3">
        <KeyPicker
          label={t('hosts.identityFile')}
          value={form.identityFile}
          onChange={(file) => {
            const next = chooseKey(form, file);
            set('identityFile', next.identityFile);
            set('identitiesOnly', next.identitiesOnly);
          }}
        />
        <JumpHostSelect
          value={form.proxyJump}
          onChange={(jump) => set('proxyJump', jump)}
          hosts={hosts}
          hostId={null}
        />
      </div>

      <SwitchGroup>
        {form.identityFile ? (
          <SwitchRow
            label={
              <>
                {t('hosts.identitiesOnly')}{' '}
                <span className="font-mono text-[11.5px] text-subtle">IdentitiesOnly</span>
              </>
            }
            hint={t('hosts.identitiesOnlyHint')}
            checked={form.identitiesOnly}
            onCheckedChange={(value) => set('identitiesOnly', value)}
          />
        ) : null}
        <ForwardAgentRow checked={form.forwardAgent} onChange={(v) => set('forwardAgent', v)} />
      </SwitchGroup>
    </>
  );
}

export function ForwardAgentRow({
  checked,
  onChange,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  const { t } = useTranslation();
  return (
    <SwitchRow
      label={
        <>
          {t('hosts.forwardAgent')}{' '}
          <span className="font-mono text-[11.5px] text-subtle">ForwardAgent</span>
        </>
      }
      hint={t('hosts.forwardAgentHint')}
      checked={checked}
      onCheckedChange={onChange}
    />
  );
}

interface ConfigPreviewProps {
  lines: readonly PreviewLine[];
  /** Lines that differ from the saved block, tinted green. */
  changed?: readonly boolean[];
  className?: string;
}

/** The block as it will appear in `~/.ssh/config`. */
export function ConfigPreview({ lines, changed, className }: ConfigPreviewProps) {
  const { t } = useTranslation();
  return (
    <div
      className={cn(
        'selectable overflow-x-auto rounded-[14px] border border-white/[0.06] bg-[#06080d] px-4 py-3.5 font-mono text-[12.5px] leading-[1.75]',
        className,
      )}
    >
      {lines.map((line, index) => {
        const text = (
          <>
            {line.key} {line.value}
          </>
        );
        return (
          // biome-ignore lint/suspicious/noArrayIndexKey: preview lines are positional
          <div key={index} className={cn('relative whitespace-pre', !line.header && 'pl-[18px]')}>
            {changed?.[index] ? (
              // A bar beside the line, so the change doesn't rest on colour alone.
              <ins
                title={t('hosts.editor.changedLine')}
                className="text-green-300 no-underline before:absolute before:top-[5px] before:bottom-[5px] before:-left-2 before:w-0.5 before:rounded-full before:bg-green-300"
              >
                {text}
              </ins>
            ) : (
              <span className={line.header ? 'font-medium text-[var(--accent-text)]' : 'text-fg-2'}>
                {text}
              </span>
            )}
          </div>
        );
      })}
    </div>
  );
}
