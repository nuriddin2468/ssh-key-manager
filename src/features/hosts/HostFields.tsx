import { AlertTriangle, ArrowRight, CornerDownRight, KeyRound } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useConfig, useEnvironment, useKeys } from '@/api/queries';
import type { HostEdit } from '@/bindings/HostEdit';
import type { HostEntry } from '@/bindings/HostEntry';
import { Select, type SelectOption } from '@/components/ui/Select';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { algorithmBadge, keyTone } from '@/features/keys/model';
import { cn } from '@/lib/cn';
import { displayPath } from '@/lib/format';
import { type HostForm, validatePort } from './model';

/** Radix Select reserves the empty string, so "none" needs its own value. */
const NONE = '__none__';

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

interface HostFieldsProps {
  form: HostForm;
  set: <K extends keyof HostForm>(key: K, value: HostForm[K]) => void;
  hosts: readonly HostEntry[];
  /** The host being edited, so it is not offered as its own jump host. */
  hostId: number | null;
  errors: { alias?: string; port?: string };
  autoFocus?: boolean;
}

/** Alias, address, user, port, key and jump host, plus the two common switches. */
export function HostFields({ form, set, hosts, hostId, errors, autoFocus }: HostFieldsProps) {
  const { t } = useTranslation();
  const keys = useKeys();
  const config = useConfig();
  const home = useEnvironment().data?.paths.home;

  const keyOptions: SelectOption[] = (keys.data?.keys ?? [])
    .filter((key) => key.privatePath)
    .map((key) => ({
      value: displayPath(key.privatePath ?? '', home),
      label: key.name,
      hint: algorithmBadge(key),
      icon: (
        <Tile tone={keyTone(key)} size={18}>
          <KeyRound className="size-[11px]" strokeWidth={2.5} />
        </Tile>
      ),
    }));
  if (form.identityFile && !keyOptions.some((o) => o.value === form.identityFile)) {
    // A key outside ~/.ssh is fine; only warn when the file really is gone.
    const missing = (config.data?.usage ?? []).some(
      (u) => u.raw === form.identityFile && u.resolved && !u.exists,
    );
    keyOptions.unshift({
      value: form.identityFile,
      label: form.identityFile,
      hint: missing ? t('hosts.missingKey') : undefined,
      icon: missing ? (
        <AlertTriangle aria-hidden="true" className="size-3.5 text-warning" strokeWidth={2} />
      ) : (
        <KeyRound aria-hidden="true" className="size-3.5 text-subtle" />
      ),
    });
  }
  const jumpOptions = hosts
    .filter((h) => h.kind === 'host' && !h.isWildcard && h.id !== hostId)
    .map((h) => h.patterns[0] ?? '')
    .filter(Boolean);
  if (form.proxyJump && !jumpOptions.includes(form.proxyJump)) jumpOptions.unshift(form.proxyJump);

  return (
    <>
      <div className="grid grid-cols-2 gap-3">
        <TextField
          label={t('hosts.alias')}
          mono
          value={form.patterns}
          onChange={(e) => set('patterns', e.target.value)}
          error={errors.alias}
          hint={t('hosts.aliasHint')}
          autoFocus={autoFocus}
          placeholder="prod"
        />
        <TextField
          label={t('hosts.hostName')}
          mono
          value={form.hostName}
          onChange={(e) => set('hostName', e.target.value)}
          hint={t('hosts.hostNameHint')}
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
        <Select
          label={t('hosts.identityFile')}
          mono
          value={form.identityFile || NONE}
          onValueChange={(next) => set('identityFile', next === NONE ? '' : next)}
          options={[
            {
              value: NONE,
              label: <span className="font-sans">{t('hosts.identityNone')}</span>,
              icon: <KeyRound aria-hidden="true" className="size-3.5 text-subtle" />,
            },
            ...keyOptions,
          ]}
        />
        <Select
          label={t('hosts.proxyJump')}
          mono
          value={form.proxyJump || NONE}
          onValueChange={(next) => set('proxyJump', next === NONE ? '' : next)}
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
      </div>

      <SwitchGroup>
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
        <SwitchRow
          label={
            <>
              {t('hosts.forwardAgent')}{' '}
              <span className="font-mono text-[11.5px] text-subtle">ForwardAgent</span>
            </>
          }
          hint={t('hosts.forwardAgentHint')}
          checked={form.forwardAgent}
          onCheckedChange={(value) => set('forwardAgent', value)}
        />
      </SwitchGroup>
    </>
  );
}

interface ConfigPreviewProps {
  lines: { key: string; value: string; header: boolean }[];
  className?: string;
}

/** The block as it will appear in `~/.ssh/config`, syntax-coloured. */
export function ConfigPreview({ lines, className }: ConfigPreviewProps) {
  return (
    <div
      className={cn(
        'selectable overflow-x-auto rounded-[14px] border border-white/[0.06] bg-black/40 p-3.5 font-mono text-[12px] leading-[21px]',
        className,
      )}
    >
      {lines.map((line, index) => (
        // biome-ignore lint/suspicious/noArrayIndexKey: preview lines are positional
        <div key={index} className="whitespace-pre">
          {line.header ? '' : '    '}
          <span className={line.header ? 'text-violet-300' : 'text-blue-300'}>{line.key}</span>{' '}
          <span className={line.header ? 'text-white' : 'text-fg'}>{line.value}</span>
        </div>
      ))}
    </div>
  );
}
