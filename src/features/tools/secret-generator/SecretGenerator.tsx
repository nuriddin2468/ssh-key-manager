import { useMutation } from '@tanstack/react-query';
import {
  Archive,
  Binary,
  Braces,
  Copy,
  Database,
  Gem,
  Hash,
  IdCard,
  KeyRound,
  type LucideIcon,
  RefreshCw,
  ShieldEllipsis,
  SquareTerminal,
  TextCursorInput,
  TrainFront,
  Wifi,
} from 'lucide-react';
import { RadioGroup } from 'radix-ui';
import { useEffect, useId, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useVaultStatus } from '@/api/queries';
import { toastError } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import { useRouter } from '@/app/router';
import type { GeneratedSecret } from '@/bindings/GeneratedSecret';
import { Button } from '@/components/ui/Button';
import { Dialog } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { Select } from '@/components/ui/Select';
import { TextField } from '@/components/ui/TextField';
import { Tile, type Tone } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { ConnectionBuilder } from './ConnectionBuilder';
import { RangeField, Segmented } from './controls';
import {
  type Choices,
  COPY_FORMATS,
  type Connection,
  type CopyFormat,
  connectionString,
  DATABASES,
  DEFAULT_CHOICES,
  EMPTY_CONNECTION,
  formatForCopy,
  isVariableName,
  PRESET_GROUPS,
  type PresetId,
  presetOf,
  RANGES,
  VARIABLE,
} from './model';
import { SaveDialog } from './SaveDialog';

const LOOK: Record<PresetId, { icon: LucideIcon; tone: Tone }> = {
  databasePassword: { icon: Database, tone: 'blue' },
  shellPassword: { icon: SquareTerminal, tone: 'green' },
  envPassword: { icon: Braces, tone: 'amber' },
  wifiPassword: { icon: Wifi, tone: 'cyan' },
  passphrase: { icon: TextCursorInput, tone: 'violet' },
  pin: { icon: Hash, tone: 'slate' },
  apiToken: { icon: KeyRound, tone: 'teal' },
  jwtSecret: { icon: ShieldEllipsis, tone: 'indigo' },
  uuid: { icon: IdCard, tone: 'aurora' },
  laravelAppKey: { icon: Binary, tone: 'rose' },
  djangoSecretKey: { icon: Gem, tone: 'green' },
  railsSecretKeyBase: { icon: TrainFront, tone: 'pink' },
};

// The last choices (never a secret), for the next time the tool opens.
let remembered: {
  id: PresetId;
  choices: Choices;
  format: CopyFormat;
  connection: Connection;
} = {
  id: 'databasePassword',
  choices: DEFAULT_CHOICES,
  format: 'raw',
  connection: EMPTY_CONNECTION,
};

/**
 * Secrets for one job each. The value comes from Rust's CSPRNG and goes to
 * the clipboard through Rust again, which keeps it out of clipboard history
 * and clears it.
 */
export function SecretGenerator() {
  const { t } = useTranslation();
  const [id, setId] = useState(remembered.id);
  const [choices, setChoices] = useState(remembered.choices);
  const [format, setFormat] = useState(remembered.format);
  const [connection, setConnection] = useState(remembered.connection);
  const [names, setNames] = useState<Partial<Record<PresetId, string>>>({});
  const [round, setRound] = useState(0);
  const [generated, setGenerated] = useState<GeneratedSecret | null>(null);
  const [saving, setSaving] = useState(false);
  const listId = useId();

  useEffect(() => {
    remembered = { id, choices, format, connection };
  }, [id, choices, format, connection]);

  const preset = useMemo(() => presetOf(id, choices), [id, choices]);
  useEffect(() => {
    let current = true;
    void round;
    api
      .toolsGenerateSecret(preset)
      .then((secret) => {
        if (current) setGenerated(secret);
      })
      .catch((error: unknown) => {
        if (current) setGenerated(null);
        toastError(t, error);
      });
    return () => {
      current = false;
    };
  }, [preset, round, t]);

  const name = names[id] ?? VARIABLE[id];
  const nameInvalid = format !== 'raw' && !isVariableName(name);
  const value = generated?.value ?? '';
  const text = value ? formatForCopy(format, name, value) : '';

  const copy = useMutation({
    mutationFn: api.toolsCopySecret,
    // The variables hold the secret: drop them once nothing shows them.
    gcTime: 0,
    onSuccess: (result) =>
      toast.success(t('toolGenerator.copied'), {
        id: 'tools-copy',
        description:
          result.clearsInSecs !== null
            ? t('passwords.clearsIn', { seconds: result.clearsInSecs })
            : undefined,
      }),
    onError: (error) => toastError(t, error),
  });

  const presetText = (preset: PresetId) => ({
    title: t(`toolGenerator.presets.${preset}.title`),
    hint: t(`toolGenerator.presets.${preset}.hint`),
    about: t(`toolGenerator.presets.${preset}.about`),
  });
  const current = presetText(id);
  const Icon = LOOK[id].icon;

  return (
    // Two columns where the panel has room, else the presets above.
    <div className="@container max-w-[1080px]">
      <div className="grid items-start gap-4 @[780px]:grid-cols-[250px_minmax(0,1fr)]">
        <RadioGroup.Root
          aria-labelledby={listId}
          value={id}
          onValueChange={(next) => setId(next as PresetId)}
          className="glass grid grid-cols-2 gap-3 rounded-2xl p-2.5 @[780px]:flex @[780px]:flex-col"
        >
          <span id={listId} className="sr-only">
            {t('toolGenerator.presetsLabel')}
          </span>
          {PRESET_GROUPS.map((group) => (
            <fieldset key={group.id} className="flex flex-col gap-0.5">
              <legend className="px-2 pt-1 pb-[5px] text-[11px] font-semibold text-subtle">
                {t(`toolGenerator.groups.${group.id}`)}
              </legend>
              {group.presets.map((preset) => {
                const look = LOOK[preset];
                const PresetIcon = look.icon;
                const text = presetText(preset);
                return (
                  <RadioGroup.Item
                    key={preset}
                    value={preset}
                    aria-label={`${text.title}. ${text.hint}`}
                    className={cn(
                      'pressable-soft flex items-center gap-2.5 rounded-xl px-2 py-1.5 text-left outline-none',
                      'focus-visible:shadow-[0_0_0_2px_rgb(var(--focus-rgb)/var(--edge-alpha))]',
                      id === preset ? 'selected-row' : 'hover:bg-ink/[0.05]',
                    )}
                  >
                    <Tile tone={look.tone} size={28}>
                      <PresetIcon className="size-[14px]" strokeWidth={2} />
                    </Tile>
                    <span className="flex min-w-0 flex-col">
                      <span className="text-[13px] leading-[18px] font-medium">{text.title}</span>
                      <span className="text-[11.5px] leading-4 text-subtle">{text.hint}</span>
                    </span>
                  </RadioGroup.Item>
                );
              })}
            </fieldset>
          ))}
        </RadioGroup.Root>

        <div className="flex min-w-0 flex-col gap-4">
          <section
            aria-labelledby={`${listId}-title`}
            className="glass flex flex-col gap-4 rounded-2xl p-4"
          >
            <header className="flex items-start gap-3">
              <Tile tone={LOOK[id].tone} size={40} glow>
                <Icon className="size-5" strokeWidth={2} />
              </Tile>
              <div className="flex min-w-0 flex-col gap-0.5">
                <h2 id={`${listId}-title`} className="text-[15px] leading-5 font-semibold">
                  {current.title}
                </h2>
                <p className="text-[12.5px] leading-[18px] text-muted">{current.about}</p>
              </div>
            </header>

            <div className="flex flex-col gap-1.5">
              <div className="flex min-h-[52px] items-center gap-2 rounded-xl border border-line bg-shade/35 py-2 pr-1.5 pl-3">
                <span className="sr-only">{t('toolGenerator.output')}: </span>
                <span className="selectable min-w-0 flex-1 font-mono text-[15px] leading-[22px] font-medium [overflow-wrap:anywhere] text-fg">
                  {value || ' '}
                </span>
                <IconButton
                  label={t('toolGenerator.regenerate')}
                  icon={<RefreshCw className="size-[15px]" strokeWidth={1.9} />}
                  onClick={() => setRound((n) => n + 1)}
                />
              </div>
              {generated ? (
                <p className="px-1 text-[12px] text-subtle">
                  {t('toolGenerator.bits', { bits: generated.bits })} ·{' '}
                  {t('toolGenerator.characters', { count: [...generated.value].length })}
                </p>
              ) : null}
            </div>

            <Options id={id} choices={choices} onChange={setChoices} />

            <div className="flex flex-col gap-3 border-t border-line-soft pt-4">
              <div className="flex flex-wrap items-start gap-2.5">
                <Select
                  label={t('toolGenerator.copyAs')}
                  value={format}
                  onValueChange={(next) => setFormat(next as CopyFormat)}
                  options={COPY_FORMATS.map((value) => ({
                    value,
                    label: t(`toolGenerator.formats.${value}`),
                  }))}
                  className="w-[200px]"
                />
                {format !== 'raw' ? (
                  <TextField
                    label={t('toolGenerator.variable')}
                    mono
                    value={name}
                    onChange={(event) => setNames({ ...names, [id]: event.target.value })}
                    error={nameInvalid ? t('toolGenerator.variableInvalid') : undefined}
                    className="min-w-[180px] flex-1"
                  />
                ) : null}
              </div>
              {format !== 'raw' && text ? (
                <div className="flex flex-col gap-1">
                  <span className="text-[12px] font-semibold text-fg-2">
                    {t('toolGenerator.preview')}
                  </span>
                  <code className="selectable rounded-lg border border-line-soft bg-shade/25 px-2.5 py-1.5 font-mono text-[12px] leading-[18px] text-fg-2 [overflow-wrap:anywhere]">
                    {text}
                  </code>
                </div>
              ) : null}
              <div className="flex flex-wrap items-center gap-2.5">
                <Button
                  variant="primary"
                  icon={<Copy aria-hidden="true" className="size-4" strokeWidth={2} />}
                  disabled={!text || nameInvalid}
                  loading={copy.isPending}
                  onClick={() => copy.mutate(text)}
                >
                  {t('toolGenerator.copy')}
                </Button>
                <SaveButton disabled={!value} onSave={() => setSaving(true)} />
              </div>
            </div>
          </section>

          {id === 'databasePassword' ? (
            <ConnectionBuilder password={value} connection={connection} onChange={setConnection} />
          ) : null}
        </div>

        <Dialog
          open={saving && value !== ''}
          onOpenChange={(open) => (open ? undefined : setSaving(false))}
        >
          {saving && value ? (
            <SaveDialog
              secret={value}
              initialTitle={
                id === 'databasePassword' && connection.host.trim()
                  ? `${DATABASES[connection.kind].label} · ${connection.host.trim()}`
                  : current.title
              }
              initialUser={id === 'databasePassword' ? connection.user.trim() : ''}
              notes={
                id === 'databasePassword' && connection.host.trim()
                  ? connectionString(connection, null)
                  : ''
              }
              onDone={() => setSaving(false)}
            />
          ) : null}
        </Dialog>
      </div>
    </div>
  );
}

/** What can be changed about the preset: its length, encoding or version. */
function Options({
  id,
  choices,
  onChange,
}: {
  id: PresetId;
  choices: Choices;
  onChange: (choices: Choices) => void;
}) {
  const { t } = useTranslation();
  switch (id) {
    case 'databasePassword':
    case 'shellPassword':
    case 'envPassword':
      return (
        <RangeField
          label={t('toolGenerator.length')}
          value={choices.length[id]}
          {...RANGES.length}
          onChange={(length) =>
            onChange({ ...choices, length: { ...choices.length, [id]: length } })
          }
        />
      );
    case 'apiToken':
    case 'jwtSecret':
      return (
        <Segmented
          label={t('toolGenerator.encoding')}
          value={choices.encoding[id]}
          onValueChange={(encoding) =>
            onChange({ ...choices, encoding: { ...choices.encoding, [id]: encoding } })
          }
          options={(['base64url', 'hex'] as const).map((value) => ({
            value,
            label: t(`toolGenerator.encodings.${value}`),
          }))}
        />
      );
    case 'uuid':
      return (
        <Segmented
          label={t('toolGenerator.version')}
          value={choices.version}
          onValueChange={(version) => onChange({ ...choices, version })}
          options={(['v4', 'v7'] as const).map((value) => ({
            value,
            label: t(`toolGenerator.versions.${value}`),
          }))}
        />
      );
    case 'wifiPassword':
      return (
        <RangeField
          label={t('toolGenerator.groupCount')}
          value={choices.groups}
          {...RANGES.groups}
          onChange={(groups) => onChange({ ...choices, groups })}
        />
      );
    case 'passphrase':
      return (
        <RangeField
          label={t('toolGenerator.words')}
          value={choices.words}
          {...RANGES.words}
          onChange={(words) => onChange({ ...choices, words })}
        />
      );
    case 'pin':
      return (
        <RangeField
          label={t('toolGenerator.digits')}
          value={choices.digits}
          {...RANGES.digits}
          onChange={(digits) => onChange({ ...choices, digits })}
        />
      );
    default:
      return null;
  }
}

/**
 * "Save to vault": straight to the dialog when the vault is open, through
 * unlocking it when it is locked; without a vault, a pointer to make one.
 */
function SaveButton({ disabled, onSave }: { disabled: boolean; onSave: () => void }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const { unlockVault } = useDialogs();
  const state = useVaultStatus().data?.state;
  const icon = <Archive aria-hidden="true" className="size-4" strokeWidth={1.9} />;
  if (state === 'missing') {
    return (
      <span className="flex flex-wrap items-center gap-2 text-[12.5px] text-muted">
        <Button icon={icon} disabled>
          {t('toolGenerator.saveToVault')}
        </Button>
        <button
          type="button"
          onClick={() => navigate({ page: 'passwords' })}
          className="text-left underline decoration-ink/30 underline-offset-2 hover:text-fg"
        >
          {t('toolGenerator.noVault')}
        </button>
      </span>
    );
  }
  return (
    <Button
      icon={icon}
      disabled={disabled || state === undefined}
      onClick={() =>
        state === 'unlocked'
          ? onSave()
          : unlockVault({ description: t('toolGenerator.unlockToSave'), onUnlocked: onSave })
      }
    >
      {t('toolGenerator.saveToVault')}
    </Button>
  );
}
