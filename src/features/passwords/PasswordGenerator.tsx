import { Dices, RefreshCw } from 'lucide-react';
import { Popover, RadioGroup } from 'radix-ui';
import { type ReactNode, useEffect, useId, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { IconButton } from '@/components/ui/IconButton';
import { Select } from '@/components/ui/Select';
import { cn } from '@/lib/cn';
import {
  CHARACTER_CLASSES,
  canToggleClass,
  clamp,
  DEFAULT_PASSPHRASE,
  DEFAULT_PASSWORD,
  PASSPHRASE_WORDS,
  PASSWORD_LENGTH,
  type PassphraseOptions,
  type PasswordOptions,
} from './model';
import { StrengthMeter, useStrength } from './StrengthMeter';

type Mode = 'password' | 'passphrase';

// The last choices, for the next time the generator opens in this session.
let remembered: { mode: Mode; password: PasswordOptions; passphrase: PassphraseOptions } = {
  mode: 'password',
  password: DEFAULT_PASSWORD,
  passphrase: DEFAULT_PASSPHRASE,
};

const SAMPLES = { lowercase: 'a–z', uppercase: 'A–Z', digits: '0–9', symbols: '!#$%' } as const;
const SEPARATORS = [
  { value: '-', key: 'separatorHyphen' },
  { value: ' ', key: 'separatorSpace' },
  { value: '.', key: 'separatorDot' },
  { value: '_', key: 'separatorUnderscore' },
  { value: '', key: 'separatorNone' },
] as const;

/** The generator button for a password field; its popover fills the field on "Use". */
export function PasswordGenerator({ onUse }: { onUse: (password: string) => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  return (
    <Popover.Root open={open} onOpenChange={setOpen}>
      <Popover.Trigger asChild>
        <IconButton
          label={t('passwords.generate')}
          icon={<Dices className="size-[15px]" strokeWidth={1.9} />}
          size="sm"
          className="size-7 rounded-md"
        />
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          sideOffset={8}
          collisionPadding={12}
          aria-label={t('passwords.generator')}
          className="z-50 w-[320px] origin-[var(--radix-popover-content-transform-origin)] rounded-2xl border border-white/10 bg-[rgb(22_27_39/0.97)] text-fg shadow-[0_24px_48px_-16px_rgb(0_0_0/0.75),inset_0_1px_0_rgb(255_255_255/0.06)] backdrop-blur-xl data-[state=closed]:animate-popover-out data-[state=open]:animate-popover-in"
        >
          {open ? (
            <GeneratorPanel
              onUse={(password) => {
                onUse(password);
                setOpen(false);
              }}
            />
          ) : null}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

function GeneratorPanel({ onUse }: { onUse: (password: string) => void }) {
  const { t } = useTranslation();
  const [mode, setMode] = useState<Mode>(remembered.mode);
  const [password, setPassword] = useState(remembered.password);
  const [passphrase, setPassphrase] = useState(remembered.passphrase);
  const [preview, setPreview] = useState('');
  const [round, setRound] = useState(0);
  const strength = useStrength(preview);
  const options = mode === 'password' ? password : passphrase;

  useEffect(() => {
    remembered = { mode, password, passphrase };
  }, [mode, password, passphrase]);

  useEffect(() => {
    let current = true;
    void round;
    api
      .vaultGenerate(options)
      .then((value) => {
        if (current) setPreview(value);
      })
      .catch(() => {
        if (current) setPreview('');
      });
    return () => {
      current = false;
    };
  }, [options, round]);

  return (
    <div className="flex flex-col gap-3.5 p-3.5">
      <RadioGroup.Root
        aria-label={t('passwords.modeLabel')}
        value={mode}
        onValueChange={(value) => setMode(value as Mode)}
        className="grid grid-cols-2 gap-1 rounded-[10px] border border-white/[0.08] bg-black/25 p-[3px]"
      >
        {(['password', 'passphrase'] as const).map((value) => (
          <RadioGroup.Item
            key={value}
            value={value}
            className={cn(
              'pressable h-7 rounded-[7px] text-[12.5px] font-medium',
              mode === value
                ? 'bg-white/[0.12] text-fg shadow-[0_1px_2px_rgb(0_0_0/0.4)]'
                : 'text-muted hover:text-fg',
            )}
          >
            {value === 'password' ? t('passwords.modePassword') : t('passwords.modePassphrase')}
          </RadioGroup.Item>
        ))}
      </RadioGroup.Root>

      <div className="flex flex-col gap-2">
        <div className="flex min-h-[52px] items-center gap-2 rounded-xl border border-white/[0.08] bg-black/35 py-2 pr-1.5 pl-3">
          <span className="sr-only">{t('passwords.preview')}: </span>
          <span className="selectable min-w-0 flex-1 font-mono text-[13px] leading-[19px] [overflow-wrap:anywhere] text-fg">
            {preview || ' '}
          </span>
          <IconButton
            label={t('passwords.regenerate')}
            icon={<RefreshCw className="size-[15px]" strokeWidth={1.9} />}
            onClick={() => setRound((n) => n + 1)}
          />
        </div>
        <StrengthMeter strength={strength} />
      </div>

      {mode === 'password' ? (
        <>
          <NumberSlider
            label={t('passwords.length')}
            value={password.length}
            min={PASSWORD_LENGTH.min}
            max={PASSWORD_LENGTH.max}
            sliderMax={PASSWORD_LENGTH.slider}
            onChange={(length) => setPassword({ ...password, length })}
          />
          <fieldset className="flex flex-col gap-2">
            <legend className="mb-2 text-[12px] font-semibold text-fg-2">
              {t('passwords.characters')}
            </legend>
            <div className="grid grid-cols-4 gap-2">
              {CHARACTER_CLASSES.map((name) => (
                <Checkbox
                  key={name}
                  label={<span className="font-mono text-[12.5px]">{SAMPLES[name]}</span>}
                  aria-label={t(`passwords.${name}`)}
                  checked={password[name]}
                  disabled={!canToggleClass(password, name)}
                  onCheckedChange={(checked) => setPassword({ ...password, [name]: checked })}
                />
              ))}
            </div>
            <Checkbox
              label={<span className="text-[12.5px]">{t('passwords.avoidAmbiguous')}</span>}
              checked={password.avoidAmbiguous}
              onCheckedChange={(avoidAmbiguous) => setPassword({ ...password, avoidAmbiguous })}
            />
          </fieldset>
        </>
      ) : (
        <>
          <NumberSlider
            label={t('passwords.words')}
            value={passphrase.words}
            min={PASSPHRASE_WORDS.min}
            max={PASSPHRASE_WORDS.max}
            onChange={(words) => setPassphrase({ ...passphrase, words })}
          />
          <Select
            label={t('passwords.separator')}
            size="sm"
            value={passphrase.separator === '' ? 'none' : passphrase.separator}
            onValueChange={(value) =>
              setPassphrase({ ...passphrase, separator: value === 'none' ? '' : value })
            }
            options={SEPARATORS.map((separator) => ({
              value: separator.value === '' ? 'none' : separator.value,
              label: t(`passwords.${separator.key}`),
              hint: separator.value.trim() ? (
                <span className="font-mono">{separator.value}</span>
              ) : undefined,
            }))}
          />
          <div className="flex flex-col gap-2">
            <Checkbox
              label={<span className="text-[12.5px]">{t('passwords.capitalize')}</span>}
              checked={passphrase.capitalize}
              onCheckedChange={(capitalize) => setPassphrase({ ...passphrase, capitalize })}
            />
            <Checkbox
              label={<span className="text-[12.5px]">{t('passwords.addNumber')}</span>}
              checked={passphrase.number}
              onCheckedChange={(number) => setPassphrase({ ...passphrase, number })}
            />
          </div>
        </>
      )}

      <Button
        variant="primary"
        className="w-full"
        disabled={!preview}
        onClick={() => onUse(preview)}
      >
        {t('passwords.use')}
      </Button>
    </div>
  );
}

interface NumberSliderProps {
  label: ReactNode;
  value: number;
  min: number;
  max: number;
  /** The slider can stop short of `max`; the number field still reaches it. */
  sliderMax?: number;
  onChange: (value: number) => void;
}

function NumberSlider({ label, value, min, max, sliderMax = max, onChange }: NumberSliderProps) {
  const id = useId();
  const [text, setText] = useState(String(value));
  useEffect(() => setText(String(value)), [value]);

  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between">
        <label
          id={`${id}-label`}
          htmlFor={`${id}-range`}
          className="text-[12px] font-semibold text-fg-2"
        >
          {label}
        </label>
        <input
          aria-labelledby={`${id}-label`}
          type="number"
          inputMode="numeric"
          min={min}
          max={max}
          value={text}
          onChange={(event) => {
            setText(event.target.value);
            const next = Number(event.target.value);
            if (event.target.value !== '' && next >= min && next <= max) onChange(Math.round(next));
          }}
          onBlur={() => onChange(clamp(Number(text), min, max))}
          className="field h-7 w-14 rounded-md px-2 text-right font-mono text-[12.5px] tabular-nums outline-none focus:border-[rgb(var(--accent-rgb)/0.55)]"
        />
      </div>
      <input
        id={`${id}-range`}
        type="range"
        min={min}
        max={Math.max(sliderMax, Math.min(value, max))}
        value={value}
        onChange={(event) => onChange(Number(event.target.value))}
        className="h-4 w-full accent-[var(--accent-2)]"
      />
    </div>
  );
}
