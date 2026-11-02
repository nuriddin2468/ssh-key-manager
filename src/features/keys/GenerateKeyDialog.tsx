import { KeyRound, Plus } from 'lucide-react';
import { RadioGroup } from 'radix-ui';
import { type FormEvent, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useAgent, useEnvironment, useKeys } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { EcdsaCurve } from '@/bindings/EcdsaCurve';
import type { GenerateAlgorithm } from '@/bindings/GenerateAlgorithm';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { PassphraseFields } from '@/components/ui/PassphraseFields';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { TextField } from '@/components/ui/TextField';
import { Tile, type Tone } from '@/components/ui/Tile';
import { cn } from '@/lib/cn';
import { useSettings } from '@/lib/settings';
import { FILE_NAME_PATTERN, suggestFileName } from './model';

type Algo = 'ed25519' | 'rsa' | 'ecdsa';

const ALGOS: { id: Algo; tone: Tone; base: string }[] = [
  { id: 'ed25519', tone: 'teal', base: 'id_ed25519' },
  { id: 'rsa', tone: 'amber', base: 'id_rsa' },
  { id: 'ecdsa', tone: 'blue', base: 'id_ecdsa' },
];

const CURVE_BITS: Record<EcdsaCurve, number> = { p256: 256, p384: 384, p521: 521 };

export function GenerateKeyDialog({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const settings = useSettings();
  const environment = useEnvironment();
  const keys = useKeys();
  const agent = useAgent();

  const taken = useMemo(() => {
    const names = new Set<string>();
    for (const key of keys.data?.keys ?? []) {
      names.add(key.name);
      for (const path of [key.privatePath, key.publicPath]) {
        const file = path?.split(/[\\/]/).pop();
        if (file) names.add(file.replace(/\.pub$/, ''));
      }
    }
    return names;
  }, [keys.data]);

  const [algo, setAlgo] = useState<Algo>(settings.defaultAlgorithm);
  const [bits, setBits] = useState(4096);
  const [curve, setCurve] = useState<EcdsaCurve>('p256');
  const [customName, setCustomName] = useState<string | null>(null);
  const [comment, setComment] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [repeat, setRepeat] = useState('');
  const [addToAgent, setAddToAgent] = useState(true);
  const [addHost, setAddHost] = useState(false);
  const [alias, setAlias] = useState('');
  const [hostName, setHostName] = useState('');
  const [user, setUser] = useState('');

  const base = ALGOS.find((a) => a.id === algo)?.base ?? 'id_ed25519';
  const fileName = customName ?? suggestFileName(base, taken);
  const commentValue = comment ?? environment.data?.defaultComment ?? '';
  const agentAvailable = agent.data?.status.available ?? false;

  const nameError = !FILE_NAME_PATTERN.test(fileName)
    ? t('generate.fileNameInvalid')
    : taken.has(fileName)
      ? t('generate.fileNameTaken')
      : undefined;
  const mismatch = passphrase !== repeat;
  const hostInvalid = addHost && alias.trim() === '';

  const algorithm: GenerateAlgorithm =
    algo === 'rsa'
      ? { kind: 'rsa', bits }
      : algo === 'ecdsa'
        ? { kind: 'ecdsa', curve }
        : { kind: 'ed25519' };

  const command = [
    'ssh-keygen',
    algo === 'rsa'
      ? `-t rsa -b ${bits}`
      : algo === 'ecdsa'
        ? `-t ecdsa -b ${CURVE_BITS[curve]}`
        : '-t ed25519',
    `-f ~/.ssh/${fileName || '…'}`,
    `-C "${commentValue}"`,
  ].join(' ');

  const generate = useAppMutation(api.generateKey, {
    success: (key) => t('generate.created', { name: key.name }),
    onSuccess: (key) => {
      navigate({ page: 'keys', keyId: key.id });
      onDone();
    },
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (nameError || mismatch || hostInvalid || generate.isPending) return;
    generate.mutate({
      key: { algorithm, fileName, comment: commentValue.trim(), passphrase: passphrase || null },
      addToAgent: addToAgent && agentAvailable,
      agentLifetimeSecs: settings.defaultLifetime,
      host: addHost
        ? { alias: alias.trim(), hostName: hostName.trim() || null, user: user.trim() || null }
        : null,
    });
  };

  return (
    <DialogContent section="keys">
      <form onSubmit={submit} className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone="teal" size={44} glow>
              <Plus className="size-[22px]" strokeWidth={2} />
            </Tile>
          }
          title={t('generate.title')}
          description={t('generate.description')}
        />
        <DialogBody>
          <fieldset className="flex flex-col">
            <legend className="mb-2.5 text-[12px] font-semibold tracking-[0.02em] text-subtle">
              {t('generate.keyType')}
            </legend>
            <RadioGroup.Root
              value={algo}
              onValueChange={(value) => setAlgo(value as Algo)}
              className="grid grid-cols-3 gap-2.5"
            >
              {ALGOS.map((option) => (
                <RadioGroup.Item
                  key={option.id}
                  value={option.id}
                  className={cn(
                    'pressable-soft flex flex-col items-start gap-2.5 rounded-[14px] border p-[13px] text-left',
                    algo === option.id
                      ? 'border-[rgb(45_212_191/0.6)] bg-[rgb(45_212_191/0.08)] shadow-[0_0_0_3px_rgb(45_212_191/0.14),0_14px_30px_-18px_rgb(45_212_191/0.8)]'
                      : 'border-white/[0.09] bg-white/[0.03] hover:bg-white/[0.05]',
                  )}
                >
                  <Tile tone={option.tone} size={36}>
                    <KeyRound className="size-[18px]" strokeWidth={2} />
                  </Tile>
                  <span className="flex flex-col gap-0.5">
                    <span className="flex flex-wrap items-center gap-1.5 font-semibold">
                      {t(`generate.${option.id}`)}
                      {option.id === 'ed25519' ? (
                        <Badge tone="accent" pill>
                          {t('generate.recommended')}
                        </Badge>
                      ) : null}
                    </span>
                    <span className="text-[12px] leading-[17px] text-muted">
                      {t(`generate.${option.id}Hint`)}
                    </span>
                  </span>
                </RadioGroup.Item>
              ))}
            </RadioGroup.Root>

            {algo === 'rsa' ? (
              <SizePicker
                label={t('generate.keySize')}
                options={[3072, 4096].map((value) => ({
                  value: String(value),
                  label: t('generate.bits', { bits: value }),
                }))}
                value={String(bits)}
                onChange={(value) => setBits(Number(value))}
              />
            ) : null}
            {algo === 'ecdsa' ? (
              <SizePicker
                label={t('generate.curve')}
                options={(['p256', 'p384', 'p521'] as const).map((value) => ({
                  value,
                  label: `P-${CURVE_BITS[value]}`,
                }))}
                value={curve}
                onChange={(value) => setCurve(value as EcdsaCurve)}
              />
            ) : null}
          </fieldset>

          <div className="grid grid-cols-2 gap-3.5">
            <TextField
              label={t('generate.fileName')}
              prefix="~/.ssh/"
              mono
              value={fileName}
              onChange={(event) => setCustomName(event.target.value)}
              error={nameError}
              hint={t('generate.fileNameHint', { name: fileName })}
            />
            <TextField
              label={t('generate.comment')}
              value={commentValue}
              onChange={(event) => setComment(event.target.value)}
              hint={t('generate.commentHint')}
            />
            <PassphraseFields
              value={passphrase}
              repeat={repeat}
              onChange={setPassphrase}
              onRepeatChange={setRepeat}
            />
          </div>
          {passphrase === '' ? (
            <p className="-mt-2 text-[12px] text-warning">{t('generate.noPassphrase')}</p>
          ) : null}

          <fieldset className="flex flex-col">
            <legend className="mb-2 text-[12px] font-semibold tracking-[0.02em] text-subtle">
              {t('generate.afterCreating')}
            </legend>
            <SwitchGroup>
              <SwitchRow
                label={t('generate.addToAgent')}
                hint={agentAvailable ? t('generate.addToAgentHint') : t('agent.stoppedTitle')}
                checked={addToAgent && agentAvailable}
                disabled={!agentAvailable}
                onCheckedChange={setAddToAgent}
              />
              <SwitchRow
                label={t('generate.addHost')}
                hint={t('generate.addHostHint')}
                checked={addHost}
                onCheckedChange={setAddHost}
              />
              {addHost ? (
                <div className="grid grid-cols-3 gap-2.5 px-2.5 pb-2">
                  <TextField
                    label={t('generate.hostAlias')}
                    mono
                    value={alias}
                    onChange={(event) => setAlias(event.target.value)}
                    placeholder="github.com"
                    autoFocus
                  />
                  <TextField
                    label={t('generate.hostName')}
                    mono
                    value={hostName}
                    onChange={(event) => setHostName(event.target.value)}
                    placeholder={alias || 'example.com'}
                  />
                  <TextField
                    label={t('generate.user')}
                    mono
                    value={user}
                    onChange={(event) => setUser(event.target.value)}
                    placeholder="git"
                  />
                </div>
              ) : null}
            </SwitchGroup>
          </fieldset>

          <div className="flex flex-col gap-1.5">
            <span className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
              {t('generate.command')}
            </span>
            <code className="selectable block rounded-xl border border-white/[0.06] bg-black/40 px-[13px] py-[11px] font-mono text-[12px] leading-[18px] break-all text-fg-2">
              <span className="text-ok">$</span> {command}
            </code>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={onDone}>
            {t('common.cancel')}
          </Button>
          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={generate.isPending}
            disabled={Boolean(nameError) || mismatch || hostInvalid}
            icon={<KeyRound className="size-4" strokeWidth={2} />}
          >
            {t('generate.submit')}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

interface SizePickerProps {
  label: string;
  options: { value: string; label: string }[];
  value: string;
  onChange: (value: string) => void;
}

function SizePicker({ label, options, value, onChange }: SizePickerProps) {
  return (
    <div className="flex items-center gap-2 pt-3">
      <span id="size-label" className="text-[12.5px] text-muted">
        {label}
      </span>
      <RadioGroup.Root
        aria-labelledby="size-label"
        value={value}
        onValueChange={onChange}
        className="flex gap-1.5"
      >
        {options.map((option) => (
          <RadioGroup.Item
            key={option.value}
            value={option.value}
            className={cn(
              'pressable h-7 rounded-full border px-[11px] font-mono text-[12px] font-medium',
              option.value === value
                ? 'border-[rgb(var(--accent-rgb)/0.55)] bg-[rgb(var(--accent-rgb)/0.12)] text-[var(--accent-text)]'
                : 'border-white/10 bg-white/[0.04] text-fg-2 hover:bg-white/[0.07]',
            )}
          >
            {option.label}
          </RadioGroup.Item>
        ))}
      </RadioGroup.Root>
    </div>
  );
}
