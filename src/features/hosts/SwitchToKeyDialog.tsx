import { AlertTriangle, Check, CheckCircle2, KeyRound, Plus, XCircle } from 'lucide-react';
import { RadioGroup } from 'radix-ui';
import { type ReactNode, useCallback, useEffect, useId, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useConfig, useEnvironment, useKeys, useVaultEntries } from '@/api/queries';
import { useAppMutation } from '@/api/useAppMutation';
import { useDialogs } from '@/app/dialogs';
import type { ConnectionTest } from '@/bindings/ConnectionTest';
import type { HostEntry } from '@/bindings/HostEntry';
import type { KeyInstall } from '@/bindings/KeyInstall';
import type { KeyView } from '@/bindings/KeyView';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { SwitchGroup, SwitchRow } from '@/components/ui/Switch';
import { Tile } from '@/components/ui/Tile';
import { algorithmBadge, keyTone } from '@/features/keys/model';
import { findKeyEntry } from '@/features/keys/vaultKey';
import { cn } from '@/lib/cn';
import { displayPath } from '@/lib/format';
import { ConfigPreview } from './HostFields';
import { LoginResult } from './LoginResult';
import type { MessageAction } from './login';
import { formFromHost, pointHostAtKey, previewLines } from './model';
import { needsUnlock, preselectKey, usableKeys } from './switchKey';
import { vaultErrorMessage } from './vault';

const STEPS = ['key', 'install', 'config', 'verify', 'finish'] as const;
type Step = (typeof STEPS)[number];

interface SwitchToKeyDialogProps {
  /** The host as saved now; it changes when step 3 saves it. */
  host: HostEntry;
  /** The alias the saved password is for. */
  alias: string;
  /** The vault entry holding the password. */
  entryId: string;
  /** Fixes the editor offers for a login result (checking the host key, editing the password). */
  onAction: Partial<Record<MessageAction, () => void>>;
  /** The key file (as the config spells it) to choose first, e.g. the one picked in the editor. */
  initialKeyPath?: string;
  /** Step 3 wrote the host block. */
  onConfigSaved?: () => void;
  onDone: () => void;
}

/**
 * Moves a host from its saved password to a key: choose a key, install it
 * with the password, point the host at it, check the key alone gets in, and
 * keep or recycle the password. Each step waits for the user and can be
 * retried; closing early undoes nothing and says what was done.
 */
export function SwitchToKeyDialog({
  host,
  alias,
  entryId,
  onAction,
  initialKeyPath,
  onConfigSaved,
  onDone,
}: SwitchToKeyDialogProps) {
  const { t, i18n } = useTranslation();
  const dialogs = useDialogs();
  const keys = useKeys();
  const config = useConfig();
  const entries = useVaultEntries();
  const home = useEnvironment().data?.paths.home;

  const [step, setStep] = useState<Step>('key');
  const [chosenId, setChosenId] = useState<string | null>(null);
  const [created, setCreated] = useState<string | null>(null);
  const clearCreated = useCallback(() => setCreated(null), []);
  const [install, setInstall] = useState<{ keyId: string; result: KeyInstall } | null>(null);
  const [skipped, setSkipped] = useState<string | null>(null);
  const [configSaved, setConfigSaved] = useState(false);
  const [verify, setVerify] = useState<{ keyId: string; result: ConnectionTest } | null>(null);
  const [error, setError] = useState<{ step: Step; message: string } | null>(null);
  const [identitiesOnly, setIdentitiesOnly] = useState(true);
  const [keep, setKeep] = useState(true);

  const all = keys.data?.keys ?? [];
  const usable = usableKeys(all);
  const picked = initialKeyPath
    ? usable.find(
        (candidate) =>
          candidate.privatePath === initialKeyPath ||
          displayPath(candidate.privatePath ?? '', home) === initialKeyPath,
      )
    : undefined;
  const key =
    chosenId === null
      ? (picked ?? preselectKey(all, host.id))
      : (usable.find((candidate) => candidate.id === chosenId) ?? null);

  const file = key?.privatePath ? displayPath(key.privatePath, home) : '';
  const spellings = new Set(
    (config.data?.usage ?? [])
      .filter((usage) => usage.hostId === host.id && usage.path === key?.privatePath)
      .map((usage) => usage.raw),
  );
  const pointed = pointHostAtKey(host, file, {
    identitiesOnly,
    isKey: (raw) => raw === file || spellings.has(raw),
  });
  const hasIdentitiesOnly = formFromHost(host).identitiesOnly;

  const installTried = Boolean(key && install?.keyId === key.id) || error?.step === 'install';
  const installOk = Boolean(key && install?.keyId === key.id && install.result.ok);
  const verifyTried = Boolean(key && verify?.keyId === key.id) || error?.step === 'verify';
  const verifyOk = Boolean(key && verify?.keyId === key.id && verify.result.ok);
  const ready: Record<Step, boolean> = {
    key: key !== null,
    install: installOk || (key !== null && skipped === key.id),
    config: !pointed.changed,
    verify: verifyOk,
    finish: true,
  };
  const passphraseSaved = Boolean(key && findKeyEntry(entries.data, key.fingerprint));

  // Focus follows the step (each heading mounts focused), so screen readers
  // hear where they are; the first one takes it before the dialog would
  // focus its close button.
  const focusOnMount = useCallback((element: HTMLElement | null) => element?.focus(), []);

  // The primary button keeps focus while it works (it is never disabled), so
  // keyboard users can press it again to go on.
  const primary = useRef<HTMLDivElement>(null);
  const focusPrimary = () => primary.current?.querySelector<HTMLElement>('button')?.focus();

  // Closing early undoes nothing; say what is already done.
  const finished = useRef(false);
  const noteOnClose = useRef(() => {});
  noteOnClose.current = () => {
    if (finished.current) return;
    const steps: string[] = [];
    if (install?.result.ok) steps.push(t('hosts.vault.switch.doneInstalled'));
    if (configSaved) steps.push(t('hosts.vault.switch.doneConfig'));
    if (verify?.result.ok) steps.push(t('hosts.vault.switch.doneVerified'));
    if (steps.length === 0) return;
    toast.message(t('hosts.vault.switch.stopped', { alias }), {
      description: t('hosts.vault.switch.stoppedText', {
        steps: new Intl.ListFormat(i18n.language, { type: 'conjunction' }).format(steps),
      }),
    });
  };
  useEffect(() => () => noteOnClose.current(), []);

  const failed = (at: Step) => (cause: unknown) => {
    setError({ step: at, message: vaultErrorMessage(t, cause) });
    focusPrimary();
    return true;
  };
  const installKey = useAppMutation(
    (target: KeyView) => api.vaultInstallPublicKey(alias, target.id),
    {
      onSuccess: (result, target) => {
        setInstall({ keyId: target.id, result });
        focusPrimary();
      },
      onError: failed('install'),
    },
  );
  const saveConfig = useAppMutation(() => api.saveHost(pointed.edit), {
    onSuccess: () => {
      setConfigSaved(true);
      onConfigSaved?.();
      focusPrimary();
    },
    onError: failed('config'),
  });
  const testKey = useAppMutation(
    (target: KeyView) => api.vaultTestKeyLogin(alias).then((result) => ({ result, target })),
    {
      onSuccess: ({ result, target }) => {
        setVerify({ keyId: target.id, result });
        focusPrimary();
      },
      onError: failed('verify'),
    },
  );
  const finish = useAppMutation(
    async (trash: boolean) => {
      if (trash) await api.vaultTrash(entryId);
      return trash;
    },
    {
      success: (trash) =>
        t(trash ? 'hosts.vault.switch.finishedTrashed' : 'hosts.vault.switch.finished', {
          alias,
          key: key?.name ?? '',
        }),
      onSuccess: () => {
        finished.current = true;
        onDone();
      },
      onError: failed('finish'),
    },
  );
  const pending =
    installKey.isPending || saveConfig.isPending || testKey.isPending || finish.isPending;

  const index = STEPS.indexOf(step);
  const go = (next: Step) => {
    setError(null);
    setStep(next);
  };
  const run = (action: () => void) => {
    if (pending) return;
    setError(null);
    action();
  };

  // The primary button: do the step's action, then go on once it is done.
  let primaryLabel: string;
  let primaryAction: () => void;
  switch (step) {
    case 'key':
      primaryLabel = t('hosts.vault.switch.continue');
      primaryAction = () => {
        if (!key) return;
        setChosenId(key.id);
        go('install');
      };
      break;
    case 'install':
      if (ready.install) {
        primaryLabel = t('hosts.vault.switch.continue');
        primaryAction = () => go('config');
      } else {
        primaryLabel = installTried ? t('common.retry') : t('hosts.vault.switch.install');
        primaryAction = () => run(() => key && installKey.mutate(key));
      }
      break;
    case 'config':
      if (ready.config) {
        primaryLabel = t('hosts.vault.switch.continue');
        primaryAction = () => go('verify');
      } else {
        primaryLabel = t('hosts.vault.switch.saveConfig');
        primaryAction = () => run(() => saveConfig.mutate(undefined));
      }
      break;
    case 'verify':
      if (ready.verify) {
        primaryLabel = t('hosts.vault.switch.continue');
        primaryAction = () => go('finish');
      } else {
        primaryLabel = verifyTried ? t('common.retry') : t('hosts.vault.switch.verify');
        primaryAction = () => run(() => key && testKey.mutate(key));
      }
      break;
    case 'finish':
      primaryLabel = t('hosts.vault.switch.done');
      primaryAction = () => run(() => finish.mutate(!keep));
      break;
  }

  const keyName = key?.name ?? '';
  const progressText = t('hosts.vault.switch.progress', { step: index + 1, total: STEPS.length });
  const titles: Record<Step, string> = {
    key: t('hosts.vault.switch.keyTitle'),
    install: t('hosts.vault.switch.installTitle'),
    config: t('hosts.vault.switch.configTitle'),
    verify: t('hosts.vault.switch.verifyTitle'),
    finish: t('hosts.vault.switch.finishTitle'),
  };

  return (
    <DialogContent section="hosts" className="max-w-[580px]">
      <DialogHeader
        icon={
          <Tile tone="blue" size={44} glow>
            <KeyRound className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('hosts.vault.switch.title', { alias })}
        description={t('hosts.vault.switch.description')}
      />
      <DialogBody>
        <div className="flex flex-col gap-2">
          <div aria-hidden="true" className="grid grid-cols-5 gap-1">
            {STEPS.map((name, i) => (
              <span
                key={name}
                className={cn(
                  'h-1 rounded-sm',
                  i < index
                    ? 'bg-[linear-gradient(90deg,var(--accent-1),var(--accent-2))]'
                    : i === index
                      ? 'bg-[rgb(var(--accent-rgb)/0.45)]'
                      : 'bg-white/10',
                )}
              />
            ))}
          </div>
          {/* Read as part of the heading, which takes focus on every step. */}
          <p aria-hidden="true" className="text-[12px] text-subtle">
            {progressText}
          </p>
          <h3
            key={step}
            ref={focusOnMount}
            tabIndex={-1}
            className="text-[15px] leading-[22px] font-semibold tracking-[-0.01em] outline-none"
          >
            <span className="sr-only">{progressText}: </span>
            {titles[step]}
          </h3>
        </div>

        {step === 'key' ? (
          <KeyStep
            alias={alias}
            hostId={host.id}
            keys={usable}
            loading={keys.isPending}
            selected={key}
            onSelect={setChosenId}
            onCreate={() =>
              dialogs.generateKeyFor((made) => {
                setChosenId(made.id);
                setCreated(made.id);
              })
            }
            created={created}
            onShown={clearCreated}
          />
        ) : null}

        {step === 'install' ? (
          <>
            <Text>{t('hosts.vault.switch.installText', { alias, key: keyName })}</Text>
            <Live>
              {install && key && install.keyId === key.id ? (
                <LoginResult
                  run={install.result}
                  context="install"
                  alias={alias}
                  onAction={onAction}
                />
              ) : null}
              {error?.step === 'install' ? <ErrorBox>{error.message}</ErrorBox> : null}
            </Live>
          </>
        ) : null}

        {step === 'config' ? (
          <>
            <Text>{t('hosts.vault.switch.configText', { alias, key: keyName })}</Text>
            {hasIdentitiesOnly ? null : (
              <SwitchGroup>
                <SwitchRow
                  label={
                    <>
                      {t('hosts.identitiesOnly')}{' '}
                      <span className="font-mono text-[11.5px] text-subtle">IdentitiesOnly</span>
                    </>
                  }
                  hint={t('hosts.vault.switch.identitiesOnlyHint')}
                  checked={identitiesOnly}
                  disabled={configSaved && !pointed.changed}
                  onCheckedChange={setIdentitiesOnly}
                />
              </SwitchGroup>
            )}
            <div className="flex flex-col gap-1.5">
              <span className="text-[12px] font-semibold tracking-[0.02em] text-subtle">
                {t('hosts.preview')}
              </span>
              <ConfigPreview lines={previewLines(pointed.edit)} />
            </div>
            <Live>
              {configSaved && !pointed.changed ? (
                <OkBox>{t('hosts.vault.switch.configSaved')}</OkBox>
              ) : !pointed.changed ? (
                <OkBox>{t('hosts.vault.switch.configUnchanged', { alias })}</OkBox>
              ) : null}
              {error?.step === 'config' ? <ErrorBox>{error.message}</ErrorBox> : null}
            </Live>
          </>
        ) : null}

        {step === 'verify' && key ? (
          <>
            <Text>{t('hosts.vault.switch.verifyText', { alias })}</Text>
            {needsUnlock(key, passphraseSaved) && !verifyOk ? (
              <div className="flex items-start gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5">
                <AlertTriangle
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0 text-warning"
                  strokeWidth={2}
                />
                <div className="flex min-w-0 flex-1 flex-col items-start gap-2">
                  <p className="text-[12.5px] leading-[18px] text-fg-2">
                    {t('hosts.vault.switch.needsUnlock', { key: key.name })}
                  </p>
                  <Button size="sm" onClick={() => dialogs.unlockKey(key)}>
                    {t('hosts.vault.switch.unlockKey')}
                  </Button>
                </div>
              </div>
            ) : null}
            {key.hardware && !verifyOk ? <Text>{t('hosts.vault.switch.touchKey')}</Text> : null}
            <Live>
              {verify && verify.keyId === key.id ? (
                <LoginResult
                  run={verify.result}
                  context="keyLogin"
                  alias={alias}
                  onAction={{ checkHostKey: onAction.checkHostKey }}
                />
              ) : null}
              {error?.step === 'verify' ? <ErrorBox>{error.message}</ErrorBox> : null}
            </Live>
          </>
        ) : null}

        {step === 'finish' ? (
          <>
            <OkBox>{t('hosts.vault.switch.finishText', { alias, key: keyName })}</OkBox>
            <ChoiceCards
              legend={titles.finish}
              legendHidden
              value={keep ? 'keep' : 'trash'}
              onValueChange={(value) => setKeep(value === 'keep')}
              columns={1}
              options={[
                {
                  value: 'keep',
                  title: t('hosts.vault.switch.keep'),
                  hint: t('hosts.vault.switch.keepHint'),
                },
                {
                  value: 'trash',
                  title: t('hosts.vault.switch.trash'),
                  hint: t('hosts.vault.switch.trashHint'),
                },
              ]}
            />
            <Live>{error?.step === 'finish' ? <ErrorBox>{error.message}</ErrorBox> : null}</Live>
          </>
        ) : null}
      </DialogBody>
      <DialogFooter>
        {index > 0 ? (
          <Button
            size="lg"
            variant="ghost"
            className="mr-auto"
            disabled={pending}
            onClick={() => go(STEPS[index - 1] ?? 'key')}
          >
            {t('hosts.vault.switch.back')}
          </Button>
        ) : null}
        {step === 'install' && !ready.install && installTried ? (
          <Button
            size="lg"
            disabled={pending}
            onClick={() => {
              if (!key) return;
              setSkipped(key.id);
              go('config');
            }}
          >
            {t('hosts.vault.switch.skip')}
          </Button>
        ) : null}
        <div ref={primary} className="contents">
          <Button
            variant="primary"
            size="lg"
            className="aria-disabled:opacity-50"
            aria-busy={pending || undefined}
            aria-disabled={pending || !ready.key || undefined}
            icon={pending ? <Spinner className="size-4" /> : undefined}
            onClick={() => {
              if (pending || !ready.key) return;
              primaryAction();
            }}
          >
            {primaryLabel}
          </Button>
        </div>
      </DialogFooter>
    </DialogContent>
  );
}

interface KeyStepProps {
  alias: string;
  hostId: number;
  keys: KeyView[];
  loading: boolean;
  selected: KeyView | null;
  onSelect: (id: string) => void;
  onCreate: () => void;
  /** A key just created: brought into view and focused once it is listed. */
  created: string | null;
  onShown: () => void;
}

function KeyStep({
  alias,
  hostId,
  keys,
  loading,
  selected,
  onSelect,
  onCreate,
  created,
  onShown,
}: KeyStepProps) {
  const { t } = useTranslation();
  const labelId = useId();
  const list = useRef<HTMLDivElement>(null);
  const listed = created !== null && keys.some((key) => key.id === created);
  useEffect(() => {
    if (!listed) return;
    const item = [...(list.current?.querySelectorAll<HTMLElement>('[role=radio]') ?? [])].find(
      (element) => element.dataset.key === created,
    );
    item?.scrollIntoView({ block: 'nearest' });
    item?.focus();
    onShown();
  }, [listed, created, onShown]);

  if (loading) {
    return (
      <div className="grid place-items-center py-6 text-subtle">
        <Spinner className="size-5" />
      </div>
    );
  }
  if (keys.length === 0) {
    return (
      <div className="flex flex-col items-start gap-3">
        <Text>{t('hosts.vault.switch.noKeys')}</Text>
        <Button
          variant="soft"
          icon={<Plus aria-hidden="true" className="size-4" strokeWidth={2.25} />}
          onClick={onCreate}
        >
          {t('hosts.vault.switch.newKey')}
        </Button>
      </div>
    );
  }
  return (
    <>
      <Text id={labelId}>{t('hosts.vault.switch.keyText', { alias })}</Text>
      <RadioGroup.Root
        ref={list}
        aria-labelledby={labelId}
        value={selected?.id ?? ''}
        onValueChange={onSelect}
        className="glass flex max-h-[260px] flex-col gap-0.5 overflow-y-auto rounded-[14px] p-1.5"
      >
        {keys.map((key) => {
          const inConfig = key.usedBy.some((usage) => usage.hostId === hostId);
          return (
            <RadioGroup.Item
              key={key.id}
              value={key.id}
              data-key={key.id}
              className={cn(
                'pressable-soft flex w-full items-center gap-[11px] rounded-[10px] px-2.5 py-2 text-left',
                key.id === selected?.id ? 'selected-row' : 'hover:bg-white/[0.04]',
              )}
            >
              <Tile tone={keyTone(key)} size={30}>
                <KeyRound className="size-[15px]" strokeWidth={2.25} />
              </Tile>
              <span className="flex min-w-0 flex-1 flex-col gap-0.5">
                <span className="truncate font-mono text-[13px] font-medium">{key.name}</span>
                <span className="flex flex-wrap items-center gap-1.5">
                  <Badge mono>{algorithmBadge(key)}</Badge>
                  {inConfig ? (
                    <Badge tone="accent">{t('hosts.vault.switch.inConfig')}</Badge>
                  ) : null}
                  {key.inAgent ? (
                    <Badge tone="violet">{t('hosts.vault.switch.inAgent')}</Badge>
                  ) : null}
                  {key.hardware ? <Badge>{t('hosts.vault.switch.hardware')}</Badge> : null}
                </span>
              </span>
              <RadioGroup.Indicator>
                <Check
                  aria-hidden="true"
                  className="size-4 text-[var(--accent-text)]"
                  strokeWidth={2.5}
                />
              </RadioGroup.Indicator>
            </RadioGroup.Item>
          );
        })}
      </RadioGroup.Root>
      <Button
        variant="ghost"
        size="sm"
        className="-mt-2 self-start text-[var(--accent-text)]"
        icon={<Plus aria-hidden="true" className="size-[15px]" strokeWidth={2} />}
        onClick={onCreate}
      >
        {t('hosts.vault.switch.newKey')}
      </Button>
    </>
  );
}

function Text({ id, children }: { id?: string; children: ReactNode }) {
  return (
    <p id={id} className="text-[13px] leading-5 text-fg-2">
      {children}
    </p>
  );
}

/** Where results appear; mounted before them, so screen readers announce them. */
function Live({ children }: { children: ReactNode }) {
  return (
    // Empty, it takes no room (the negative margin cancels the body's gap)
    // but stays in the accessibility tree.
    <div role="status" className="flex flex-col gap-2 empty:-mt-[18px]">
      {children}
    </div>
  );
}

function OkBox({ children }: { children: ReactNode }) {
  return (
    <p className="flex gap-2.5 rounded-xl border border-ok/30 bg-ok/[0.08] px-3 py-2.5 font-medium">
      <CheckCircle2 aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-ok" strokeWidth={2} />
      {children}
    </p>
  );
}

function ErrorBox({ children }: { children: ReactNode }) {
  return (
    <p className="flex gap-2.5 rounded-xl border border-critical-solid/30 bg-critical-solid/10 px-3 py-2.5">
      <XCircle
        aria-hidden="true"
        className="mt-0.5 size-4 shrink-0 text-critical"
        strokeWidth={2}
      />
      {children}
    </p>
  );
}
