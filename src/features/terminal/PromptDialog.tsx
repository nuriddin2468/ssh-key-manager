import {
  Eye,
  EyeOff,
  KeyRound,
  LockKeyhole,
  MessageSquareText,
  ShieldQuestion,
} from 'lucide-react';
import { type FormEvent, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { PromptAsk } from '@/bindings/PromptAsk';
import type { SaveOffer } from '@/bindings/SaveOffer';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { DialogBody, DialogContent, DialogFooter, DialogHeader } from '@/components/ui/Dialog';
import { IconButton } from '@/components/ui/IconButton';
import { TextField } from '@/components/ui/TextField';
import { Tile } from '@/components/ui/Tile';
import { VaultIcon } from '@/features/keys/VaultControls';
import { fileName, hostKeyHost, promptAccount, type Tab } from './model';

interface PromptDialogProps {
  tab: Tab;
  ask: PromptAsk;
  onAnswer: (answer: PromptAnswer) => void;
}

/**
 * What `ssh` asks, as a dialog that names the host. Render it inside an open
 * `<Dialog>` whose closing (Escape) cancels the prompt.
 */
export function PromptDialog({ tab, ask, onAnswer }: PromptDialogProps) {
  switch (ask.type) {
    case 'hostKey':
      return <HostKeyDialog ask={ask} onAnswer={onAnswer} />;
    default:
      return <SecretDialog tab={tab} ask={ask} onAnswer={onAnswer} />;
  }
}

/**
 * "Trust this key?", titled with the host the key is for (a jump host's key
 * names the jump host). Anything ssh says besides the plain question shows
 * as a warning, and "Don't connect" becomes the main button.
 */
function HostKeyDialog({
  ask,
  onAnswer,
}: {
  ask: Extract<PromptAsk, { type: 'hostKey' }>;
  onAnswer: (answer: PromptAnswer) => void;
}) {
  const { t } = useTranslation();
  const warning = ask.extra.length > 0;
  return (
    <DialogContent section="terminal" className="max-w-[480px]" dismissible={false}>
      <EscapeIs onEscape={() => onAnswer({ type: 'trust', trust: false })} />
      <DialogHeader
        icon={
          <Tile tone={warning ? 'rose' : 'amber'} size={40} glow>
            <ShieldQuestion className="size-5" strokeWidth={2} />
          </Tile>
        }
        title={t('terminal.prompt.hostKeyTitle', { host: hostKeyHost(ask.host) })}
        description={warning ? t('terminal.prompt.hostKeyExtra') : t('terminal.prompt.hostKeyText')}
        closable={false}
      />
      <DialogBody>
        <div className="selectable rounded-[11px] border border-white/[0.07] bg-terminal px-3 py-2.5 font-mono text-[12px] leading-[1.6] break-all">
          <span className="text-subtle">{ask.host}</span>
          <br />
          <span className="text-subtle">{ask.keyType}</span>
          <br />
          <span className="text-fg">{ask.fingerprint}</span>
        </div>
        {warning ? (
          <figure className="flex flex-col gap-1.5">
            <figcaption className="text-[12px] font-medium text-critical">
              {t('terminal.prompt.hostKeyExtraLabel')}
            </figcaption>
            <pre className="selectable max-h-[180px] overflow-auto rounded-[11px] border border-critical-solid/30 bg-critical-solid/10 px-3 py-2.5 font-mono text-[12px] leading-[1.6] break-all whitespace-pre-wrap text-fg">
              {ask.extra.join('\n')}
            </pre>
          </figure>
        ) : null}
        <p className="text-[12px] text-muted">{t('terminal.prompt.hostKeyNote')}</p>
      </DialogBody>
      <DialogFooter>
        <Button
          variant={warning ? 'primary' : 'secondary'}
          size="lg"
          onClick={() => onAnswer({ type: 'trust', trust: false })}
        >
          {t('terminal.prompt.dontConnect')}
        </Button>
        <Button
          variant={warning ? 'danger' : 'primary'}
          size="lg"
          onClick={() => onAnswer({ type: 'trust', trust: true })}
        >
          {t('terminal.prompt.trust')}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}

/**
 * Escape answers the prompt (Cancel). The dialog itself ignores clicks and
 * focus outside it, so only a deliberate key or button answers ssh.
 */
function EscapeIs({ onEscape }: { onEscape: () => void }) {
  const latest = useRef(onEscape);
  latest.current = onEscape;
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      // Radix has already blocked its own Escape handling (dismissible={false}).
      if (event.key !== 'Escape') return;
      event.preventDefault();
      latest.current();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);
  return null;
}

type SecretAsk = Exclude<PromptAsk, { type: 'hostKey' }>;

/** The texts and options of a dialog that asks for a secret. */
function useSecretCopy(tab: Tab, ask: SecretAsk) {
  const { t } = useTranslation();
  switch (ask.type) {
    case 'password': {
      const descriptions = {
        asked: t('terminal.prompt.passwordAsked'),
        keyFailed: t('terminal.prompt.passwordKeyFailed'),
        savedRejected: t('terminal.prompt.passwordSavedRejected'),
        rejected: t('terminal.prompt.passwordRejected'),
      };
      return {
        tone: 'pink' as const,
        icon: <VaultIcon className="size-5" />,
        title: t('terminal.prompt.passwordTitle', { account: promptAccount(tab, ask) }),
        description: ask.foreign
          ? t('terminal.prompt.passwordForeign', { alias: tab.alias })
          : descriptions[ask.why],
        label: t('terminal.prompt.password'),
        submit: t('terminal.prompt.signIn'),
        save: ask.save,
        saveLabel:
          ask.save === 'update'
            ? t('terminal.prompt.saveUpdate')
            : t('terminal.prompt.saveNew', { alias: tab.alias }),
        hint: undefined,
        code: false,
        quote: undefined,
        warning: undefined,
      };
    }
    case 'passphrase':
      return {
        tone: 'teal' as const,
        icon: <KeyRound className="size-5" strokeWidth={2} />,
        title: t('terminal.prompt.passphraseTitle', { key: fileName(ask.key) }),
        description: ask.retry
          ? t('terminal.prompt.passphraseRetry')
          : t('terminal.prompt.passphraseAsked'),
        label: t('terminal.prompt.passphrase'),
        submit: t('terminal.prompt.unlock'),
        save: ask.save,
        saveLabel:
          ask.save === 'update'
            ? t('terminal.prompt.saveUpdate')
            : t('terminal.prompt.savePassphrase'),
        hint: undefined,
        code: false,
        quote: undefined,
        warning: undefined,
      };
    case 'oneTimeCode':
      return {
        tone: 'pink' as const,
        icon: <LockKeyhole className="size-5" strokeWidth={2} />,
        title: t('terminal.prompt.codeTitle', { account: promptAccount(tab, ask) }),
        description: ask.retry
          ? t('terminal.prompt.codeRetry')
          : ask.foreign
            ? t('terminal.prompt.codeForeign', { alias: tab.alias, question: ask.question })
            : t('terminal.prompt.codeAsked', { question: ask.question }),
        label: t('terminal.prompt.code'),
        submit: t('terminal.prompt.send'),
        save: 'none' as SaveOffer,
        saveLabel: '',
        hint: ask.foreign ? undefined : t('terminal.prompt.codeHint'),
        code: true,
        quote: undefined,
        warning: undefined,
      };
    case 'other':
      // The text is the sender's, shown as a quote: never in the app's voice.
      return {
        tone: 'slate' as const,
        icon: <MessageSquareText className="size-5" strokeWidth={2} />,
        title: ask.unverified
          ? t('terminal.prompt.otherUnverifiedTitle')
          : t('terminal.prompt.otherTitle', { account: promptAccount(tab, ask) }),
        description: ask.foreign
          ? t('terminal.prompt.otherFromForeign', { alias: tab.alias })
          : t('terminal.prompt.otherFromServer'),
        label: t('terminal.prompt.otherAnswer'),
        submit: t('terminal.prompt.send'),
        save: 'none' as SaveOffer,
        saveLabel: '',
        hint: undefined,
        code: false,
        quote: ask.text,
        warning: ask.unverified
          ? t('terminal.prompt.otherUnverified', { alias: tab.alias })
          : undefined,
      };
  }
}

function SecretDialog({
  tab,
  ask,
  onAnswer,
}: {
  tab: Tab;
  ask: SecretAsk;
  onAnswer: (answer: PromptAnswer) => void;
}) {
  const { t } = useTranslation();
  const copy = useSecretCopy(tab, ask);
  const [value, setValue] = useState('');
  const [visible, setVisible] = useState(false);
  const canSave = copy.save === 'new' || copy.save === 'update';
  const [save, setSave] = useState(canSave);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!value) return;
    onAnswer({ type: 'secret', value, save: canSave && save });
  };

  return (
    <DialogContent section="terminal" className="max-w-[460px]" dismissible={false}>
      <EscapeIs onEscape={() => onAnswer({ type: 'cancel' })} />
      <form onSubmit={submit} noValidate className="flex min-h-0 flex-col">
        <DialogHeader
          icon={
            <Tile tone={copy.tone} size={40} glow>
              {copy.icon}
            </Tile>
          }
          title={copy.title}
          description={copy.description}
        />
        <DialogBody>
          {copy.quote !== undefined ? (
            <figure className="flex flex-col gap-1.5">
              <figcaption className="text-[12px] text-muted">
                {t('terminal.prompt.otherQuote')}
              </figcaption>
              <blockquote className="selectable max-h-[200px] overflow-auto rounded-[11px] border border-white/[0.07] border-l-2 border-l-white/25 bg-terminal px-3 py-2.5 font-mono text-[12px] leading-[1.6] break-words whitespace-pre-wrap text-fg">
                {copy.quote}
              </blockquote>
            </figure>
          ) : null}
          {copy.warning ? <p className="text-[12px] text-critical">{copy.warning}</p> : null}
          <TextField
            label={copy.label}
            type={copy.code || visible ? 'text' : 'password'}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            autoComplete={copy.code ? 'one-time-code' : 'off'}
            inputMode={copy.code ? 'numeric' : undefined}
            mono
            inputClassName={copy.code ? 'text-[15px] tracking-[2px]' : undefined}
            hint={copy.hint}
            suffix={
              copy.code ? undefined : (
                <IconButton
                  label={visible ? t('terminal.prompt.hide') : t('terminal.prompt.show')}
                  icon={
                    visible ? (
                      <EyeOff className="size-[15px]" strokeWidth={1.75} />
                    ) : (
                      <Eye className="size-[15px]" strokeWidth={1.75} />
                    )
                  }
                  onClick={() => setVisible((shown) => !shown)}
                />
              )
            }
          />
          {canSave ? (
            <Checkbox checked={save} onCheckedChange={setSave} label={copy.saveLabel} />
          ) : copy.save === 'locked' ? (
            <p className="text-[12px] text-muted">{t('terminal.prompt.saveLocked')}</p>
          ) : copy.save === 'noVault' ? (
            <p className="text-[12px] text-muted">{t('terminal.prompt.saveNoVault')}</p>
          ) : null}
        </DialogBody>
        <DialogFooter>
          <Button size="lg" onClick={() => onAnswer({ type: 'cancel' })}>
            {t('common.cancel')}
          </Button>
          <Button type="submit" variant="primary" size="lg" disabled={!value}>
            {copy.submit}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
