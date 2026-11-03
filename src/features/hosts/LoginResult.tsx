import { CheckCircle2, X, XCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { Button } from '@/components/ui/Button';
import { IconButton } from '@/components/ui/IconButton';
import { cn } from '@/lib/cn';
import { loginMessage, type MessageAction, type RunContext, type SshRun } from './login';

interface LoginResultProps {
  run: SshRun;
  context: RunContext;
  alias: string;
  /** The vault has this host's password but is locked. */
  vaultLocked?: boolean;
  /** Fixes offered as a button when the result calls for one. */
  onAction?: Partial<Record<MessageAction, () => void>>;
  onClose?: () => void;
  /** The title of a success, in place of the usual one (a git service's greeting, say). */
  okTitle?: string;
  /** `status` announces the result; leave it out inside a live region of your own. */
  role?: 'status';
  className?: string;
}

/** What an `ssh` run did, in plain words, with a fix and what `ssh` printed. */
export function LoginResult({
  run,
  context,
  alias,
  vaultLocked,
  onAction,
  onClose,
  okTitle,
  role,
  className,
}: LoginResultProps) {
  const { t } = useTranslation();
  const message = loginMessage(run, context, { vaultLocked });
  // Every placeholder any of the messages uses.
  const values = { alias, key: '', account: '', ...message.values };
  const ok = message.tone === 'ok';
  const fix = message.action ? onAction?.[message.action] : undefined;
  const Icon = ok ? CheckCircle2 : XCircle;
  const title =
    ok && okTitle
      ? okTitle
      : message.title === 'signedIn'
        ? t('hosts.testOk')
        : message.title === 'failed'
          ? t('hosts.testFailed')
          : t(`hosts.vault.result.${message.title}`, values);

  return (
    <div
      role={role}
      className={cn(
        'flex gap-2.5 rounded-xl border px-3 py-2.5',
        ok ? 'border-ok/30 bg-ok/[0.08]' : 'border-critical-solid/30 bg-critical-solid/10',
        className,
      )}
    >
      <Icon
        aria-hidden="true"
        className={cn('mt-0.5 size-4 shrink-0', ok ? 'text-ok' : 'text-critical')}
        strokeWidth={2}
      />
      <div className="flex min-w-0 flex-1 flex-col items-start gap-1">
        <span className="font-medium">{title}</span>
        {message.detail ? (
          <span className="text-[12.5px] leading-[18px] text-muted">
            {t(`hosts.vault.result.${message.detail}`, values)}
          </span>
        ) : null}
        {fix && message.action ? (
          <Button size="sm" className="mt-1" onClick={fix}>
            {t(`hosts.vault.result.${message.action}`)}
          </Button>
        ) : null}
        {run.output ? (
          // Scrolls when long, so it takes focus for keyboard scrolling.
          <section
            aria-label={t('hosts.vault.result.output')}
            // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
            tabIndex={0}
            className="mt-0.5 max-h-24 w-full overflow-auto rounded-md"
          >
            <pre className="selectable font-mono text-[11.5px] leading-[17px] whitespace-pre-wrap text-fg-2">
              {run.output}
            </pre>
          </section>
        ) : null}
      </div>
      {onClose ? (
        <IconButton label={t('common.close')} icon={<X className="size-3.5" />} onClick={onClose} />
      ) : null}
    </div>
  );
}
