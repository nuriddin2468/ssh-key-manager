import {
  AlertTriangle,
  Check,
  Clock,
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  ShieldAlert,
  Variable,
} from 'lucide-react';
import { type ReactNode, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { useRouter } from '@/app/router';
import type { ChatEntry } from '@/bindings/ChatEntry';
import type { Gone } from '@/bindings/Gone';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { IconButton } from '@/components/ui/IconButton';
import { REVEAL_MS } from '@/features/passwords/SavedSecret';
import { cn } from '@/lib/cn';
import { formatDuration } from '@/lib/format';
import { ItemCard } from '../ItemCard';
import { secondsUntil, soon, useChatAction } from './model';

interface BubbleProps {
  peer: { key: string; name: string; online: boolean };
  entry: ChatEntry;
  /** Opens the review that adds received variables to an environment. */
  onAddVariables: (id: string) => void;
}

/** One entry of a conversation: a message, a secret, variables, a card or a line. */
export function Bubble({ peer, entry, onAddVariables }: BubbleProps) {
  const { t, i18n } = useTranslation();
  const { body } = entry;
  if (body.kind === 'line') {
    return (
      <p className="self-center px-3 text-center text-[12px] leading-[18px] text-subtle">
        {t('nearby.chat.line.paused', { name: peer.name })}
      </p>
    );
  }
  const time = new Date(entry.at).toLocaleTimeString(i18n.language, {
    hour: '2-digit',
    minute: '2-digit',
  });
  return (
    <div className={cn('flex max-w-[72%] flex-col gap-1', entry.mine ? 'self-end' : 'self-start')}>
      <div
        className={cn(
          'selectable text-[13px] leading-5 text-fg',
          // A card is framed by its own item card: no bubble around it.
          body.kind === 'card'
            ? ''
            : entry.mine
              ? 'rounded-2xl border border-[rgb(var(--accent-rgb)/0.35)] bg-[rgb(var(--accent-rgb)/0.14)] px-3 py-2'
              : 'rounded-2xl border border-line bg-card px-3 py-2',
        )}
      >
        {body.kind === 'text' ? (
          <p dir="auto" className="whitespace-pre-wrap [overflow-wrap:anywhere]">
            {body.text}
          </p>
        ) : body.kind === 'secret' ? (
          <SecretBody
            peer={peer}
            entry={entry}
            label={body.label}
            expires={body.expires}
            gone={body.gone}
          />
        ) : body.kind === 'variables' ? (
          <VariablesBody peer={peer} entry={entry} onAdd={() => onAddVariables(entry.id)} />
        ) : (
          <CardBody peer={peer} entry={entry} />
        )}
      </div>
      <Status peer={peer} entry={entry} time={time} />
    </div>
  );
}

function Status({
  peer,
  entry,
  time,
}: {
  peer: { key: string; online: boolean };
  entry: ChatEntry;
  time: string;
}) {
  const { t } = useTranslation();
  const retry = useChatAction(() => api.chatRetry(peer.key, entry.id));
  const delivery = entry.delivery;
  let state: ReactNode = null;
  if (entry.mine) {
    switch (delivery.state) {
      case 'sending':
        state = (
          <span className="inline-flex items-center gap-1">
            <Clock aria-hidden="true" className="size-3" strokeWidth={2} />
            {t('nearby.chat.delivery.sending')}
          </span>
        );
        break;
      case 'delivered':
        state = (
          <span className="inline-flex items-center gap-1">
            <Check aria-hidden="true" className="size-3" strokeWidth={2.4} />
            {t('nearby.chat.delivery.delivered')}
          </span>
        );
        break;
      case 'notDelivered':
        state = (
          <span className="inline-flex items-center gap-1.5 text-critical">
            {t('nearby.chat.delivery.notDelivered')}
            {peer.online ? (
              <button
                type="button"
                className="pressable font-medium underline underline-offset-2"
                disabled={retry.isPending}
                onClick={() => retry.mutate(undefined)}
              >
                {t('nearby.chat.delivery.retry')}
              </button>
            ) : null}
          </span>
        );
        break;
      case 'refused':
        state = (
          <span className="text-critical">
            {t('nearby.chat.delivery.refused', {
              reason: t(`nearby.chat.refusal.${delivery.reason}`),
            })}
          </span>
        );
        break;
      default:
        break;
    }
  }
  return (
    <span
      className={cn(
        'flex items-center gap-2 px-1 text-[11px] text-subtle',
        entry.mine ? 'self-end' : 'self-start',
      )}
    >
      <time dateTime={entry.at}>{time}</time>
      {state}
    </span>
  );
}

/** What stays of a secret or variables once their value is gone. */
const GONE = {
  secret: {
    expired: 'nearby.chat.secret.expired',
    wiped: 'nearby.chat.secret.wiped',
    wipedByPeer: 'nearby.chat.secret.wipedByPeer',
  },
  variables: {
    expired: 'nearby.chat.variables.expired',
    wiped: 'nearby.chat.variables.wiped',
    wipedByPeer: 'nearby.chat.variables.wipedByPeer',
  },
} as const satisfies Record<'secret' | 'variables', Record<Gone, string>>;

/** A masked value: Show (hides itself again after 30 s) and Copy, through the backend. */
function MaskedValue({
  peer,
  id,
  name,
}: {
  peer: { key: string };
  id: string;
  name: string | null;
}) {
  const { t } = useTranslation();
  const [value, setValue] = useState<string | null>(null);
  useEffect(() => {
    if (value === null) return undefined;
    const timer = window.setTimeout(() => setValue(null), REVEAL_MS);
    return () => window.clearTimeout(timer);
  }, [value]);
  const reveal = useChatAction(() => api.chatReveal(peer.key, id, name), setValue);
  const copy = useChatAction(
    () => api.chatCopy(peer.key, id, name),
    (result) =>
      toast.success(
        result.clearsInSecs
          ? t('nearby.chat.secret.clears', { seconds: result.clearsInSecs })
          : t('nearby.chat.secret.copied'),
      ),
  );
  return (
    <span className="flex min-w-0 items-center gap-1">
      <span
        className={cn(
          'min-w-0 flex-1 truncate font-mono text-[12.5px]',
          value === null ? 'text-muted' : 'selectable text-fg',
        )}
      >
        {value ?? (
          <>
            <span aria-hidden="true">••••••••••••</span>
            <span className="sr-only">{t('nearby.chat.secret.hidden')}</span>
          </>
        )}
      </span>
      <IconButton
        size="sm"
        variant="ghost"
        label={value === null ? t('nearby.chat.secret.show') : t('nearby.chat.secret.hide')}
        icon={
          value === null ? (
            <Eye className="size-3.5" strokeWidth={2} />
          ) : (
            <EyeOff className="size-3.5" strokeWidth={2} />
          )
        }
        disabled={reveal.isPending}
        onClick={() => (value === null ? reveal.mutate(undefined) : setValue(null))}
      />
      <IconButton
        size="sm"
        variant="ghost"
        label={t('nearby.chat.secret.copy')}
        icon={<Copy className="size-3.5" strokeWidth={2} />}
        disabled={copy.isPending}
        onClick={() => copy.mutate(undefined)}
      />
    </span>
  );
}

function Expiry({ expires }: { expires: string }) {
  const { t, i18n } = useTranslation();
  const seconds = secondsUntil(expires);
  return (
    <Badge tone={soon(expires) ? 'warning' : 'neutral'}>
      {t('nearby.chat.secret.expiresIn', {
        time: formatDuration(Math.max(60, seconds), i18n.language),
      })}
    </Badge>
  );
}

function Wipe({ peer, id }: { peer: { key: string; name: string; online: boolean }; id: string }) {
  const { t } = useTranslation();
  const [asking, setAsking] = useState(false);
  const wipe = useChatAction(
    () => api.chatRevoke(peer.key, id),
    () => setAsking(false),
  );
  return (
    <>
      <Button size="sm" variant="ghost" onClick={() => setAsking(true)}>
        {t('nearby.chat.secret.wipe')}
      </Button>
      <ConfirmDialog
        open={asking}
        onOpenChange={setAsking}
        title={t('nearby.chat.secret.wipeTitle')}
        description={t('nearby.chat.secret.wipeText', { name: peer.name })}
        confirmLabel={t('nearby.chat.secret.wipeConfirm')}
        destructive
        busy={wipe.isPending}
        onConfirm={() => wipe.mutate(undefined)}
      />
    </>
  );
}

function SecretBody({
  peer,
  entry,
  label,
  expires,
  gone,
}: {
  peer: { key: string; name: string; online: boolean };
  entry: ChatEntry;
  label: string;
  expires: string | null;
  gone: Gone | null;
}) {
  const { t } = useTranslation();
  if (gone) {
    return (
      <p className="flex items-center gap-1.5 text-subtle">
        <KeyRound aria-hidden="true" className="size-3.5" strokeWidth={2} />
        {t(GONE.secret[gone], { name: peer.name })}
      </p>
    );
  }
  return (
    <div className="flex min-w-[240px] flex-col gap-1.5">
      <span className="flex items-center gap-1.5 text-[12px] font-medium text-fg-2">
        <KeyRound aria-hidden="true" className="size-3.5" strokeWidth={2} />
        <span dir="auto" className="truncate">
          {label || t('nearby.chat.secret.label')}
        </span>
      </span>
      <MaskedValue peer={peer} id={entry.id} name={null} />
      <span className="flex flex-wrap items-center gap-2">
        {expires ? <Expiry expires={expires} /> : null}
        {entry.mine ? <Wipe peer={peer} id={entry.id} /> : null}
      </span>
    </div>
  );
}

function VariablesBody({
  peer,
  entry,
  onAdd,
}: {
  peer: { key: string; name: string; online: boolean };
  entry: ChatEntry;
  onAdd: () => void;
}) {
  const { t } = useTranslation();
  if (entry.body.kind !== 'variables') return null;
  const { label, variables, expires, gone } = entry.body;
  return (
    <div className="flex min-w-[280px] flex-col gap-2">
      <span className="flex items-center gap-1.5 text-[12px] font-medium text-fg-2">
        <Variable aria-hidden="true" className="size-3.5" strokeWidth={2} />
        {t('nearby.chat.variables.count', { count: variables.length })}
        {label ? (
          <span dir="auto" className="truncate font-normal text-subtle">
            {t('nearby.chat.variables.from', { label })}
          </span>
        ) : null}
      </span>
      <ul className="flex flex-col gap-1">
        {variables.map((variable) => (
          <li key={variable.name} className="flex min-w-0 items-center gap-2">
            <span className="shrink-0 font-mono text-[12px] text-fg-2">{variable.name}</span>
            {variable.risky ? (
              <ShieldAlert
                role="img"
                aria-label={t('nearby.chat.variables.risky')}
                className="size-3.5 shrink-0 text-warning"
                strokeWidth={2}
              />
            ) : null}
            <span className="min-w-0 flex-1">
              {gone ? (
                <span className="text-subtle">—</span>
              ) : variable.secret ? (
                <MaskedValue peer={peer} id={entry.id} name={variable.name} />
              ) : (
                <span className="selectable block truncate font-mono text-[12px] text-muted">
                  {variable.value}
                </span>
              )}
            </span>
          </li>
        ))}
      </ul>
      {gone ? (
        <p className="text-subtle">{t(GONE.variables[gone], { name: peer.name })}</p>
      ) : (
        <span className="flex flex-wrap items-center gap-2">
          {expires ? <Expiry expires={expires} /> : null}
          {entry.mine ? (
            <Wipe peer={peer} id={entry.id} />
          ) : (
            <Button size="sm" variant="soft" onClick={onAdd}>
              {t('nearby.chat.variables.add')}
            </Button>
          )}
        </span>
      )}
    </div>
  );
}

function CardBody({
  peer,
  entry,
}: {
  peer: { key: string; name: string; online: boolean };
  entry: ChatEntry;
}) {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const answer = useChatAction((accept: boolean) => api.chatAnswer(peer.key, entry.id, accept));
  if (entry.body.kind !== 'card') return null;
  const { item, outcome, name, keysDiffer, group } = entry.body;
  const mine = entry.mine;
  const said: Record<typeof outcome, string> = {
    waiting: mine
      ? t('nearby.chat.card.waitingMine', { name: peer.name })
      : t('nearby.chat.card.waitingTheirs', { name: peer.name }),
    accepted: t('nearby.chat.card.accepted'),
    saved: mine
      ? t('nearby.chat.card.savedMine', { name: peer.name })
      : t('nearby.chat.card.savedTheirs', { saved: name ?? '' }),
    notSaved: t('nearby.chat.card.notSaved'),
    declined: mine
      ? t('nearby.chat.card.declinedMine', { name: peer.name })
      : t('nearby.chat.card.declinedTheirs'),
    unsupported: t('nearby.chat.card.unsupported', { name: peer.name }),
    ended: t('nearby.chat.card.ended', { name: peer.name }),
    notConfirmed: t('nearby.chat.card.notConfirmed', { name: peer.name }),
  };
  return (
    <div className="flex min-w-[280px] flex-col gap-2">
      <ItemCard item={item} />
      <p className="text-[12.5px] leading-[18px] text-fg-2">{said[outcome]}</p>
      {keysDiffer ? (
        <p className="flex gap-1.5 text-[12px] leading-[18px] text-warning">
          <AlertTriangle aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" strokeWidth={2} />
          {t('nearby.chat.card.keysDiffer')}
        </p>
      ) : null}
      {!mine && outcome === 'waiting' && peer.online ? (
        <span className="flex gap-2">
          <Button
            size="sm"
            variant="primary"
            loading={answer.isPending && answer.variables === true}
            disabled={answer.isPending}
            onClick={() => answer.mutate(true)}
          >
            {t('nearby.send.accept')}
          </Button>
          <Button
            size="sm"
            loading={answer.isPending && answer.variables === false}
            disabled={answer.isPending}
            onClick={() => answer.mutate(false)}
          >
            {t('nearby.send.decline')}
          </Button>
        </span>
      ) : null}
      {!mine && outcome === 'saved' && group !== null ? (
        <Button size="sm" onClick={() => navigate({ page: 'hostsFile', received: group })}>
          {t('nearby.send.openHosts')}
        </Button>
      ) : null}
    </div>
  );
}
