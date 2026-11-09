import { AlertTriangle, CheckCircle2, Laptop, XCircle } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { useKeys } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { ItemSummary } from '@/bindings/ItemSummary';
import type { Pairing } from '@/bindings/Pairing';
import type { PairingFailure } from '@/bindings/PairingFailure';
import { Button } from '@/components/ui/Button';
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { groupCode } from '@/features/browser/queries';
import { ItemCard } from './ItemCard';
import { canRetry, isActive } from './model';
import { AuthorizeStep, SetMasterStep, TransferStep } from './OwnSteps';
import { useNearby } from './queries';

export const FAILURES = {
  unreachable: 'nearby.pairing.unreachable',
  declined: 'nearby.pairing.declined',
  peerDeclined: 'nearby.pairing.peerDeclined',
  cancelled: 'nearby.pairing.cancelled',
  peerLeft: 'nearby.pairing.peerLeft',
  timedOut: 'nearby.pairing.timedOut',
  vaultLocked: 'nearby.pairing.vaultLocked',
  version: 'nearby.pairing.version',
  broken: 'nearby.pairing.broken',
  refused: 'nearby.pairing.refused',
  turned: 'nearby.pairing.turned',
  notSaved: 'nearby.pairing.notSaved',
  otherVault: 'nearby.pairing.otherVault',
  notOwn: 'nearby.pairing.notOwn',
} as const satisfies Record<PairingFailure, string>;

/** What the receiver reads before accepting, by what is offered. */
const OFFERED = {
  password: 'nearby.send.offeredPassword',
  host: 'nearby.send.offeredHost',
  hostsGroup: 'nearby.send.offeredGroup',
  publicKey: 'nearby.send.offeredKey',
  environment: 'envs.share.offered',
} as const satisfies Record<ItemSummary['type'], string>;

/**
 * App-wide: a pairing with another device, from either side, or adding one
 * of the user's devices. Both users compare the code on their screens; the
 * backend saves the contact (or the device) only when both say it matches.
 * Syncs have a dialog of their own. Mounted once in the shell.
 */
export function PairingDialog() {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const status = useNearby();
  const keys = useKeys();
  const any = status.data?.pairing ?? null;
  // A finished pairing the user closed goes at once: the backend's event
  // that it is gone only confirms it.
  const [dismissed, setDismissed] = useState<number | null>(null);
  const pairing = any?.kind === 'sync' || (any && any.id === dismissed) ? null : any;
  // The last pairing shown stays while the dialog animates out.
  const shown = useRef<Pairing | null>(null);
  if (pairing) shown.current = pairing;
  const current = pairing ?? shown.current;

  const answer = useAppMutation((vars: { id: number; matched: boolean }) =>
    api.nearbyAnswer(vars.id, vars.matched),
  );
  // Closing a finished pairing lets it go; closing one going on cancels it,
  // and the dialog then says it was cancelled.
  const close = (id: number) => {
    if (!isActive(pairing)) setDismissed(id);
    void api.nearbyClose(id).catch((error) => toastError(t, error));
  };

  // Each step replaces the buttons, and the focused one with them: focus
  // the "no" when a question comes up, else the last button.
  const footer = useRef<HTMLDivElement>(null);
  const step = pairing?.phase.type;
  useEffect(() => {
    // These steps focus a field or button of their own.
    if (!step || step === 'authorize' || step === 'setMaster') return;
    const buttons = footer.current?.querySelectorAll<HTMLElement>('button');
    const asks = step === 'compare' || step === 'offered' || step === 'nameMismatch';
    const target = asks ? buttons?.[0] : buttons?.[buttons.length - 1];
    target?.focus();
  }, [step]);

  // A hosts file group isn't saved yet: the Hosts file page shows it as a
  // change, which the user saves with the administrator password.
  const groupFrom =
    pairing?.phase.type === 'received' && pairing.phase.item.type === 'hostsGroup'
      ? pairing.id
      : null;
  useEffect(() => {
    if (groupFrom === null) return;
    void api.nearbyClose(groupFrom).catch(() => undefined);
    navigate({ page: 'hostsFile', received: groupFrom });
  }, [groupFrom, navigate]);

  if (!current) return null;
  // The name comes with the other side's first message; until then the
  // dialog names nobody. Every sentence that names it comes after. For a
  // computer paired before, it is the name the vault keeps, whatever name
  // that computer gives itself now.
  const peer = current.peer ?? '';
  const phase = current.phase;
  const active = isActive(current);
  const code = phase.type === 'compare' || phase.type === 'waiting' ? phase.code : null;
  const item =
    phase.type === 'offering' ||
    phase.type === 'offered' ||
    phase.type === 'sent' ||
    phase.type === 'received'
      ? phase.item
      : null;
  const device = current.kind === 'device';
  const mismatch = phase.type === 'nameMismatch' ? phase.announced : null;
  const aboutItem = item !== null || mismatch !== null;
  const usualTitle = !current.peer
    ? t('nearby.pairing.title')
    : device
      ? current.outgoing
        ? t('nearby.own.titleOut', { peer })
        : t('nearby.own.titleIn', { peer })
      : phase.type === 'offering' || phase.type === 'sent'
        ? t('nearby.send.titleTo', { peer })
        : phase.type === 'offered' || phase.type === 'received'
          ? t('nearby.send.titleFrom', { peer })
          : current.outgoing
            ? t('nearby.pairing.titleOut', { peer })
            : t('nearby.pairing.titleIn', { peer });
  const title = mismatch !== null ? t('nearby.send.mismatchTitle') : usualTitle;
  const description = aboutItem
    ? t('nearby.send.description')
    : device
      ? t('nearby.own.description')
      : t('nearby.pairing.description');

  return (
    // Closing cancels a pairing that is going on; it can't be dismissed by accident.
    <Dialog open={pairing !== null} onOpenChange={(open) => open || close(current.id)}>
      <DialogContent section="nearby" className="max-w-[460px]" dismissible={!active}>
        <DialogHeader
          closable={!active}
          icon={
            <Tile tone="orange" size={44} glow>
              <Laptop className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={title}
          description={description}
        />
        <DialogBody>
          <div role="status" className="flex flex-col gap-3">
            {phase.type === 'connecting' ? (
              <p className="flex items-center justify-center gap-2.5 py-6 text-[13px] text-subtle">
                <Spinner className="size-4" />
                {t('nearby.pairing.connecting')}
              </p>
            ) : null}
            {code ? (
              <>
                <div className="glass flex flex-col items-center gap-1.5 rounded-2xl px-4 py-4">
                  <span className="text-[12px] font-medium text-subtle">
                    {t('nearby.pairing.code')}
                  </span>
                  <span
                    role="img"
                    aria-label={code.split('').join(' ')}
                    className="selectable font-mono text-[32px] leading-10 font-semibold tracking-[0.12em] text-fg"
                  >
                    {groupCode(code)}
                  </span>
                </div>
                <p className="text-[13px] leading-5 text-fg-2">
                  {phase.type === 'compare'
                    ? t('nearby.pairing.compare', { peer })
                    : t('nearby.pairing.waiting', { peer })}
                </p>
              </>
            ) : null}
            {mismatch !== null ? (
              <div className="flex gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5 text-[12.5px] leading-[18px] text-fg-2">
                <AlertTriangle
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0 text-warning"
                  strokeWidth={2}
                />
                <span className="flex flex-col gap-1">
                  <span className="font-medium text-fg">
                    {t('nearby.send.mismatch', { peer, announced: mismatch })}
                  </span>
                  <span>{t('nearby.send.mismatchHint')}</span>
                </span>
              </div>
            ) : null}
            {item ? <ItemCard item={item} /> : null}
            {phase.type === 'offering' ? (
              <p className="flex items-center gap-2.5 text-[13px] leading-5 text-fg-2">
                <Spinner className="size-4" />
                {t('nearby.send.offering', { peer })}
              </p>
            ) : null}
            {phase.type === 'offered' ? (
              <p className="text-[13px] leading-5 text-fg-2">
                {t('nearby.send.offered', { peer })} {t(OFFERED[phase.item.type])}
              </p>
            ) : null}
            {phase.type === 'sent' ? (
              <OkBox>
                {phase.item.type === 'hostsGroup'
                  ? t('nearby.send.sentGroup', { peer })
                  : t('nearby.send.sent', { peer })}
              </OkBox>
            ) : null}
            {phase.type === 'received' && phase.item.type !== 'hostsGroup' ? (
              <OkBox>
                {phase.item.type === 'host'
                  ? t('nearby.send.receivedHost', { name: phase.name })
                  : phase.item.type === 'publicKey'
                    ? t('nearby.send.receivedKey', { name: phase.name })
                    : phase.item.type === 'environment'
                      ? t('envs.share.received', { name: phase.name })
                      : t('nearby.send.receivedPassword', { name: phase.name })}
              </OkBox>
            ) : null}
            {phase.type === 'received' && phase.keysDiffer ? (
              <p className="flex gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5 text-[12.5px] leading-[18px] text-fg-2">
                <AlertTriangle
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0 text-warning"
                  strokeWidth={2}
                />
                {t('nearby.send.keysDiffer')}
              </p>
            ) : null}
            {phase.type === 'authorize' ? (
              <AuthorizeStep id={current.id} peer={peer} vault={phase.vault} />
            ) : null}
            {phase.type === 'approving' ? (
              <p className="flex items-center gap-2.5 text-[13px] leading-5 text-fg-2">
                <Spinner className="size-4" />
                {t('nearby.own.approving', { peer })}
              </p>
            ) : null}
            {phase.type === 'transfer' ? (
              <TransferStep done={phase.done} total={phase.total} />
            ) : null}
            {phase.type === 'setMaster' ? <SetMasterStep id={current.id} peer={peer} /> : null}
            {phase.type === 'added' ? (
              <OkBox>
                {phase.vault
                  ? t('nearby.own.addedVault', { peer })
                  : t('nearby.own.added', { peer })}
              </OkBox>
            ) : null}
            {phase.type === 'joined' ? <OkBox>{t('nearby.own.joined')}</OkBox> : null}
            {phase.type === 'paired' || phase.type === 'known' ? (
              <p className="flex gap-2.5 rounded-xl border border-ok/30 bg-ok/[0.08] px-3 py-2.5 font-medium">
                <CheckCircle2
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0 text-ok"
                  strokeWidth={2}
                />
                {t(phase.type === 'paired' ? 'nearby.pairing.paired' : 'nearby.pairing.known', {
                  peer,
                })}
              </p>
            ) : null}
            {phase.type === 'failed' ? (
              <p className="flex gap-2.5 rounded-xl border border-critical-solid/30 bg-critical-solid/10 px-3 py-2.5">
                <XCircle
                  aria-hidden="true"
                  className="mt-0.5 size-4 shrink-0 text-critical"
                  strokeWidth={2}
                />
                <span className="flex flex-col gap-0.5">
                  <span className="font-medium">{t('nearby.pairing.failed')}</span>
                  <span className="text-[12.5px] leading-[18px] text-muted">
                    {t(FAILURES[phase.reason])}
                  </span>
                </span>
              </p>
            ) : null}
          </div>
        </DialogBody>
        <DialogFooter>
          <div ref={footer} className="contents">
            {phase.type === 'offered' ? (
              <>
                <Button
                  size="lg"
                  disabled={answer.isPending}
                  onClick={() => answer.mutate({ id: current.id, matched: false })}
                >
                  {t('nearby.send.decline')}
                </Button>
                <Button
                  size="lg"
                  variant="primary"
                  loading={answer.isPending}
                  onClick={() => answer.mutate({ id: current.id, matched: true })}
                >
                  {t('nearby.send.accept')}
                </Button>
              </>
            ) : phase.type === 'nameMismatch' ? (
              // Not sending is the safe answer, so it is the one that stands out.
              <>
                <Button
                  size="lg"
                  variant="primary"
                  disabled={answer.isPending}
                  onClick={() => answer.mutate({ id: current.id, matched: false })}
                >
                  {t('nearby.send.dontSend')}
                </Button>
                <Button
                  size="lg"
                  loading={answer.isPending}
                  onClick={() => answer.mutate({ id: current.id, matched: true })}
                >
                  {t('nearby.send.sendAnyway')}
                </Button>
              </>
            ) : phase.type === 'compare' ? (
              <>
                <Button
                  size="lg"
                  disabled={answer.isPending}
                  onClick={() => answer.mutate({ id: current.id, matched: false })}
                >
                  {t('nearby.pairing.differs')}
                </Button>
                <Button
                  size="lg"
                  variant="primary"
                  loading={answer.isPending}
                  onClick={() => answer.mutate({ id: current.id, matched: true })}
                >
                  {t('nearby.pairing.matches')}
                </Button>
              </>
            ) : active ? (
              <Button size="lg" onClick={() => close(current.id)}>
                {t('common.cancel')}
              </Button>
            ) : (
              <>
                {phase.type === 'joined' ? (
                  <Button
                    size="lg"
                    onClick={() => {
                      close(current.id);
                      void api.nearbySync(null).catch((error) => toastError(t, error));
                    }}
                  >
                    {t('nearby.own.syncNow')}
                  </Button>
                ) : null}
                {phase.type === 'received' && phase.item.type !== 'hostsGroup' ? (
                  <Button
                    size="lg"
                    onClick={() => {
                      close(current.id);
                      const { item } = phase;
                      navigate(
                        item.type === 'host'
                          ? { page: 'hosts' }
                          : item.type === 'publicKey'
                            ? {
                                page: 'keys',
                                keyId: keys.data?.keys.find(
                                  (key) =>
                                    key.name === phase.name && key.fingerprint === item.fingerprint,
                                )?.id,
                              }
                            : item.type === 'environment'
                              ? { page: 'envs' }
                              : { page: 'passwords' },
                      );
                    }}
                  >
                    {phase.item.type === 'host'
                      ? t('nearby.send.openHosts')
                      : phase.item.type === 'publicKey'
                        ? t('nearby.send.openKeys')
                        : phase.item.type === 'environment'
                          ? t('envs.share.open')
                          : t('nearby.send.openPasswords')}
                  </Button>
                ) : null}
                <Button
                  size="lg"
                  variant={
                    phase.type === 'failed' && !canRetry(phase.reason) ? 'secondary' : 'primary'
                  }
                  onClick={() => close(current.id)}
                >
                  {phase.type === 'failed' ? t('common.close') : t('nearby.pairing.done')}
                </Button>
              </>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function OkBox({ children }: { children: React.ReactNode }) {
  return (
    <p className="flex gap-2.5 rounded-xl border border-ok/30 bg-ok/[0.08] px-3 py-2.5 font-medium">
      <CheckCircle2 aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-ok" strokeWidth={2} />
      {children}
    </p>
  );
}
