import { CheckCircle2, Laptop, XCircle } from 'lucide-react';
import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError, useAppMutation } from '@/api/useAppMutation';
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
import { canRetry, isActive } from './model';
import { useNearby } from './queries';

const FAILURES = {
  unreachable: 'nearby.pairing.unreachable',
  declined: 'nearby.pairing.declined',
  peerDeclined: 'nearby.pairing.peerDeclined',
  cancelled: 'nearby.pairing.cancelled',
  peerLeft: 'nearby.pairing.peerLeft',
  timedOut: 'nearby.pairing.timedOut',
  vaultLocked: 'nearby.pairing.vaultLocked',
  version: 'nearby.pairing.version',
  broken: 'nearby.pairing.broken',
} as const satisfies Record<PairingFailure, string>;

/**
 * App-wide: a pairing with another device, from either side. Both users
 * compare the code on their screens; the backend saves the contact only when
 * both say it matches. Mounted once in the shell.
 */
export function PairingDialog() {
  const { t } = useTranslation();
  const status = useNearby();
  const pairing = status.data?.pairing ?? null;
  // The last pairing shown stays while the dialog animates out.
  const shown = useRef<Pairing | null>(null);
  if (pairing) shown.current = pairing;
  const current = pairing ?? shown.current;

  const answer = useAppMutation((vars: { id: number; matched: boolean }) =>
    api.nearbyAnswer(vars.id, vars.matched),
  );
  const close = (id: number) => void api.nearbyClose(id).catch((error) => toastError(t, error));

  // Each step replaces the buttons, and the focused one with them: focus
  // "They differ" when the codes come up, else the one button left.
  const footer = useRef<HTMLDivElement>(null);
  const step = pairing?.phase.type;
  useEffect(() => {
    if (!step) return;
    const buttons = footer.current?.querySelectorAll<HTMLElement>('button');
    const target = step === 'compare' ? buttons?.[0] : buttons?.[buttons.length - 1];
    target?.focus();
  }, [step]);

  if (!current) return null;
  // The name comes with the other side's first message; until then the
  // dialog names nobody. Every sentence that names it comes after.
  const peer = current.peer ?? '';
  const phase = current.phase;
  const active = isActive(current);
  const code = phase.type === 'compare' || phase.type === 'waiting' ? phase.code : null;

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
          title={
            !current.peer
              ? t('nearby.pairing.title')
              : current.outgoing
                ? t('nearby.pairing.titleOut', { peer })
                : t('nearby.pairing.titleIn', { peer })
          }
          description={t('nearby.pairing.description')}
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
            {phase.type === 'compare' ? (
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
              <Button
                size="lg"
                variant={
                  phase.type === 'failed' && !canRetry(phase.reason) ? 'secondary' : 'primary'
                }
                onClick={() => close(current.id)}
              >
                {phase.type === 'failed' ? t('common.close') : t('nearby.pairing.done')}
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
