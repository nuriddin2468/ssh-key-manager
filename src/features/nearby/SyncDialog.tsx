import { AlertTriangle, CheckCircle2, RefreshCw, XCircle } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { Pairing } from '@/bindings/Pairing';
import type { Review } from '@/bindings/Review';
import type { SyncDecisions } from '@/bindings/SyncDecisions';
import type { SyncSummary } from '@/bindings/SyncSummary';
import { Button } from '@/components/ui/Button';
import { Checkbox } from '@/components/ui/Checkbox';
import { ChoiceCards } from '@/components/ui/ChoiceCards';
import {
  Dialog,
  DialogBody,
  DialogContent,
  DialogFooter,
  DialogHeader,
} from '@/components/ui/Dialog';
import { Spinner } from '@/components/ui/Spinner';
import { Tile } from '@/components/ui/Tile';
import { shortFingerprint } from '@/lib/format';
import { conflictRows, isActive, summaryLine } from './model';
import { FAILURES } from './PairingDialog';
import { useNearby } from './queries';

/**
 * App-wide: a sync this computer started with one of the user's devices.
 * The user decides here on conflicts, risky directives and many deletions;
 * a sync the other device started only ends in a notice. Mounted once in
 * the shell.
 */
export function SyncDialog() {
  const { t } = useTranslation();
  const { navigate } = useRouter();
  const status = useNearby();
  const pairing = status.data?.pairing ?? null;
  const ours = pairing?.kind === 'sync' && pairing.outgoing ? pairing : null;
  // The last sync shown stays while the dialog animates out.
  const shown = useRef<Pairing | null>(null);
  if (ours) shown.current = ours;
  const current = ours ?? shown.current;

  const close = (id: number) => void api.nearbyClose(id).catch((error) => toastError(t, error));

  if (!current) return null;
  const peer = current.peer ?? '';
  const phase = current.phase;
  const active = isActive(current);

  return (
    <Dialog open={ours !== null} onOpenChange={(open) => open || close(current.id)}>
      <DialogContent section="nearby" className="max-w-[560px]" dismissible={!active}>
        <DialogHeader
          closable={!active}
          icon={
            <Tile tone="orange" size={44} glow>
              <RefreshCw className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={
            phase.type === 'synced'
              ? t('nearby.sync.titleDone', { peer })
              : t('nearby.sync.title', { peer })
          }
          description={t('nearby.sync.description')}
        />
        {phase.type === 'decide' ? (
          <Decide
            key={current.id}
            id={current.id}
            peer={peer}
            review={phase.review}
            onCancel={() => close(current.id)}
          />
        ) : (
          <>
            <DialogBody>
              <div role="status" className="flex flex-col gap-3">
                {phase.type === 'connecting' || phase.type === 'syncing' ? (
                  <p className="flex items-center justify-center gap-2.5 py-6 text-[13px] text-subtle">
                    <Spinner className="size-4" />
                    {t('nearby.sync.syncing')}
                  </p>
                ) : null}
                {phase.type === 'synced' ? <Summary peer={peer} summary={phase.summary} /> : null}
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
              {active ? (
                <Button size="lg" onClick={() => close(current.id)}>
                  {t('common.cancel')}
                </Button>
              ) : (
                <>
                  {phase.type === 'synced' ? (
                    <Button
                      size="lg"
                      onClick={() => {
                        close(current.id);
                        navigate({ page: 'hosts' });
                      }}
                    >
                      {t('nearby.sync.openHosts')}
                    </Button>
                  ) : null}
                  <Button size="lg" variant="primary" autoFocus onClick={() => close(current.id)}>
                    {phase.type === 'failed' ? t('common.close') : t('nearby.pairing.done')}
                  </Button>
                </>
              )}
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

type Version = 'mine' | 'theirs' | '';
type Risky = 'apply' | 'decline' | '';

/** What the sync brings that needs the user: each choice optional. */
function Decide({
  id,
  peer,
  review,
  onCancel,
}: {
  id: number;
  peer: string;
  review: Review;
  onCancel: () => void;
}) {
  const { t } = useTranslation();
  const [versions, setVersions] = useState<Record<string, Version>>({});
  const [risky, setRisky] = useState<Record<string, Risky>>({});
  const [remove, setRemove] = useState(false);
  const decide = useAppMutation((decisions: SyncDecisions) => api.nearbyDecide(id, decisions));
  const first = useRef<HTMLParagraphElement>(null);
  useEffect(() => first.current?.focus(), []);

  const ids = (choices: Record<string, string>, value: string) =>
    Object.entries(choices)
      .filter(([, choice]) => choice === value)
      .map(([host]) => host);
  const submit = () =>
    decide.mutate({
      mine: ids(versions, 'mine'),
      theirs: ids(versions, 'theirs'),
      apply: ids(risky, 'apply'),
      decline: ids(risky, 'decline'),
      delete: remove,
    });

  return (
    <>
      <DialogBody>
        <p ref={first} tabIndex={-1} className="text-[13px] leading-5 text-fg-2 outline-none">
          {t('nearby.sync.decide')}
        </p>

        {review.conflicts.length > 0 ? (
          <section aria-labelledby="sync-conflicts" className="flex flex-col gap-2">
            <div className="flex flex-col">
              <h3 id="sync-conflicts" className="text-[13px] font-semibold">
                {t('nearby.sync.conflicts')}
              </h3>
              <span className="text-[12px] text-subtle">{t('nearby.sync.conflictsHint')}</span>
            </div>
            {review.conflicts.map((conflict) => (
              <div key={conflict.id} className="glass flex flex-col gap-2.5 rounded-xl p-3">
                <span className="selectable font-mono text-[13px] font-medium">{conflict.id}</span>
                <table aria-label={conflict.id} className="w-full table-fixed text-[12px]">
                  <thead>
                    <tr className="text-left text-subtle">
                      <th scope="col" className="w-[34%] pb-1 font-medium" />
                      <th scope="col" className="pb-1 font-medium">
                        {t('nearby.sync.here')}
                      </th>
                      <th scope="col" className="pb-1 font-medium">
                        {peer}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {conflict.mine === null || conflict.theirs === null ? (
                      <tr>
                        <td />
                        <td className="text-fg-2">
                          {conflict.mine === null ? t('nearby.sync.deleted') : '—'}
                        </td>
                        <td className="text-fg-2">
                          {conflict.theirs === null ? t('nearby.sync.deleted') : '—'}
                        </td>
                      </tr>
                    ) : null}
                    {conflictRows(conflict)
                      .filter((row) => row.differs)
                      .map((row) => (
                        <tr key={row.key} className="align-top">
                          <th
                            scope="row"
                            className="py-0.5 pr-2 text-left font-mono font-normal text-subtle"
                          >
                            {row.key}
                          </th>
                          <td className="selectable py-0.5 pr-2 font-mono break-all text-fg-2">
                            {row.mine ?? '—'}
                          </td>
                          <td className="selectable py-0.5 font-mono break-all text-fg-2">
                            {row.theirs ?? '—'}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
                <ChoiceCards<Version>
                  legend={conflict.id}
                  legendHidden
                  columns={2}
                  value={versions[conflict.id] ?? ''}
                  onValueChange={(value) =>
                    setVersions((current) => ({ ...current, [conflict.id]: value }))
                  }
                  options={[
                    { value: 'mine', title: t('nearby.sync.keepMine') },
                    { value: 'theirs', title: t('nearby.sync.takeTheirs', { peer }) },
                  ]}
                />
              </div>
            ))}
          </section>
        ) : null}

        {review.risky.length > 0 ? (
          <section aria-labelledby="sync-risky" className="flex flex-col gap-2">
            <div className="flex flex-col">
              <h3 id="sync-risky" className="flex items-center gap-1.5 text-[13px] font-semibold">
                <AlertTriangle
                  aria-hidden="true"
                  className="size-3.5 text-warning"
                  strokeWidth={2.2}
                />
                {t('nearby.sync.risky')}
              </h3>
              <span className="text-[12px] text-subtle">{t('nearby.sync.riskyHint')}</span>
            </div>
            {review.risky.map((change) => (
              <div
                key={change.id}
                className="flex flex-col gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.07] p-3"
              >
                <span className="selectable font-mono text-[13px] font-medium">{change.id}</span>
                <ul className="flex flex-col gap-0.5">
                  {change.lines.map((line) => (
                    <li
                      key={`${line.key} ${line.value}`}
                      className="selectable font-mono text-[12px] break-all text-fg-2"
                    >
                      {line.key} {line.value}
                    </li>
                  ))}
                </ul>
                <ChoiceCards<Risky>
                  legend={change.id}
                  legendHidden
                  columns={2}
                  value={risky[change.id] ?? ''}
                  onValueChange={(value) =>
                    setRisky((current) => ({ ...current, [change.id]: value }))
                  }
                  options={[
                    { value: 'apply', title: t('nearby.sync.add') },
                    { value: 'decline', title: t('nearby.sync.dontAdd') },
                  ]}
                />
              </div>
            ))}
          </section>
        ) : null}

        {review.deletions.length > 0 ? (
          <section aria-labelledby="sync-deletions" className="flex flex-col gap-2">
            <h3 id="sync-deletions" className="text-[13px] font-semibold">
              {t('nearby.sync.deletions', { peer, count: review.deletions.length })}
            </h3>
            <p className="selectable font-mono text-[12px] leading-[18px] break-words text-fg-2">
              {review.deletions.join(', ')}
            </p>
            <Checkbox
              checked={remove}
              onCheckedChange={(checked) => setRemove(checked === true)}
              label={t('nearby.sync.deleteToo')}
            />
          </section>
        ) : null}
      </DialogBody>
      <DialogFooter>
        <Button size="lg" disabled={decide.isPending} onClick={onCancel}>
          {t('common.cancel')}
        </Button>
        <Button size="lg" variant="primary" loading={decide.isPending} onClick={submit}>
          {t('nearby.sync.continue')}
        </Button>
      </DialogFooter>
    </>
  );
}

/** How a sync went on this computer. */
function Summary({ peer, summary }: { peer: string; summary: SyncSummary }) {
  const { t } = useTranslation();
  const notes = [
    summary.deferred ? t('nearby.sync.deferred', { count: summary.deferred }) : null,
    summary.deferredThere
      ? t('nearby.sync.deferredThere', { count: summary.deferredThere, peer })
      : null,
    summary.conflicts ? t('nearby.sync.conflictsLeft', { count: summary.conflicts }) : null,
    summary.failed ? t('nearby.sync.failed', { count: summary.failed }) : null,
  ].filter((note) => note !== null);
  return (
    <>
      <p className="flex gap-2.5 rounded-xl border border-ok/30 bg-ok/[0.08] px-3 py-2.5 font-medium">
        <CheckCircle2
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-ok"
          strokeWidth={2}
        />
        {summaryLine(t, summary)}
      </p>
      {notes.length > 0 ? (
        <ul className="flex flex-col gap-1 text-[12.5px] leading-[18px] text-fg-2">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      ) : null}
      {summary.keysDiffer.length > 0 ? (
        <div className="flex flex-col gap-2 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.09] px-3 py-2.5">
          <span className="flex items-center gap-2 font-medium">
            <AlertTriangle
              aria-hidden="true"
              className="size-4 shrink-0 text-warning"
              strokeWidth={2}
            />
            {t('nearby.sync.keysDiffer')}
          </span>
          <span className="text-[12.5px] leading-[18px] text-fg-2">
            {t('nearby.sync.keysDifferText', { peer })}
          </span>
          <ul className="flex flex-col gap-1.5">
            {summary.keysDiffer.map((host) => (
              <li key={`${host.host}:${host.port}`} className="flex flex-col text-[12px]">
                <span className="selectable font-mono font-medium">
                  {host.port === 22 ? host.host : `${host.host}:${host.port}`}
                </span>
                <span className="selectable font-mono text-subtle">
                  {t('nearby.sync.here')}: {host.here.map(shortFingerprint).join(', ')}
                </span>
                <span className="selectable font-mono text-subtle">
                  {peer}: {host.there.map(shortFingerprint).join(', ')}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </>
  );
}
