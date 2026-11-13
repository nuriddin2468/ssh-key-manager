import {
  AlertTriangle,
  Braces,
  CheckCircle2,
  Eye,
  EyeOff,
  Folder,
  Info,
  KeyRound,
  Link2,
  RefreshCw,
  Server,
  XCircle,
} from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { api } from '@/api/commands';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import { useRouter } from '@/app/router';
import type { Pairing } from '@/bindings/Pairing';
import type { Review } from '@/bindings/Review';
import type { SyncDecisions } from '@/bindings/SyncDecisions';
import type { SyncItemKind } from '@/bindings/SyncItemKind';
import type { SyncSummary } from '@/bindings/SyncSummary';
import type { VaultChange } from '@/bindings/VaultChange';
import type { VaultConflict } from '@/bindings/VaultConflict';
import { Badge } from '@/components/ui/Badge';
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
import {
  canShow,
  conflictRows,
  conflictStory,
  deletionGroups,
  fieldLabel,
  fieldLabels,
  isActive,
  summaryLines,
  vaultOffText,
} from './model';
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
  const [vaultVersions, setVaultVersions] = useState<Record<string, Version>>({});
  const [vaultRisky, setVaultRisky] = useState<Record<string, Risky>>({});
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
      vaultMine: ids(vaultVersions, 'mine'),
      vaultTheirs: ids(vaultVersions, 'theirs'),
      vaultApply: ids(vaultRisky, 'apply'),
      vaultDecline: ids(vaultRisky, 'decline'),
    });
  const vault = review.vault;
  const deletionCount = review.deletions.length + vault.deletions.length;

  return (
    <>
      <DialogBody>
        <p ref={first} tabIndex={-1} className="text-[13px] leading-5 text-fg-2 outline-none">
          {t('nearby.sync.decide')}
        </p>

        {review.conflicts.length + vault.conflicts.length > 0 ? (
          <section aria-labelledby="sync-conflicts" className="flex flex-col gap-2">
            <div className="flex flex-col">
              <h3 id="sync-conflicts" className="text-[13px] font-semibold">
                {t('nearby.sync.conflicts')}
              </h3>
              <span className="text-[12px] text-subtle">{t('nearby.sync.conflictsHint')}</span>
            </div>
            {review.conflicts.map((conflict) => (
              <div key={conflict.id} className="glass flex flex-col gap-2.5 rounded-xl p-3">
                <HostTitle id={conflict.id} />
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
            {vault.conflicts.map((conflict) => (
              <VaultConflictCard
                key={conflict.id}
                id={id}
                peer={peer}
                conflict={conflict}
                value={vaultVersions[conflict.id] ?? ''}
                onChange={(value) =>
                  setVaultVersions((current) => ({ ...current, [conflict.id]: value }))
                }
              />
            ))}
            {vault.conflicts.some((conflict) => conflict.kind !== 'folder') ? (
              <p className="text-[12px] leading-[18px] text-subtle">
                {t('nearby.sync.vault.historyNote')}
              </p>
            ) : null}
          </section>
        ) : null}

        {review.risky.length + vault.risky.length > 0 ? (
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
                <HostTitle id={change.id} />
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
            {vault.risky.map((change) => (
              <RiskyVariablesCard
                key={change.id}
                change={change}
                value={vaultRisky[change.id] ?? ''}
                onChange={(value) =>
                  setVaultRisky((current) => ({ ...current, [change.id]: value }))
                }
              />
            ))}
          </section>
        ) : null}

        {deletionCount > 0 ? (
          <section aria-labelledby="sync-deletions" className="flex flex-col gap-2">
            <h3 id="sync-deletions" className="text-[13px] font-semibold">
              {vault.deletions.length > 0
                ? t('nearby.sync.vault.deletions', { peer, count: deletionCount })
                : t('nearby.sync.deletions', { peer, count: review.deletions.length })}
            </h3>
            {review.deletions.length > 0 ? (
              <p className="text-[12px] leading-[18px] break-words text-fg-2">
                {vault.deletions.length > 0 ? (
                  <span className="text-subtle">{t('nearby.sync.vault.kinds.hosts')}: </span>
                ) : null}
                <span className="selectable font-mono">{review.deletions.join(', ')}</span>
              </p>
            ) : null}
            {deletionGroups(t, vault.deletions).map((group) => (
              <p key={group.kind} className="text-[12px] leading-[18px] break-words text-fg-2">
                <span className="text-subtle">{group.kind}: </span>
                <span className="selectable">{group.names.join(', ')}</span>
              </p>
            ))}
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
  const lines = summaryLines(t, summary);
  return (
    <>
      <div className="flex gap-2.5 rounded-xl border border-ok/30 bg-ok/[0.08] px-3 py-2.5 font-medium">
        <CheckCircle2
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-ok"
          strokeWidth={2}
        />
        {lines.length > 1 ? (
          <ul className="flex flex-col gap-0.5">
            {lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        ) : (
          <p>{lines[0]}</p>
        )}
      </div>
      {summary.vaultOff ? (
        <p className="flex gap-2.5 rounded-xl border border-info-solid/30 bg-info-solid/10 px-3 py-2.5 text-[12.5px] leading-[18px] text-fg-2">
          <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-info" strokeWidth={2} />
          {vaultOffText(t, summary.vaultOff, peer)}
        </p>
      ) : null}
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

/** The icon of a kind of the vault's items. */
function KindIcon({ kind }: { kind: SyncItemKind }) {
  const icons = { login: KeyRound, environment: Braces, shared: Link2, folder: Folder };
  const Icon = icons[kind];
  return (
    <Icon aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-subtle" strokeWidth={2} />
  );
}

/** A host's alias as a conflict or a risky change shows it, with the icon items have. */
function HostTitle({ id }: { id: string }) {
  const { t } = useTranslation();
  return (
    <div className="flex items-start gap-2">
      <Server aria-hidden="true" className="mt-0.5 size-3.5 shrink-0 text-subtle" strokeWidth={2} />
      <span className="selectable font-mono text-[13px] font-medium break-all">
        <span className="sr-only">{t('nearby.sync.vault.kind.host')}: </span>
        {id}
      </span>
    </div>
  );
}

/** An item's title, with its kind for screen readers (sighted users have the icon). */
function ItemTitle({ kind, title }: { kind: SyncItemKind; title: string }) {
  const { t } = useTranslation();
  return (
    <span className="selectable text-[13px] font-medium break-words">
      <span className="sr-only">{t(`nearby.sync.vault.kind.${kind}`)}: </span>
      {title}
    </span>
  );
}

/** One of the vault's items both computers changed: what differs, its values on request, the choice. */
function VaultConflictCard({
  id,
  peer,
  conflict,
  value,
  onChange,
}: {
  id: number;
  peer: string;
  conflict: VaultConflict;
  value: Version;
  onChange: (value: Version) => void;
}) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const labels = fieldLabels(t, conflict.fields, conflict.kind);
  const both = conflict.here === 'changed' && conflict.there === 'changed';
  const showable = both ? conflict.fields.filter(canShow) : [];
  const title = conflict.label || conflict.id;
  return (
    <div className="glass flex flex-col gap-2.5 rounded-xl p-3">
      <div className="flex items-start gap-2">
        <KindIcon kind={conflict.kind} />
        <div className="flex min-w-0 flex-col">
          <ItemTitle kind={conflict.kind} title={title} />
          <span className="text-[12px] text-subtle">{conflictStory(t, conflict, peer)}</span>
        </div>
      </div>
      {labels.length > 0 ? (
        <div className="flex flex-wrap items-center gap-1.5 text-[12px] text-subtle">
          <span>{t('nearby.sync.vault.differs')}</span>
          {labels.map((label) => (
            <Badge key={label} mono>
              {label}
            </Badge>
          ))}
        </div>
      ) : null}
      {showable.length > 0 ? (
        <>
          <Button
            size="sm"
            variant="ghost"
            className="-ml-2 self-start"
            aria-expanded={open}
            onClick={() => setOpen((current) => !current)}
          >
            {open ? (
              <EyeOff aria-hidden="true" className="size-3.5" strokeWidth={2} />
            ) : (
              <Eye aria-hidden="true" className="size-3.5" strokeWidth={2} />
            )}
            {open ? t('nearby.sync.vault.hideValues') : t('nearby.sync.vault.showValues')}
          </Button>
          {open ? (
            <ConflictValues id={id} peer={peer} conflict={conflict} fields={showable} />
          ) : null}
        </>
      ) : null}
      <ChoiceCards<Version>
        legend={title}
        legendHidden
        columns={2}
        value={value}
        onValueChange={onChange}
        options={[
          { value: 'mine', title: t('nearby.sync.keepMine') },
          { value: 'theirs', title: t('nearby.sync.takeTheirs', { peer }) },
        ]}
      />
    </div>
  );
}

/** A conflict's text fields: each one's two values once the user asks for them. */
function ConflictValues({
  id,
  peer,
  conflict,
  fields,
}: {
  id: number;
  peer: string;
  conflict: VaultConflict;
  fields: string[];
}) {
  const { t } = useTranslation();
  const [shown, setShown] = useState<Record<string, { mine: string; theirs: string }>>({});
  // The button goes once the values come: the focus goes to its row.
  const rows = useRef<Record<string, HTMLTableCellElement | null>>({});
  const [focus, setFocus] = useState<string | null>(null);
  useEffect(() => {
    if (focus) rows.current[focus]?.focus();
  }, [focus]);
  const show = async (field: string) => {
    try {
      // One after the other: past the free secrets, each is asked for in
      // a dialog of its own.
      const mine = await api.nearbySyncValue(id, conflict.id, field, false);
      const theirs = await api.nearbySyncValue(id, conflict.id, field, true);
      setShown((current) => ({ ...current, [field]: { mine, theirs } }));
      setFocus(field);
    } catch (error) {
      toastError(t, error);
    }
  };
  return (
    <table aria-label={conflict.label || conflict.id} className="w-full table-fixed text-[12px]">
      <thead>
        <tr className="text-left text-subtle">
          <th scope="col" className="w-[30%] pb-1 font-medium" />
          <th scope="col" className="pb-1 font-medium">
            {t('nearby.sync.here')}
          </th>
          <th scope="col" className="pb-1 font-medium">
            {peer}
          </th>
        </tr>
      </thead>
      <tbody>
        {fields.map((field) => {
          const values = shown[field];
          const label = fieldLabel(t, field, conflict.kind);
          return (
            <tr key={field} className="align-top">
              <th
                scope="row"
                tabIndex={-1}
                ref={(cell) => {
                  rows.current[field] = cell;
                }}
                className="py-0.5 pr-2 text-left font-mono font-normal text-subtle outline-none"
              >
                {label}
              </th>
              {values ? (
                <>
                  <td className="selectable py-0.5 pr-2 font-mono break-all text-fg-2">
                    {values.mine || '—'}
                  </td>
                  <td className="selectable py-0.5 font-mono break-all text-fg-2">
                    {values.theirs || '—'}
                  </td>
                </>
              ) : (
                <td colSpan={2} className="py-0.5">
                  <Button
                    size="sm"
                    variant="ghost"
                    aria-label={`${t('nearby.sync.vault.show')}: ${label}`}
                    onClick={() => void show(field)}
                  >
                    {t('nearby.sync.vault.show')}
                  </Button>
                </td>
              )}
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** An environment's variables a sync would add or change that make programs load code. */
function RiskyVariablesCard({
  change,
  value,
  onChange,
}: {
  change: VaultChange;
  value: Risky;
  onChange: (value: Risky) => void;
}) {
  const { t } = useTranslation();
  const title = change.label || change.id;
  return (
    <div className="flex flex-col gap-2.5 rounded-xl border border-warning-solid/30 bg-warning-solid/[0.07] p-3">
      <div className="flex items-start gap-2">
        <KindIcon kind={change.kind} />
        <div className="flex min-w-0 flex-col">
          <ItemTitle kind={change.kind} title={title} />
          <span className="text-[12px] text-subtle">{t('nearby.sync.vault.riskyVariables')}</span>
        </div>
      </div>
      <ul className="flex flex-col gap-0.5">
        {change.risky.map((name) => (
          <li key={name} className="selectable font-mono text-[12px] break-all text-fg-2">
            {name}
          </li>
        ))}
      </ul>
      <ChoiceCards<Risky>
        legend={title}
        legendHidden
        columns={2}
        value={value}
        onValueChange={onChange}
        options={[
          { value: 'apply', title: t('nearby.sync.add') },
          { value: 'decline', title: t('nearby.sync.dontAdd') },
        ]}
      />
    </div>
  );
}
