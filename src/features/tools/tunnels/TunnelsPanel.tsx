import { useQuery } from '@tanstack/react-query';
import { isTauri } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { openUrl } from '@tauri-apps/plugin-opener';
import {
  Cable,
  ChevronDown,
  ClipboardCopy,
  ExternalLink,
  FilePlus2,
  MoreHorizontal,
  Pencil,
  Plus,
  Square,
  Trash2,
  TriangleAlert,
} from 'lucide-react';
import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { toast } from 'sonner';
import { api } from '@/api/commands';
import { queryClient, useConfig } from '@/api/queries';
import { toastError, useAppMutation } from '@/api/useAppMutation';
import type { PromptAnswer } from '@/bindings/PromptAnswer';
import type { TunnelView } from '@/bindings/TunnelView';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState } from '@/components/ui/EmptyState';
import { IconButton } from '@/components/ui/IconButton';
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from '@/components/ui/Menu';
import { Spinner } from '@/components/ui/Spinner';
import { Switch } from '@/components/ui/Switch';
import { Tile } from '@/components/ui/Tile';
import { newTab, waitingText } from '@/features/terminal/model';
import { PromptDialog } from '@/features/terminal/PromptDialog';
import { copyText } from '@/lib/clipboard';
import { cn } from '@/lib/cn';
import { AppError } from '@/lib/ipc';
import { OutputBox } from '../ssh/parts';
import {
  forwardText,
  isMoving,
  isOn,
  KIND_TONE,
  reasonText,
  type StatusTone,
  statusOf,
  tunnelTitle,
} from './model';
import { KIND_ICON, TunnelDialog } from './TunnelDialog';

const TUNNELS = ['tunnels'] as const;
/** Sent by the backend whenever a tunnel changes (`crate::tunnels::CHANGED_EVENT`). */
const CHANGED_EVENT = 'tunnels-changed';

function useTunnels() {
  useEffect(() => {
    if (!isTauri()) return;
    const stop = listen(CHANGED_EVENT, () => {
      void queryClient.invalidateQueries({ queryKey: TUNNELS });
    });
    return () => void stop.then((unlisten) => unlisten());
  }, []);
  return useQuery({
    queryKey: TUNNELS,
    queryFn: api.tunnelList,
    // The desktop app says when something changes; the browser mock can't.
    refetchInterval: (query) => (!isTauri() || query.state.data?.some(isMoving) ? 1000 : false),
  });
}

/** A clock for countdowns, ticking while one is shown. */
function useNow(ticking: boolean): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    if (!ticking) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [ticking]);
  return now;
}

/**
 * The Tunnels tool: saved port forwards, each with a switch, its status and
 * why it stopped. A prompt `ssh` puts to a tunnel opens the terminal's
 * prompt dialog.
 */
export function TunnelsPanel() {
  const { t } = useTranslation();
  const tunnels = useTunnels();
  const views = tunnels.data ?? [];
  const now = useNow(views.some((view) => view.state.state === 'retrying'));
  const [editing, setEditing] = useState<TunnelView | 'new' | null>(null);
  const [deleting, setDeleting] = useState<TunnelView | null>(null);
  const [answering, setAnswering] = useState<{ id: string; prompt: number } | null>(null);
  const [seen, setSeen] = useState<Set<number>>(() => new Set());

  // A new prompt opens its dialog once; closing it leaves "Answer" on the row.
  useEffect(() => {
    const waiting = views.find((view) => view.prompt && !seen.has(view.prompt.id));
    if (waiting?.prompt && !answering) {
      setSeen((current) => new Set(current).add(waiting.prompt?.id ?? 0));
      setAnswering({ id: waiting.tunnel.id, prompt: waiting.prompt.id });
    }
  }, [views, seen, answering]);
  const asking = views.find(
    (view) => view.tunnel.id === answering?.id && view.prompt?.id === answering.prompt,
  );
  const tab = useMemo(() => (asking ? newTab(asking.tunnel.alias) : null), [asking]);

  const stopAll = useAppMutation(() => api.tunnelStopAll(), {
    success: () => t('tunnels.stoppedAll'),
  });
  const remove = useAppMutation((id: string) => api.tunnelDelete(id), {
    onSuccess: () => setDeleting(null),
  });
  const answer = (reply: PromptAnswer) => {
    if (!asking?.prompt) return;
    const { id } = asking.tunnel;
    const prompt = asking.prompt.id;
    setAnswering(null);
    api
      .tunnelAnswer(id, prompt, reply)
      .catch((error: unknown) => toastError(t, error))
      .finally(() => void queryClient.invalidateQueries({ queryKey: TUNNELS }));
  };
  const anyOn = views.some((view) => isOn(view.state));

  return (
    <div className="flex flex-col gap-3.5">
      <div className="flex flex-wrap items-center gap-2.5">
        <p className="min-w-0 flex-1 text-[12.5px] text-muted">{t('tunnels.description')}</p>
        {anyOn ? (
          <Button
            variant="ghost"
            size="sm"
            icon={<Square className="size-3.5" strokeWidth={2.25} />}
            onClick={() => stopAll.mutate(undefined)}
            loading={stopAll.isPending}
          >
            {t('tunnels.stopAll')}
          </Button>
        ) : null}
        {views.length > 0 ? (
          <Button
            variant="primary"
            size="sm"
            icon={<Plus className="size-4" strokeWidth={2.25} />}
            onClick={() => setEditing('new')}
          >
            {t('tunnels.add')}
          </Button>
        ) : null}
      </div>

      {tunnels.isPending ? (
        <div className="grid place-items-center py-10">
          <Spinner className="size-5 text-subtle" />
        </div>
      ) : views.length === 0 ? (
        <EmptyState
          icon={
            <Tile tone="cyan" size={40} glow>
              <Cable className="size-5" strokeWidth={2} />
            </Tile>
          }
          title={t('tunnels.empty.title')}
          description={t('tunnels.empty.body')}
          action={
            <Button
              variant="primary"
              icon={<Plus className="size-4" strokeWidth={2.25} />}
              onClick={() => setEditing('new')}
            >
              {t('tunnels.add')}
            </Button>
          }
        />
      ) : (
        <ul className="glass flex flex-col rounded-2xl p-1.5">
          {views.map((view) => (
            <TunnelRow
              key={view.tunnel.id}
              view={view}
              now={now}
              onEdit={() => setEditing(view)}
              onDelete={() => setDeleting(view)}
              onAnswer={() =>
                view.prompt && setAnswering({ id: view.tunnel.id, prompt: view.prompt.id })
              }
            />
          ))}
        </ul>
      )}

      <Dialog
        open={editing !== null}
        onOpenChange={(open) => (open ? undefined : setEditing(null))}
      >
        {editing !== null ? (
          <TunnelDialog
            editing={editing === 'new' ? null : editing}
            onDone={() => setEditing(null)}
          />
        ) : null}
      </Dialog>
      <Dialog
        open={Boolean(asking && tab)}
        onOpenChange={(open) => (open ? undefined : setAnswering(null))}
      >
        {asking?.prompt && tab ? (
          <PromptDialog tab={tab} ask={asking.prompt.ask} onAnswer={answer} />
        ) : null}
      </Dialog>
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => (open ? undefined : setDeleting(null))}
        title={t('tunnels.delete.title', {
          name: deleting ? tunnelTitle(t, deleting.tunnel) : '',
        })}
        description={t('tunnels.delete.body')}
        confirmLabel={t('tunnels.delete.confirm')}
        destructive
        busy={remove.isPending}
        onConfirm={() => deleting && remove.mutate(deleting.tunnel.id)}
      />
    </div>
  );
}

const DOT: Record<StatusTone, string> = {
  off: 'bg-faint',
  busy: 'bg-info-solid',
  ok: 'bg-ok shadow-[0_0_8px_var(--color-ok)]',
  warning: 'bg-warning-solid',
  critical: 'bg-critical-solid',
  info: 'bg-info-solid',
};
const TEXT: Record<StatusTone, string> = {
  off: 'text-subtle',
  busy: 'text-info',
  ok: 'text-ok',
  warning: 'text-warning',
  critical: 'text-critical',
  info: 'text-info',
};

function TunnelRow({
  view,
  now,
  onEdit,
  onDelete,
  onAnswer,
}: {
  view: TunnelView;
  now: number;
  onEdit: () => void;
  onDelete: () => void;
  onAnswer: () => void;
}) {
  const { t } = useTranslation();
  const config = useConfig();
  const { tunnel, state } = view;
  const on = isOn(state);
  const title = tunnelTitle(t, tunnel);
  const status = statusOf(t, view, now);
  const reason = reasonText(t, view);
  const failure = state.state === 'failed' || state.state === 'retrying' ? state.failure : null;
  const [details, setDetails] = useState(false);
  const Icon = KIND_ICON[tunnel.kind];

  const toggle = useAppMutation((next: boolean) => api.tunnelSetOn(tunnel.id, next));
  const exportLine = useAppMutation(
    () => api.tunnelExport(tunnel.id, config.data?.view.revision ?? ''),
    {
      success: () => t('tunnels.exported', { line: view.configLine }),
      onError: (error) => {
        if (error.code !== 'not_found') return false;
        toast.error(t('tunnels.noBlock', { alias: tunnel.alias }));
        return true;
      },
    },
  );
  const copyLine = () =>
    copyText(view.configLine)
      .then(() => toast.success(t('tunnels.copied', { line: view.configLine })))
      .catch((error: unknown) => toastError(t, AppError.from(error)));
  const open = () => {
    if (!view.browserUrl) return;
    if (isTauri()) void openUrl(view.browserUrl).catch((error: unknown) => toastError(t, error));
    else window.open(view.browserUrl, '_blank', 'noopener');
  };

  return (
    <li className="flex items-start gap-3 rounded-xl px-2.5 py-2.5">
      <Tile tone={KIND_TONE[tunnel.kind]} size={34} className={cn(!on && 'opacity-60')}>
        <Icon className="size-[17px]" strokeWidth={2} />
      </Tile>
      <div className="flex min-w-0 flex-1 flex-col gap-0.5">
        <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1">
          <span className="truncate font-semibold">{title}</span>
          {view.exposed ? (
            <Badge tone="warning">
              <TriangleAlert aria-hidden="true" className="mr-1 size-3" strokeWidth={2.25} />
              {t('tunnels.dialog.bindAll')}
            </Badge>
          ) : null}
        </div>
        <span className="truncate font-mono text-[12px] text-subtle">
          {tunnel.name.trim() ? `${forwardText(t, tunnel)} · ` : ''}
          {t(`tunnels.kind.${tunnel.kind}`)} · {t('tunnels.via', { alias: tunnel.alias })}
        </span>
        <div aria-live="polite" className="mt-1 flex min-w-0 flex-col gap-1">
          <span className={cn('flex items-center gap-1.5 text-[12.5px]', TEXT[status.tone])}>
            {status.tone === 'busy' ? (
              <Spinner className="size-3" />
            ) : (
              <span
                aria-hidden="true"
                className={cn('size-2 shrink-0 rounded-full', DOT[status.tone])}
              />
            )}
            {status.text}
            {view.prompt ? (
              <span className="text-muted">
                {' — '}
                {waitingText(t, newTab(tunnel.alias), view.prompt.ask)}
              </span>
            ) : null}
          </span>
          {reason ? <span className="text-[12.5px] text-fg-2">{reason}</span> : null}
          {view.exposed && on ? (
            <span className="text-[12px] text-warning">{t('tunnels.exposed')}</span>
          ) : null}
        </div>
        {failure?.output ? (
          <div className="mt-1 flex flex-col gap-1.5">
            <button
              type="button"
              aria-expanded={details}
              onClick={() => setDetails(!details)}
              className="pressable flex w-fit items-center gap-1 rounded-md text-[12px] font-medium text-subtle hover:text-fg"
            >
              <ChevronDown
                aria-hidden="true"
                className={cn('size-3.5 transition-transform', details && 'rotate-180')}
              />
              {t('tunnels.output')}
            </button>
            {details ? <OutputBox text={failure.output} /> : null}
          </div>
        ) : null}
      </div>
      <div className="flex shrink-0 items-center gap-1.5 pt-0.5">
        {view.prompt ? (
          <Button size="sm" variant="soft" onClick={onAnswer}>
            {t('tunnels.answer')}
          </Button>
        ) : null}
        {view.browserUrl && state.state === 'up' ? (
          <IconButton
            label={t('tunnels.openBrowser')}
            icon={<ExternalLink className="size-4" strokeWidth={2} />}
            onClick={open}
          />
        ) : null}
        <Menu>
          <MenuTrigger asChild>
            <IconButton
              label={t('tunnels.actions', { name: title })}
              icon={<MoreHorizontal className="size-4" strokeWidth={2} />}
            />
          </MenuTrigger>
          <MenuContent align="end">
            <MenuItem icon={<Pencil className="size-4" />} onSelect={onEdit}>
              {t('tunnels.edit')}
            </MenuItem>
            <MenuItem icon={<ClipboardCopy className="size-4" />} onSelect={() => void copyLine()}>
              {t('tunnels.copyLine')}
            </MenuItem>
            <MenuItem
              icon={<FilePlus2 className="size-4" />}
              disabled={!config.data}
              onSelect={() => exportLine.mutate(undefined)}
            >
              {t('tunnels.export')}
            </MenuItem>
            <MenuSeparator />
            <MenuItem destructive icon={<Trash2 className="size-4" />} onSelect={onDelete}>
              {t('common.delete')}
            </MenuItem>
          </MenuContent>
        </Menu>
        <Switch
          checked={toggle.isPending ? toggle.variables : on}
          onCheckedChange={(next) => toggle.mutate(next)}
          aria-label={title}
          className="ml-1"
        />
      </div>
    </li>
  );
}
