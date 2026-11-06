import type { TFunction } from 'i18next';
import type { Tunnel } from '@/bindings/Tunnel';
import type { TunnelFailure } from '@/bindings/TunnelFailure';
import type { TunnelKind } from '@/bindings/TunnelKind';
import type { TunnelState } from '@/bindings/TunnelState';
import type { TunnelView } from '@/bindings/TunnelView';
import type { Tone } from '@/components/ui/Tile';

export const KINDS: readonly TunnelKind[] = ['local', 'remote', 'dynamic'];

export const KIND_TONE: Record<TunnelKind, Tone> = {
  local: 'cyan',
  remote: 'violet',
  dynamic: 'amber',
};

function bracketed(host: string): string {
  return host.includes(':') ? `[${host}]` : host;
}

/** Where it listens, as `ssh` writes it: `localhost:8080`, `*:1080`, `8080`. */
export function listenText(tunnel: Tunnel): string {
  const bind = tunnel.bindAddress ?? (tunnel.kind === 'remote' ? null : 'localhost');
  return bind ? `${bracketed(bind)}:${tunnel.listenPort}` : String(tunnel.listenPort);
}

export function targetText(tunnel: Tunnel): string {
  return `${bracketed(tunnel.targetHost ?? '')}:${tunnel.targetPort ?? ''}`;
}

/** `localhost:8080 → db:5432`, `Server port 8080 → localhost:3000`, `SOCKS on localhost:1080`. */
export function forwardText(t: TFunction, tunnel: Tunnel): string {
  return t(`tunnels.forward.${tunnel.kind}`, {
    listen: listenText(tunnel),
    target: targetText(tunnel),
  });
}

/** Its name, or the forward. */
export function tunnelTitle(t: TFunction, tunnel: Tunnel): string {
  return tunnel.name.trim() || forwardText(t, tunnel);
}

/**
 * `ssh -N -L localhost:8080:db:5432 web`, without the options the app adds;
 * `…` stands for what is not filled in yet.
 */
export function commandText(tunnel: Tunnel): string {
  const flag = { local: '-L', remote: '-R', dynamic: '-D' }[tunnel.kind];
  const filled: Tunnel = {
    ...tunnel,
    targetHost: tunnel.targetHost || '…',
  };
  const listen = listenText(filled).replace(/(^|:)0$/, '$1…');
  const target = `${bracketed(filled.targetHost ?? '…')}:${tunnel.targetPort ?? '…'}`;
  const spec = tunnel.kind === 'dynamic' ? listen : `${listen}:${target}`;
  return `ssh -N ${flag} ${spec} ${tunnel.alias || '…'}`;
}

/** Started and not given up: the switch shows on. */
export function isOn(state: TunnelState): boolean {
  return state.state === 'connecting' || state.state === 'up' || state.state === 'retrying';
}

/** Changing by itself soon: worth asking the backend again shortly. */
export function isMoving(view: TunnelView): boolean {
  return view.state.state === 'connecting' || view.state.state === 'retrying';
}

export function secondsUntil(at: string, now: number): number {
  return Math.max(0, Math.ceil((Date.parse(at) - now) / 1000));
}

export type StatusTone = 'off' | 'busy' | 'ok' | 'warning' | 'critical' | 'info';

/** The status line: what it says and its colour. */
export function statusOf(
  t: TFunction,
  view: TunnelView,
  now: number,
): { text: string; tone: StatusTone } {
  const { tunnel, state } = view;
  if (view.prompt) return { text: t('tunnels.state.waiting'), tone: 'info' };
  switch (state.state) {
    case 'off':
      return { text: t('tunnels.state.off'), tone: 'off' };
    case 'connecting':
      return {
        text:
          state.attempt > 1
            ? t('tunnels.state.connectingAgain', { attempt: state.attempt })
            : t('tunnels.state.connecting'),
        tone: 'busy',
      };
    case 'up':
      return tunnel.kind === 'remote'
        ? { text: t('tunnels.state.connected', { port: tunnel.listenPort }), tone: 'ok' }
        : { text: t('tunnels.state.listening', { address: listenText(tunnel) }), tone: 'ok' };
    case 'retrying':
      return {
        text: t('tunnels.state.retrying', { seconds: secondsUntil(state.at, now) }),
        tone: 'warning',
      };
    case 'failed':
      return { text: t('tunnels.state.failed'), tone: 'critical' };
  }
}

/** Why it isn't up, in a sentence; `null` when nothing failed. */
export function reasonText(t: TFunction, view: TunnelView): string | null {
  const failure: TunnelFailure | null =
    view.state.state === 'failed' || view.state.state === 'retrying' ? view.state.failure : null;
  if (!failure) return null;
  return t(`tunnels.reason.${failure.reason}`, { port: view.tunnel.listenPort });
}

/** Form state of the tunnel dialog: numbers stay text while typed. */
export interface TunnelForm {
  id: string;
  name: string;
  alias: string;
  kind: TunnelKind;
  /** All addresses instead of loopback (local, SOCKS) or the server's default (remote). */
  all: boolean;
  listenPort: string;
  targetHost: string;
  targetPort: string;
  autoReconnect: boolean;
}

export function formOf(tunnel: Tunnel | null, alias: string): TunnelForm {
  if (!tunnel) {
    return {
      id: '',
      name: '',
      alias,
      kind: 'local',
      all: false,
      listenPort: '',
      targetHost: 'localhost',
      targetPort: '',
      autoReconnect: true,
    };
  }
  return {
    id: tunnel.id,
    name: tunnel.name,
    alias: tunnel.alias,
    kind: tunnel.kind,
    all: tunnel.bindAddress === '*' || tunnel.bindAddress === '0.0.0.0',
    listenPort: String(tunnel.listenPort),
    targetHost: tunnel.targetHost ?? '',
    targetPort: tunnel.targetPort === null ? '' : String(tunnel.targetPort),
    autoReconnect: tunnel.autoReconnect,
  };
}

export function parsePort(text: string): number | null {
  if (!/^\d{1,5}$/.test(text.trim())) return null;
  const port = Number(text);
  return port >= 1 && port <= 65535 ? port : null;
}

export function isHost(host: string): boolean {
  const value = host.trim();
  return (
    value.length > 0 &&
    value.length <= 253 &&
    !/^[-.]/.test(value) &&
    /^[A-Za-z0-9._:-]+$/.test(value) &&
    // A name with a colon must be an IPv6 address.
    (!value.includes(':') || /^[0-9A-Fa-f:.]+$/.test(value))
  );
}

/** The tunnel the form describes, as far as it can be made yet. */
export function tunnelOf(form: TunnelForm): Tunnel {
  const forward = form.kind !== 'dynamic';
  return {
    id: form.id,
    name: form.name.trim(),
    alias: form.alias,
    kind: form.kind,
    bindAddress: form.all ? '*' : null,
    listenPort: parsePort(form.listenPort) ?? 0,
    targetHost: forward ? form.targetHost.trim() : null,
    targetPort: forward ? parsePort(form.targetPort) : null,
    autoReconnect: form.autoReconnect,
  };
}

/** What is wrong with the form, by field. */
export function formProblems(form: TunnelForm): {
  alias: boolean;
  listenPort: boolean;
  targetHost: boolean;
  targetPort: boolean;
} {
  const forward = form.kind !== 'dynamic';
  return {
    alias: form.alias === '',
    listenPort: parsePort(form.listenPort) === null,
    targetHost: forward && !isHost(form.targetHost),
    targetPort: forward && parsePort(form.targetPort) === null,
  };
}
