import type { TFunction } from 'i18next';
import { describe, expect, it } from 'vitest';
import type { Tunnel } from '@/bindings/Tunnel';
import type { TunnelView } from '@/bindings/TunnelView';
import {
  commandText,
  formOf,
  formProblems,
  isHost,
  isOn,
  listenText,
  parsePort,
  reasonText,
  secondsUntil,
  statusOf,
  tunnelOf,
} from './model';

const t = ((key: string, values?: Record<string, unknown>) =>
  values ? `${key} ${JSON.stringify(values)}` : key) as unknown as TFunction;

const local: Tunnel = {
  id: 'a',
  name: '',
  alias: 'web',
  kind: 'local',
  bindAddress: null,
  listenPort: 8080,
  targetHost: 'db.internal',
  targetPort: 5432,
  autoReconnect: false,
};

function view(partial: Partial<TunnelView>): TunnelView {
  return {
    tunnel: local,
    state: { state: 'off' },
    prompt: null,
    browserUrl: null,
    exposed: false,
    configLine: '',
    ...partial,
  };
}

describe('tunnels model', () => {
  it('writes forwards as ssh does', () => {
    expect(listenText(local)).toBe('localhost:8080');
    expect(listenText({ ...local, kind: 'remote' })).toBe('8080');
    expect(listenText({ ...local, bindAddress: '::1' })).toBe('[::1]:8080');
    expect(commandText(local)).toBe('ssh -N -L localhost:8080:db.internal:5432 web');
    expect(commandText({ ...local, kind: 'dynamic', targetHost: null, targetPort: null })).toBe(
      'ssh -N -D localhost:8080 web',
    );
    expect(commandText({ ...local, listenPort: 0, targetPort: null, alias: '' })).toBe(
      'ssh -N -L localhost:…:db.internal:… …',
    );
  });

  it('says where a tunnel is', () => {
    const now = Date.parse('2026-11-06T12:00:00Z');
    expect(statusOf(t, view({ state: { state: 'up', since: '' } }), now).tone).toBe('ok');
    expect(
      statusOf(
        t,
        view({ tunnel: { ...local, kind: 'remote' }, state: { state: 'up', since: '' } }),
        now,
      ).text,
    ).toBe('tunnels.state.connected {"port":8080}');
    const failure = { reason: 'portUnavailable' as const, exitCode: 255, output: '' };
    const retrying = view({
      state: { state: 'retrying', attempt: 2, at: '2026-11-06T12:00:05Z', failure },
    });
    expect(statusOf(t, retrying, now).text).toBe('tunnels.state.retrying {"seconds":5}');
    expect(reasonText(t, retrying)).toBe('tunnels.reason.portUnavailable {"port":8080}');
    expect(reasonText(t, view({}))).toBeNull();
    expect(isOn(retrying.state)).toBe(true);
    expect(isOn({ state: 'failed', failure })).toBe(false);
    expect(secondsUntil('2026-11-06T11:59:00Z', now)).toBe(0);
  });

  it('checks the form', () => {
    expect(parsePort('22')).toBe(22);
    for (const bad of ['0', '65536', '-1', '8o', '', '1e3']) expect(parsePort(bad)).toBeNull();
    for (const host of ['localhost', '10.0.0.5', 'fd00::5', 'db_1.internal']) {
      expect(isHost(host)).toBe(true);
    }
    for (const host of ['-oProxyCommand=x', 'a b', 'a:b@c', '.x', ''])
      expect(isHost(host)).toBe(false);
    const form = { ...formOf(local, ''), listenPort: 'x' };
    expect(formProblems(form)).toEqual({
      alias: false,
      listenPort: true,
      targetHost: false,
      targetPort: false,
    });
    const socks = tunnelOf({
      ...formOf(null, 'web'),
      kind: 'dynamic',
      listenPort: '1080',
      all: true,
    });
    expect(socks).toMatchObject({ bindAddress: '*', targetHost: null, targetPort: null });
    expect(formOf(null, '').alias).toBe('');
  });
});
