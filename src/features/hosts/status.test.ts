import { describe, expect, it } from 'vitest';
import type { ConnectionEvent } from '@/bindings/ConnectionEvent';
import { hostEvents, hostStatus, outcomeTone, statusTone } from './status';

const event = (at: string, outcome: ConnectionEvent['outcome']): ConnectionEvent => ({
  at,
  via: 'check',
  outcome,
});

const base = { aliases: ['prod'], tabs: [], checking: false, missingKey: false, events: [] };

describe('hostStatus', () => {
  it('puts a live session first, then a running check, a missing key and the last event', () => {
    const events = [event('2026-11-04T10:00:00Z', 'unreachable')];
    const tabs = [
      { key: 'tab-1', alias: 'prod', phase: 'connecting' },
      { key: 'tab-2', alias: 'prod', phase: 'connected' },
      { key: 'tab-3', alias: 'other', phase: 'connected' },
    ];
    expect(hostStatus({ ...base, tabs, checking: true, missingKey: true, events })).toEqual({
      kind: 'connected',
      tab: 'tab-2',
    });
    expect(hostStatus({ ...base, tabs: tabs.slice(0, 1), checking: true })).toEqual({
      kind: 'connecting',
      tab: 'tab-1',
    });
    expect(hostStatus({ ...base, checking: true, missingKey: true, events })).toEqual({
      kind: 'checking',
    });
    expect(hostStatus({ ...base, missingKey: true, events })).toEqual({ kind: 'missingKey' });
    expect(hostStatus({ ...base, events })).toEqual({ kind: 'last', event: events[0] });
    expect(hostStatus(base)).toEqual({ kind: 'never' });
  });

  it('ignores ended sessions and other hosts', () => {
    const tabs = [
      { key: 'tab-1', alias: 'prod', phase: 'ended' },
      { key: 'tab-2', alias: 'prod-2', phase: 'connected' },
    ];
    expect(hostStatus({ ...base, tabs })).toEqual({ kind: 'never' });
  });
});

describe('tones', () => {
  it('tells what to give from what failed', () => {
    expect(outcomeTone('signedIn')).toBe('ok');
    expect(outcomeTone('passphraseMissing')).toBe('warning');
    expect(outcomeTone('hostKeyUnknown')).toBe('warning');
    expect(outcomeTone('hostKeyChanged')).toBe('error');
    expect(outcomeTone('unreachable')).toBe('error');
    expect(statusTone({ kind: 'connected', tab: 't' })).toBe('online');
    expect(statusTone({ kind: 'checking' })).toBe('busy');
    expect(statusTone({ kind: 'never' })).toBe('none');
  });
});

describe('hostEvents', () => {
  it('merges the events of every alias, newest first', () => {
    const history = {
      a: [event('2026-11-04T09:00:00Z', 'signedIn')],
      b: [event('2026-11-04T11:00:00Z', 'failed'), event('2026-11-03T11:00:00Z', 'signedIn')],
    };
    expect(hostEvents(history, ['a', 'b']).map((e) => e.at)).toEqual([
      '2026-11-04T11:00:00Z',
      '2026-11-04T09:00:00Z',
      '2026-11-03T11:00:00Z',
    ]);
    expect(hostEvents(undefined, ['a'])).toEqual([]);
  });
});
