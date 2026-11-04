import { describe, expect, it } from 'vitest';
import type { Pairing } from '@/bindings/Pairing';
import { canRetry, clock, isActive, isAddress, secondsLeft } from './model';

describe('secondsLeft', () => {
  it('counts down to the end and stops at zero', () => {
    const now = Date.parse('2026-11-04T12:00:00Z');
    expect(secondsLeft('2026-11-04T12:09:30Z', now)).toBe(570);
    expect(secondsLeft('2026-11-04T11:59:00Z', now)).toBe(0);
    expect(secondsLeft(null, now)).toBeNull();
    expect(secondsLeft('soon', now)).toBeNull();
  });
});

describe('clock', () => {
  it('shows minutes and seconds', () => {
    expect(clock(570)).toBe('9:30');
    expect(clock(65)).toBe('1:05');
    expect(clock(0)).toBe('0:00');
  });
});

describe('isActive', () => {
  const pairing = (phase: Pairing['phase']): Pairing => ({
    id: 1,
    peer: null,
    outgoing: true,
    phase,
  });

  it('is true until the pairing ends', () => {
    expect(isActive(pairing({ type: 'connecting' }))).toBe(true);
    expect(isActive(pairing({ type: 'compare', code: '123456' }))).toBe(true);
    expect(isActive(pairing({ type: 'waiting', code: '123456' }))).toBe(true);
    expect(isActive(pairing({ type: 'paired' }))).toBe(false);
    expect(isActive(pairing({ type: 'failed', reason: 'unreachable' }))).toBe(false);
    expect(isActive(null)).toBe(false);
  });
});

describe('canRetry', () => {
  it('offers another try after a failure, not after a decision', () => {
    expect(canRetry('unreachable')).toBe(true);
    expect(canRetry('peerLeft')).toBe(true);
    expect(canRetry('declined')).toBe(false);
    expect(canRetry('peerDeclined')).toBe(false);
    expect(canRetry('cancelled')).toBe(false);
  });
});

describe('isAddress', () => {
  it('takes host:port', () => {
    expect(isAddress('192.168.1.24:48213')).toBe(true);
    expect(isAddress(' laptop.local:5000 ')).toBe(true);
    expect(isAddress('[fe80::1]:22')).toBe(true);
    expect(isAddress('192.168.1.24')).toBe(false);
    expect(isAddress('host:0')).toBe(false);
    expect(isAddress('host:70000')).toBe(false);
    expect(isAddress('a b:22')).toBe(false);
  });
});
