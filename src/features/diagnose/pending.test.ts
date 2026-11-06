import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Diagnosis } from '@/bindings/Diagnosis';
import { requestHostFix, takeHostFix } from './pending';

const diagnosis: Diagnosis = { cause: { kind: 'unknown' }, hop: null, lines: [] };
const ready = () => true;

describe('pending host fixes', () => {
  afterEach(() => {
    vi.useRealTimers();
    takeHostFix(['prod', 'other'], ready);
  });

  it('runs once, for the host it was asked for, when the editor can make it', () => {
    requestHostFix('prod', 'identitiesOnly', diagnosis);
    expect(takeHostFix(['other'], ready)).toBeUndefined();
    expect(takeHostFix(['prod'], () => false)).toBeUndefined();
    expect(takeHostFix(['prod'], ready)).toEqual({ fix: 'identitiesOnly', diagnosis });
    expect(takeHostFix(['prod'], ready)).toBeUndefined();
  });

  it('drops a fix the editor didn’t make soon after', () => {
    vi.useFakeTimers();
    requestHostFix('prod', 'installKey', diagnosis);
    vi.advanceTimersByTime(11_000);
    expect(takeHostFix(['prod'], ready)).toBeUndefined();
  });
});
