import { act, renderHook } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { useFolds } from './folds';

describe('cards folded to five rows', () => {
  it('are unfolded by id on the page, so a card keeps it wherever it moves', () => {
    const { result } = renderHook(() => useFolds());
    expect(result.current('hosts')).toMatchObject({ all: false, refocus: false });
    act(() => result.current('hosts').onToggle());
    expect(result.current('hosts')).toMatchObject({ all: true, refocus: true });
    expect(result.current('keys')).toMatchObject({ all: false, refocus: false });
    act(() => result.current('hosts').onToggle());
    expect(result.current('hosts').all).toBe(false);
  });
});
