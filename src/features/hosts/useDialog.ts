import { useCallback, useRef, useState } from 'react';

/**
 * State for a dialog opened from code rather than a Radix `Dialog.Trigger`.
 * Radix gives focus back only to its trigger, so this remembers what had
 * focus when the dialog opened and returns focus there when it closes, or to
 * `fallback` if that element is gone by then.
 */
export function useDialog<T>(
  fallback?: () => HTMLElement | null | undefined,
): [T | null, (value: T) => void, () => void] {
  const [value, setValue] = useState<T | null>(null);
  const opener = useRef<HTMLElement | null>(null);
  const fallbackRef = useRef(fallback);
  fallbackRef.current = fallback;

  const open = useCallback((next: T) => {
    const active = document.activeElement;
    opener.current = active instanceof HTMLElement && active !== document.body ? active : null;
    setValue(next);
  }, []);
  const close = useCallback(() => {
    const element = opener.current;
    opener.current = null;
    setValue(null);
    // After the dialog, and its focus trap, are gone.
    requestAnimationFrame(() =>
      setTimeout(() => {
        const target = element?.isConnected ? element : fallbackRef.current?.();
        target?.focus();
      }, 0),
    );
  }, []);
  return [value, open, close];
}
