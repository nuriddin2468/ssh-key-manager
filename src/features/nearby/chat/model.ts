import { useMutation } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { toastError } from '@/api/useAppMutation';
import { AppError } from '@/lib/ipc';
import type { ChatEntry } from '@/bindings/ChatEntry';

/** The terms a secret or variables may have, in seconds: an hour, a day, a week. */
export const TERMS = [
  { seconds: 3600, label: 'nearby.chat.secretDialog.hour' },
  { seconds: 86_400, label: 'nearby.chat.secretDialog.day' },
  { seconds: 604_800, label: 'nearby.chat.secretDialog.week' },
] as const;

/**
 * A chat command: a failure becomes a toast. Nothing else is refreshed: the
 * backend's chat events do that.
 */
export function useChatAction<TVars, TResult>(
  run: (vars: TVars) => Promise<TResult>,
  onSuccess?: (result: TResult, vars: TVars) => void,
) {
  const { t } = useTranslation();
  return useMutation({
    mutationFn: run,
    // The variables may hold a secret: gone as soon as nothing shows them.
    gcTime: 0,
    onSuccess,
    // A no in the system dialog is the user's own answer: nothing to report.
    onError: (error) => {
      if (AppError.from(error).code !== 'cancelled') toastError(t, error);
    },
  });
}

/** Seconds from now until `iso`, at least 0. */
export function secondsUntil(iso: string, now = Date.now()): number {
  return Math.max(0, Math.round((new Date(iso).getTime() - now) / 1000));
}

/** Whether a value going at `iso` goes within ten minutes. */
export function soon(iso: string, now = Date.now()): boolean {
  return secondsUntil(iso, now) < 600;
}

/** Entries grouped by the day they came, in order. */
export function byDay(entries: ChatEntry[]): { day: string; entries: ChatEntry[] }[] {
  const days: { day: string; entries: ChatEntry[] }[] = [];
  for (const entry of entries) {
    const day = entry.at.slice(0, 10);
    const last = days.at(-1);
    if (last?.day === day) last.entries.push(entry);
    else days.push({ day, entries: [entry] });
  }
  return days;
}
