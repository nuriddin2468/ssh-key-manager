/** Shows paths under the home directory as `~/…`. */
export function displayPath(path: string, home: string | undefined): string {
  if (!home) return path;
  const trimmed = home.replace(/[\\/]+$/, '');
  if (path === trimmed) return '~';
  if (path.startsWith(`${trimmed}/`) || path.startsWith(`${trimmed}\\`)) {
    return `~${path.slice(trimmed.length)}`;
  }
  return path;
}

/** `SHA256:k3XbV9qL…KjBnHw` — enough to recognise a key at a glance. */
export function shortFingerprint(fingerprint: string | null | undefined): string {
  if (!fingerprint) return '—';
  if (fingerprint.length <= 26) return fingerprint;
  return `${fingerprint.slice(0, 16)}…${fingerprint.slice(-6)}`;
}

export function formatDate(iso: string | null | undefined, locale: string): string {
  if (!iso) return '—';
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '—';
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium' }).format(date);
}

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ['year', 365 * 24 * 3600],
  ['month', 30 * 24 * 3600],
  ['week', 7 * 24 * 3600],
  ['day', 24 * 3600],
  ['hour', 3600],
  ['minute', 60],
];

export function formatRelative(date: Date, locale: string, now: Date = new Date()): string {
  const seconds = Math.round((date.getTime() - now.getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });
  for (const [unit, size] of UNITS) {
    if (Math.abs(seconds) >= size) return rtf.format(Math.round(seconds / size), unit);
  }
  return rtf.format(0, 'minute');
}

/** `3 h 12 min` style durations for agent lifetimes. */
export function formatDuration(totalSeconds: number, locale: string): string {
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const fmt = (value: number, unit: 'hour' | 'minute') =>
    new Intl.NumberFormat(locale, { style: 'unit', unit, unitDisplay: 'short' }).format(value);
  if (hours > 0 && minutes > 0) return `${fmt(hours, 'hour')} ${fmt(minutes, 'minute')}`;
  if (hours > 0) return fmt(hours, 'hour');
  return fmt(Math.max(minutes, 1), 'minute');
}
