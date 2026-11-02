export type Platform = 'macos' | 'windows' | 'linux';

function detect(): Platform {
  const ua = typeof navigator === 'undefined' ? '' : navigator.userAgent;
  if (/Mac OS X|Macintosh/.test(ua)) return 'macos';
  if (/Windows/.test(ua)) return 'windows';
  return 'linux';
}

export const platform: Platform = detect();

/** The primary shortcut modifier as shown in menus and tooltips. */
export const modLabel = platform === 'macos' ? '⌘' : 'Ctrl+';

/** Name of the system file manager, for "Show in …" actions. */
export const fileManagerName =
  platform === 'macos' ? 'Finder' : platform === 'windows' ? 'Explorer' : 'Files';
