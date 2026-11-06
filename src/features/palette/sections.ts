// What the list shows for a query: the ranked matches, or with nothing typed
// yet, what was run lately and then what the caller suggests.

import type { PaletteItem } from './items';
import { parseQuery, type Ranked, rank, type Scope } from './search';

export interface Section {
  id: string;
  /** A heading; the ranked matches have none. */
  label?: string;
  items: Ranked<PaletteItem>[];
}

export interface Group {
  id: string;
  label: string;
  items: readonly PaletteItem[];
}

/** Matches shown at most: past them, typing more is quicker than scrolling. */
export const MATCHES_SHOWN = 60;
/** Recently run items shown before anything is typed. */
export const RECENT_SHOWN = 5;

const unranked = (item: PaletteItem): Ranked<PaletteItem> => ({
  item,
  tier: 0,
  score: 0,
  positions: [],
});

/**
 * The sections for `query`. With text after the scope prefix, its matches
 * in that scope; without, `browse(scope)`, after the recently run items when
 * no scope was given.
 */
export function buildSections(
  items: readonly PaletteItem[],
  query: string,
  options: {
    recent: readonly string[];
    recentLabel: string;
    browse: (scope: Scope) => Group[];
  },
): Section[] {
  const { scope, text } = parseQuery(query);
  if (text) {
    const pool = scope === 'all' ? items : items.filter((item) => item.scope === scope);
    const matches = rank(pool, text, options.recent).slice(0, MATCHES_SHOWN);
    return matches.length > 0 ? [{ id: 'matches', items: matches }] : [];
  }
  const sections: Section[] = [];
  const shown = new Set<string>();
  if (scope === 'all') {
    const byId = new Map(items.map((item) => [item.id, item]));
    const recent = options.recent
      .map((id) => byId.get(id))
      .filter((item): item is PaletteItem => item !== undefined)
      .slice(0, RECENT_SHOWN);
    if (recent.length > 0) {
      sections.push({ id: 'recent', label: options.recentLabel, items: recent.map(unranked) });
      for (const item of recent) shown.add(item.id);
    }
  }
  for (const group of options.browse(scope)) {
    const rest = group.items.filter((item) => !shown.has(item.id));
    if (rest.length > 0) {
      sections.push({ id: group.id, label: group.label, items: rest.map(unranked) });
    }
  }
  return sections;
}
