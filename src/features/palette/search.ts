// Finding items as the user types: the command palette's and the quick
// search window's. No React here, so both use it and the tests run it alone.

/** How well a text matches: exact, then a prefix, then a word or part of it, then letters in order. */
export const TIER = { none: 0, fuzzy: 1, contains: 2, prefix: 3, exact: 4 } as const;
export type Tier = (typeof TIER)[keyof typeof TIER];

export interface Match {
  tier: Tier;
  /** Orders matches of one tier, higher first. */
  score: number;
  /** Positions in the text that matched, for highlighting. */
  positions: number[];
}

export interface Searchable {
  /** Stable across sessions: the recently used list keeps it. */
  id: string;
  title: string;
  /** The action's words, which a query may start with: "connect prod". */
  verbs: readonly string[];
  /** Other text the item is found by, ranked below its title: a host name, a user name. */
  keywords?: readonly string[];
  /** The object's main action, listed before its others when both match alike. */
  primary?: boolean;
}

export interface Ranked<T> {
  item: T;
  tier: Tier;
  score: number;
  /** In `item.title`. */
  positions: number[];
}

const SEPARATOR = /[\s\-_./:@+,()[\]]/;
const SEPARATORS = /[\s\-_./:@+,()[\]]/g;

/**
 * Lower case without accents, one character for each character, so
 * positions found in the folded text are positions in the original.
 */
export function fold(text: string): string {
  let out = '';
  for (const char of text) {
    const plain = char.normalize('NFD').replace(/\p{M}/gu, '').toLowerCase();
    // Characters outside the BMP count twice in positions; keep them as they are.
    out += char.length === 1 && plain.length > 0 ? (plain[0] ?? char) : char;
  }
  return out;
}

function range(from: number, length: number): number[] {
  return Array.from({ length }, (_, index) => from + index);
}

/** `needle` (folded, trimmed, not empty) in `text`. */
export function matchText(text: string, needle: string): Match | null {
  if (!needle) return null;
  // "web prod" finds "web-prod" as a prefix: any separator matches a space.
  const folded = fold(text);
  const haystack = needle.includes(' ') ? folded.replace(SEPARATORS, ' ') : folded;
  if (haystack === needle)
    return { tier: TIER.exact, score: 1000, positions: range(0, text.length) };
  if (haystack.startsWith(needle)) {
    return {
      tier: TIER.prefix,
      score: 1000 - (haystack.length - needle.length),
      positions: range(0, needle.length),
    };
  }
  // A later word starts with it ("prod" in "web-prod"), or it appears inside one.
  let at = haystack.indexOf(needle, 1);
  let inside = -1;
  while (at > 0) {
    if (SEPARATOR.test(haystack[at - 1] ?? '')) {
      return { tier: TIER.contains, score: 900 - at, positions: range(at, needle.length) };
    }
    if (inside < 0) inside = at;
    at = haystack.indexOf(needle, at + 1);
  }
  if (inside > 0) {
    return { tier: TIER.contains, score: 700 - inside, positions: range(inside, needle.length) };
  }
  return fuzzy(haystack, needle);
}

/** The needle's letters in order, spaces skipped; closer together and at word starts is better. */
function fuzzy(haystack: string, needle: string): Match | null {
  const letters = needle.replace(/\s+/g, '');
  if (letters.length < 2) return null;
  const positions: number[] = [];
  let from = 0;
  for (const letter of letters) {
    const at = haystack.indexOf(letter, from);
    if (at < 0) return null;
    positions.push(at);
    from = at + 1;
  }
  let score = 500;
  for (const [index, at] of positions.entries()) {
    const previous = positions[index - 1];
    if (previous !== undefined) score -= Math.min(at - previous - 1, 10) * 4;
    if (at === 0 || SEPARATOR.test(haystack[at - 1] ?? '')) score += 12;
  }
  return { tier: TIER.fuzzy, score: Math.max(1, Math.min(599, score)), positions };
}

/** The query as matched: folded, trimmed, single spaces. */
export function normalizeQuery(query: string): string {
  return fold(query).trim().replace(/\s+/g, ' ');
}

const better = (a: Match | null, b: Match | null): Match | null =>
  !b ? a : !a || b.tier > a.tier || (b.tier === a.tier && b.score > a.score) ? b : a;

function matchKeywords(item: Searchable, needle: string): Match | null {
  let best: Match | null = null;
  for (const keyword of item.keywords ?? []) {
    const match = matchText(keyword, needle);
    if (match) {
      // A keyword never outranks a title's prefix, and leaves nothing to highlight.
      const tier = Math.min(match.tier, TIER.contains) as Tier;
      best = better(best, { tier, score: match.score - 100, positions: [] });
    }
  }
  return best;
}

/**
 * How `item` matches `query` (normalized, not empty): its title, else its
 * keywords. Words that start one of its verbs may come first or last
 * ("connect prod", "prod ssh"); they then must, and the rest must match.
 */
export function matchItem(item: Searchable, query: string): Match | null {
  const whole = matchText(item.title, query);
  if (whole && whole.tier >= TIER.prefix) return whole;
  let best = better(whole, matchKeywords(item, query));

  const verbWords = item.verbs.flatMap((verb) => fold(verb).split(/\s+/)).filter(Boolean);
  const isVerb = (token: string) =>
    verbWords.some((word) => word === token || (token.length >= 2 && word.startsWith(token)));
  const tokens = query.split(' ');
  const verbs = tokens.filter(isVerb);
  if (verbs.length === 0) return best;
  const rest = tokens.filter((token) => !isVerb(token)).join(' ');
  if (!rest) {
    // Only the action: every item it applies to, below anything named so.
    return better(best, { tier: TIER.fuzzy, score: 650, positions: [] });
  }
  const named = better(matchText(item.title, rest), matchKeywords(item, rest));
  if (named) best = better(best, { ...named, score: named.score + 50 });
  return best;
}

/**
 * The items that match `query`, best first: by tier, then recently used
 * (`recent`, most recent first), then score, then main actions, then title.
 */
export function rank<T extends Searchable>(
  items: readonly T[],
  query: string,
  recent: readonly string[] = [],
): Ranked<T>[] {
  const needle = normalizeQuery(query);
  if (!needle) return [];
  const used = recentOrder(recent);
  const ranked: Ranked<T>[] = [];
  for (const item of items) {
    const match = matchItem(item, needle);
    if (match) ranked.push({ item, ...match });
  }
  return ranked.sort(
    (a, b) =>
      b.tier - a.tier ||
      used(a.item) - used(b.item) ||
      b.score - a.score ||
      Number(Boolean(b.item.primary)) - Number(Boolean(a.item.primary)) ||
      a.item.title.localeCompare(b.item.title),
  );
}

/** Recently used first (most recent first), the rest in their order. */
export function byRecent<T extends Searchable>(
  items: readonly T[],
  recent: readonly string[],
): T[] {
  const used = recentOrder(recent);
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => used(a.item) - used(b.item) || a.index - b.index)
    .map(({ item }) => item);
}

function recentOrder(recent: readonly string[]): (item: Searchable) => number {
  const order = new Map(recent.map((id, index) => [id, index]));
  return (item) => order.get(item.id) ?? Number.MAX_SAFE_INTEGER;
}

/** Where a query looks: `>` actions and pages, `@` hosts, `#` passwords, else everywhere. */
export type Scope = 'all' | 'actions' | 'hosts' | 'passwords';

export const PREFIXES = { '>': 'actions', '@': 'hosts', '#': 'passwords' } as const;

export function parseQuery(raw: string): { scope: Scope; text: string } {
  const first = raw.trimStart()[0];
  if (first && first in PREFIXES) {
    return {
      scope: PREFIXES[first as keyof typeof PREFIXES],
      text: raw.trimStart().slice(1).trim(),
    };
  }
  return { scope: 'all', text: raw.trim() };
}
