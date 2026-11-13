// The colour tokens in app.css, and the rule that components use only them:
// a raw colour looks right in one theme and wrong in the other.

import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = join(__dirname, '..', '..');
const SRC = join(ROOT, 'src');
const CSS = readFileSync(join(SRC, 'styles', 'app.css'), 'utf8');

/**
 * Files that may hold colour values, each for a reason that holds in both
 * themes. Anything else uses the tokens in app.css.
 */
const ALLOWED = new Map([
  ['src/components/Logo.tsx', 'the brand mark, the same in both themes'],
  ['src/components/ui/Tile.tsx', 'icon tiles: a white glyph on a coloured gradient in both themes'],
  ['src/features/terminal/screen.ts', 'xterm takes plain colours: both terminal palettes'],
]);

const HUES =
  'slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose';
const UTILITY =
  '(?:bg|text|text-shadow|border(?:-[xytrblse])?|divide|ring|ring-offset|outline|decoration|shadow|inset-shadow|inset-ring|drop-shadow|from|via|to|fill|stroke|caret|accent|placeholder)';
/** CSS colour names. Keys like `color:` check only the neutral ones: projects have colours named teal, blue… */
const NEUTRAL_NAMES = 'white|black|gr[ae]y|silver|whitesmoke|gainsboro|snow|ivory';
const COLOR_NAMES = `${NEUTRAL_NAMES}|red|green|blue|yellow|orange|purple|pink|navy|teal|maroon|olive|lime|aqua|fuchsia|cyan|magenta|indigo|violet|gold|brown|crimson|coral|salmon|tomato|turquoise`;

const RULES: { name: string; pattern: RegExp; instead: string }[] = [
  {
    name: 'white or black utility',
    pattern: new RegExp(`(?<![\\w-])${UTILITY}-(?:white|black)(?![\\w-])`, 'g'),
    instead: 'a role token (border-line, bg-fill, bg-well, text-on-solid…) or ink/shade',
  },
  {
    name: 'Tailwind palette colour',
    pattern: new RegExp(
      `(?<![\\w-])${UTILITY}-(?:${HUES})-\\d{2,3}(?![\\w-])|--color-(?:(?:${HUES})-\\d{2,3}|white|black)(?![\\w-])`,
      'g',
    ),
    instead:
      'a status token, or another section’s colours: data-hue="hosts" with text-[var(--accent-text)]',
  },
  {
    name: 'hex colour',
    pattern: /(?<![\w&/])#(?:[0-9a-f]{8}|[0-9a-f]{6}|[0-9a-f]{3,4})(?![\w-])/gi,
    instead: 'a token from src/styles/app.css',
  },
  {
    name: 'colour function',
    pattern: /(?<![a-z0-9-])(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\((?!\s*var\()/gi,
    instead: 'a token, or rgb(var(--accent-rgb)/…) for the page’s accent',
  },
  {
    name: 'colour name',
    pattern: new RegExp(
      [
        // In a Tailwind arbitrary value: bg-[white], color-mix(in_srgb,black_20%,…)
        `(?<=[\\[(,_])(?:${COLOR_NAMES})(?=[\\]),_])`,
        // An SVG colour attribute: fill="white", stopColor={'black'}
        `(?<![\\w-])(?:fill|stroke|stopColor|floodColor|lightingColor)=\\{?\\s*['"\`](?:${COLOR_NAMES})['"\`]`,
        // A style or CSS-in-TS value: color: 'white', background: black
        `(?<![\\w-])(?:color|background(?:-?color)?|border(?:-?color)?|outline(?:-?color)?|caret(?:-?color)?|fill|stroke)\\s*:\\s*['"\`]?(?:${NEUTRAL_NAMES})(?![\\w-])`,
      ].join('|'),
      'gi',
    ),
    instead: 'a token from src/styles/app.css',
  },
  {
    name: 'gradient colour as text',
    pattern:
      /(?<![\w-])(?:text|fill|stroke|decoration|caret|placeholder|outline)-\[var\(--accent-[12]\)\]/g,
    instead:
      'var(--accent-fg) or var(--accent-text): --accent-1 and -2 are the gradient’s, pale in the light theme',
  },
];

function sourceFiles(): string[] {
  return (readdirSync(SRC, { recursive: true }) as string[])
    .filter((file) => /\.tsx?$/.test(file))
    .filter((file) => !/\.test\.tsx?$/.test(file))
    .map((file) => relative(ROOT, join(SRC, file)).split('\\').join('/'))
    .filter((file) => !file.startsWith('src/bindings/') && !file.startsWith('src/i18n/locales/'))
    .sort();
}

function findRaw(text: string): string[] {
  const found: string[] = [];
  text.split('\n').forEach((line, index) => {
    for (const rule of RULES) {
      for (const match of line.matchAll(rule.pattern)) {
        found.push(`${index + 1}: ${rule.name} “${match[0]}”; use ${rule.instead}`);
      }
    }
  });
  return found;
}

describe('components', () => {
  it('use colour tokens, not raw colours', () => {
    const offences = sourceFiles()
      .filter((file) => !ALLOWED.has(file))
      .flatMap((file) =>
        findRaw(readFileSync(join(ROOT, file), 'utf8')).map((line) => `${file}:${line}`),
      );
    expect(offences, 'See the token list at the top of src/styles/app.css.').toEqual([]);
  });

  it('the check catches what it should and lets tokens through', () => {
    const caught = (text: string) => findRaw(text).length;
    expect(caught("'border-white/[0.06] hover:bg-black/30 text-white'")).toBe(3);
    expect(caught("'border-s-white/10 border-e-black text-shadow-black/40'")).toBe(3);
    expect(caught("'text-violet-200 bg-blue-400/12'")).toBe(2);
    expect(caught("'bg-[var(--color-violet-400)] text-[var(--color-white)]'")).toBe(2);
    expect(caught('stroke="#A78BFA" bg-[#06080d] \'rgb(255 255 255 / 0.1)\'')).toBe(3);
    expect(caught("shadow-[0_1px_2px_rgb(0_0_0/0.4)] bg-[hsl(0_0%_100%)] 'RGB(0 0 0)'")).toBe(3);
    expect(caught('fill="white" stopColor={\'black\'} stroke="red"')).toBe(3);
    expect(caught("style={{ color: 'white', background: 'black' }}")).toBe(2);
    expect(caught("'bg-[white] bg-[color-mix(in_srgb,black_20%,transparent)]'")).toBe(2);
    expect(caught("'text-[var(--accent-1)] fill-[var(--accent-2)]'")).toBe(2);
    expect(
      findRaw(
        "'border-line bg-fill text-on-solid bg-ink/[0.07] bg-[rgb(var(--accent-rgb)/0.1)] url(#glow) text-[var(--accent-text)]'",
      ),
    ).toEqual([]);
    // Not colours: a project's colour name, a gradient of the accent, `transparent`, words.
    expect(
      findRaw(
        "color: 'teal' bg-[linear-gradient(135deg,var(--accent-1),var(--accent-2))] bg-[color-mix(in_srgb,var(--color-ok)_70%,transparent)] 'a white glyph'",
      ),
    ).toEqual([]);
  });

  it('allow-list only files that exist', () => {
    const files = new Set(sourceFiles());
    for (const file of ALLOWED.keys()) expect(files, file).toContain(file);
  });
});

/** `--name: value;` pairs in the first block that `selector` opens. */
function block(selector: string): Map<string, string> {
  const start = CSS.indexOf(`${selector} {`);
  expect(start, selector).toBeGreaterThanOrEqual(0);
  const end = CSS.indexOf('\n}', start);
  const vars = new Map<string, string>();
  for (const match of CSS.slice(start, end).matchAll(/^\s*(--[\w-]+):\s*([^;]+);/gm)) {
    vars.set(match[1] as string, (match[2] as string).replace(/\s+/g, ' ').trim());
  }
  return vars;
}

const DARK = new Map([...block('@theme'), ...block(':root')]);
const LIGHT = block(':root[data-theme="light"]');

describe('tokens', () => {
  it('every colour and elevation has a light value', () => {
    const themed = [...DARK.keys()].filter(
      (name) => name.startsWith('--color-') || name.startsWith('--elevation-'),
    );
    expect(themed.length).toBeGreaterThan(50);
    expect(themed.filter((name) => !LIGHT.has(name))).toEqual([]);
  });

  type Rgb = [number, number, number];

  function parse(value: string): Rgb {
    const hex = /^#([0-9a-f]{6})$/i.exec(value);
    if (hex) {
      const n = Number.parseInt(hex[1] as string, 16);
      return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
    }
    if (value === '#fff') return [255, 255, 255];
    throw new Error(`not an opaque colour: ${value}`);
  }

  function luminance([r, g, b]: Rgb): number {
    const channel = (c: number) => {
      const s = c / 255;
      return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
    };
    return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
  }

  function contrast(a: Rgb, b: Rgb): number {
    const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
    return (hi + 0.05) / (lo + 0.05);
  }

  const TEXT = [
    '--color-fg',
    '--color-fg-2',
    '--color-muted',
    '--color-subtle',
    '--color-label',
    '--color-nav',
    '--color-critical',
    '--color-warning',
    '--color-info',
    '--color-ok',
  ];
  const SURFACES = ['--color-canvas', '--color-surface', '--color-sidebar', '--color-popover'];

  it.each([
    ['dark', DARK],
    ['light', LIGHT],
  ])('text in the %s theme reads at 4.5:1 or more on every surface', (_theme, vars) => {
    const failing: string[] = [];
    for (const text of TEXT) {
      for (const surface of SURFACES) {
        const ratio = contrast(parse(vars.get(text) as string), parse(vars.get(surface) as string));
        if (ratio < 4.5) failing.push(`${text} on ${surface}: ${ratio.toFixed(2)}`);
      }
    }
    expect(failing).toEqual([]);
  });

  it('light accent text reads at 4.5:1 on white and on the page', () => {
    const surface = parse(LIGHT.get('--color-surface') as string);
    const accents = [
      ...CSS.matchAll(/\[data-theme="light"\][^{]*\{[^}]*--accent-text: (#[0-9a-f]{6});/g),
    ].map((match) => match[1] as string);
    expect(accents.length).toBe(13);
    for (const accent of accents) {
      expect(contrast(parse(accent), [255, 255, 255]), accent).toBeGreaterThanOrEqual(4.5);
      expect(contrast(parse(accent), surface), accent).toBeGreaterThanOrEqual(4.5);
    }
  });
});
