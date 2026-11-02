import { describe, expect, it } from 'vitest';
import en from './locales/en';
import ru from './locales/ru';
import uz from './locales/uz';

type Tree = { [key: string]: string | Tree };

/** Translation keys with plural suffixes folded, e.g. `keys.meta`. */
function keys(tree: Tree, prefix = ''): Set<string> {
  const out = new Set<string>();
  for (const [key, value] of Object.entries(tree)) {
    const path = `${prefix}${key.replace(/_(zero|one|two|few|many|other)$/, '')}`;
    if (typeof value === 'string') out.add(path);
    else for (const nested of keys(value, `${path}.`)) out.add(nested);
  }
  return out;
}

function placeholders(tree: Tree, prefix = ''): Map<string, string> {
  const out = new Map<string, string>();
  for (const [key, value] of Object.entries(tree)) {
    const path = `${prefix}${key.replace(/_(zero|one|two|few|many|other)$/, '')}`;
    if (typeof value === 'string') {
      const names = [...value.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort();
      out.set(
        path,
        [...new Set([...(out.get(path)?.split(',').filter(Boolean) ?? []), ...names])]
          .sort()
          .join(','),
      );
    } else for (const [k, v] of placeholders(value, `${path}.`)) out.set(k, v);
  }
  return out;
}

describe.each([
  ['ru', ru],
  ['uz', uz],
])('%s translation', (_, locale) => {
  it('has exactly the English keys', () => {
    expect([...keys(locale as Tree)].sort()).toEqual([...keys(en as unknown as Tree)].sort());
  });

  it('uses the same placeholders as English', () => {
    const english = placeholders(en as unknown as Tree);
    const translated = placeholders(locale as Tree);
    for (const [key, names] of english) {
      // Plural forms may drop {{count}} ("one key" vs "{{count}} keys").
      const strip = (list: string | undefined) =>
        (list ?? '')
          .split(',')
          .filter((n) => n && n !== 'count')
          .join(',');
      expect(strip(translated.get(key)), key).toBe(strip(names));
    }
  });
});
