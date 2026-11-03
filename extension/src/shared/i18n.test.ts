import { describe, expect, it } from 'vitest';
import enMessages from '../../_locales/en/messages.json';
import ruMessages from '../../_locales/ru/messages.json';
import uzMessages from '../../_locales/uz/messages.json';
import { LOCALES, pickLanguage } from './i18n';

const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe('extension strings', () => {
  it.each(['ru', 'uz'] as const)(
    '%s has every English string with the same placeholders',
    (lang) => {
      const english = LOCALES.en;
      const other = LOCALES[lang];
      expect(Object.keys(other).sort()).toEqual(Object.keys(english).sort());
      for (const [key, text] of Object.entries(english)) {
        expect(placeholders(other[key as keyof typeof english]), key).toEqual(placeholders(text));
        expect(other[key as keyof typeof english].trim(), key).not.toBe('');
      }
    },
  );

  it('picks the first language it speaks', () => {
    expect(pickLanguage(['de-DE', 'ru-RU', 'en'])).toBe('ru');
    expect(pickLanguage(['uz-Latn-UZ'])).toBe('uz');
    expect(pickLanguage(['fr'])).toBe('en');
    expect(pickLanguage([])).toBe('en');
  });

  it('names the extension in every store language', () => {
    for (const messages of [enMessages, ruMessages, uzMessages]) {
      expect(Object.keys(messages).sort()).toEqual(['extensionDescription', 'extensionName']);
      expect(messages.extensionName.message).toBe('SSH Key Manager');
      expect(messages.extensionDescription.message.length).toBeLessThanOrEqual(132);
    }
  });
});
