import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import en from './locales/en';
import ru from './locales/ru';
import uz from './locales/uz';

export const LANGUAGES = ['en', 'ru', 'uz'] as const;
export type Language = (typeof LANGUAGES)[number];

/** Each language's name in itself, as language pickers show it. */
export const LANGUAGE_NAMES: Record<Language, string> = {
  en: 'English',
  ru: 'Русский',
  uz: 'Oʻzbekcha',
};

const STORAGE_KEY = 'sshkm.language';

/** The saved choice, or `null` to follow the system language. */
export function storedLanguage(): Language | null {
  try {
    const value = localStorage.getItem(STORAGE_KEY);
    return LANGUAGES.includes(value as Language) ? (value as Language) : null;
  } catch {
    return null;
  }
}

function systemLanguage(): Language {
  const preferred = typeof navigator === 'undefined' ? [] : navigator.languages;
  for (const tag of preferred) {
    const base = tag.split('-')[0] as Language;
    if (LANGUAGES.includes(base)) return base;
  }
  return 'en';
}

export function setLanguage(language: Language | null): void {
  try {
    if (language) localStorage.setItem(STORAGE_KEY, language);
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    // Storage can be unavailable; the choice then lasts for this session only.
  }
  void i18n.changeLanguage(language ?? systemLanguage());
}

void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, ru: { translation: ru }, uz: { translation: uz } },
  lng: storedLanguage() ?? systemLanguage(),
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
  returnNull: false,
});

i18n.on('languageChanged', (language) => {
  document.documentElement.lang = language;
});
document.documentElement.lang = i18n.language;

export default i18n;
