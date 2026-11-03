// The extension's words in the app's three languages. The language is the
// first of the user's preferred languages the app speaks, else English.
// `{name}` marks a value filled in by `t`.

const en = {
  appName: 'SSH Key Manager',
  checking: 'Checking…',
  openApp: 'Open SSH Key Manager',
  connect: 'Connect',
  tryAgain: 'Try again',

  noHostTitle: 'Browser autofill is off',
  noHostText: 'In SSH Key Manager, open Settings and turn on Browser autofill.',
  notRunningTitle: 'SSH Key Manager isn’t running',
  notRunningText: 'Open the app to fill passwords.',
  noVaultTitle: 'No vault yet',
  noVaultText: 'Create a password vault in SSH Key Manager first.',
  unpairedTitle: 'Connect this browser',
  unpairedText: 'Connect it to SSH Key Manager once to fill and save passwords.',
  revokedTitle: 'This browser was disconnected',
  revokedText: 'It was disconnected in SSH Key Manager, or another vault is open.',
  connectAgain: 'Connect again',
  lockedTitle: 'The vault is locked',
  lockedText: 'Unlock it in SSH Key Manager to fill passwords.',
  unlockInApp: 'Unlock in SSH Key Manager',
  readyTitle: 'Connected',
  readyText: 'Click a login field on a site to fill a saved password.',
  disconnect: 'Disconnect this browser',
  failedTitle: 'Something went wrong',
  failedText: 'Try again in a moment.',

  connectTitle: 'Connect to SSH Key Manager',
  connectIntro:
    'The extension fills passwords from your SSH Key Manager vault. Connect it once; the app asks you to confirm.',
  connectCode: 'Connection code',
  connectCompare: 'SSH Key Manager shows a code too. If it’s the same, choose Connect in the app.',
  connectWaiting: 'Waiting for you to confirm in the app…',
  connectDoneText:
    'You can close this tab. Click a login field on any site to fill a saved password.',
  connectDenied: 'The connection was declined in the app.',
  connectExpired: 'The app got no answer in time. Try again.',
  connectBusy: 'Another browser is connecting right now. Finish that first, then try again.',
  connectLocked: 'The vault is locked. Unlock it in SSH Key Manager, then try again.',
  connectNotRunning: 'SSH Key Manager isn’t running. Open it, then try again.',
  connectFailed: 'Couldn’t connect. Try again.',

  menuLabel: 'Saved logins',
  menuLocked: 'Unlock SSH Key Manager to fill',
  menuHint: 'SSH Key Manager can fill this field. Press Down Arrow to choose.',
  noUsername: 'No username',

  saveTitle: 'Save login for {site}?',
  updateTitle: 'Update password for {title}?',
  save: 'Save',
  update: 'Update',
  notNow: 'Not now',
  saved: 'Saved in SSH Key Manager',
  updated: 'Password updated in SSH Key Manager',
  saveLocked: 'Unlock the vault in SSH Key Manager, then choose Save again.',
  saveFailed: 'Couldn’t save. Try again.',
  close: 'Close',
};

export type Key = keyof typeof en;
type Strings = Record<Key, string>;

const ru: Strings = {
  appName: 'SSH Key Manager',
  checking: 'Проверка…',
  openApp: 'Открыть SSH Key Manager',
  connect: 'Подключить',
  tryAgain: 'Повторить',

  noHostTitle: 'Автозаполнение выключено',
  noHostText: 'В SSH Key Manager откройте «Настройки» и включите автозаполнение в браузере.',
  notRunningTitle: 'SSH Key Manager не запущен',
  notRunningText: 'Откройте приложение, чтобы заполнять пароли.',
  noVaultTitle: 'Хранилища пока нет',
  noVaultText: 'Сначала создайте хранилище паролей в SSH Key Manager.',
  unpairedTitle: 'Подключите этот браузер',
  unpairedText: 'Подключите его к SSH Key Manager один раз, чтобы заполнять и сохранять пароли.',
  revokedTitle: 'Браузер отключён',
  revokedText: 'Его отключили в SSH Key Manager, или открыто другое хранилище.',
  connectAgain: 'Подключить снова',
  lockedTitle: 'Хранилище заблокировано',
  lockedText: 'Разблокируйте его в SSH Key Manager, чтобы заполнять пароли.',
  unlockInApp: 'Разблокировать в SSH Key Manager',
  readyTitle: 'Подключено',
  readyText: 'Нажмите на поле входа на сайте, чтобы подставить сохранённый пароль.',
  disconnect: 'Отключить этот браузер',
  failedTitle: 'Что-то пошло не так',
  failedText: 'Попробуйте ещё раз чуть позже.',

  connectTitle: 'Подключение к SSH Key Manager',
  connectIntro:
    'Расширение заполняет пароли из хранилища SSH Key Manager. Подключите его один раз — приложение попросит подтвердить.',
  connectCode: 'Код подключения',
  connectCompare:
    'SSH Key Manager тоже показывает код. Если он совпадает, нажмите «Подключить» в приложении.',
  connectWaiting: 'Ждём подтверждения в приложении…',
  connectDoneText:
    'Вкладку можно закрыть. Нажмите на поле входа на любом сайте, чтобы подставить сохранённый пароль.',
  connectDenied: 'Подключение отклонено в приложении.',
  connectExpired: 'Приложение не получило ответа вовремя. Попробуйте ещё раз.',
  connectBusy: 'Сейчас подключается другой браузер. Завершите это и попробуйте снова.',
  connectLocked: 'Хранилище заблокировано. Разблокируйте его в SSH Key Manager и попробуйте снова.',
  connectNotRunning: 'SSH Key Manager не запущен. Откройте его и попробуйте снова.',
  connectFailed: 'Не удалось подключиться. Попробуйте ещё раз.',

  menuLabel: 'Сохранённые логины',
  menuLocked: 'Разблокируйте SSH Key Manager, чтобы заполнить',
  menuHint: 'SSH Key Manager может заполнить это поле. Нажмите стрелку вниз, чтобы выбрать.',
  noUsername: 'Без имени пользователя',

  saveTitle: 'Сохранить логин для {site}?',
  updateTitle: 'Обновить пароль для {title}?',
  save: 'Сохранить',
  update: 'Обновить',
  notNow: 'Не сейчас',
  saved: 'Сохранено в SSH Key Manager',
  updated: 'Пароль обновлён в SSH Key Manager',
  saveLocked: 'Разблокируйте хранилище в SSH Key Manager и снова нажмите «Сохранить».',
  saveFailed: 'Не удалось сохранить. Попробуйте ещё раз.',
  close: 'Закрыть',
};

const uz: Strings = {
  appName: 'SSH Key Manager',
  checking: 'Tekshirilmoqda…',
  openApp: 'SSH Key Managerni ochish',
  connect: 'Ulash',
  tryAgain: 'Qayta urinish',

  noHostTitle: 'Avtomatik toʻldirish oʻchiq',
  noHostText: 'SSH Key Managerda Sozlamalarni oching va brauzerda avtomatik toʻldirishni yoqing.',
  notRunningTitle: 'SSH Key Manager ishlamayapti',
  notRunningText: 'Parollarni toʻldirish uchun ilovani oching.',
  noVaultTitle: 'Hali ombor yoʻq',
  noVaultText: 'Avval SSH Key Managerda parollar omborini yarating.',
  unpairedTitle: 'Bu brauzerni ulang',
  unpairedText: 'Parollarni toʻldirish va saqlash uchun uni SSH Key Managerga bir marta ulang.',
  revokedTitle: 'Bu brauzer uzildi',
  revokedText: 'U SSH Key Managerda uzilgan yoki boshqa ombor ochiq.',
  connectAgain: 'Qayta ulash',
  lockedTitle: 'Ombor qulflangan',
  lockedText: 'Parollarni toʻldirish uchun uni SSH Key Managerda oching.',
  unlockInApp: 'SSH Key Managerda ochish',
  readyTitle: 'Ulangan',
  readyText: 'Saqlangan parolni toʻldirish uchun saytdagi kirish maydonini bosing.',
  disconnect: 'Bu brauzerni uzish',
  failedTitle: 'Nimadir notoʻgʻri ketdi',
  failedText: 'Birozdan keyin qayta urinib koʻring.',

  connectTitle: 'SSH Key Managerga ulanish',
  connectIntro:
    'Kengaytma parollarni SSH Key Manager omboridan toʻldiradi. Uni bir marta ulang — ilova tasdiqlashni soʻraydi.',
  connectCode: 'Ulanish kodi',
  connectCompare:
    'SSH Key Manager ham kod koʻrsatadi. Agar u bir xil boʻlsa, ilovada «Ulash»ni tanlang.',
  connectWaiting: 'Ilovada tasdiqlashingiz kutilmoqda…',
  connectDoneText:
    'Bu varaqni yopishingiz mumkin. Saqlangan parolni toʻldirish uchun istalgan saytdagi kirish maydonini bosing.',
  connectDenied: 'Ulanish ilovada rad etildi.',
  connectExpired: 'Ilova oʻz vaqtida javob olmadi. Qayta urinib koʻring.',
  connectBusy: 'Hozir boshqa brauzer ulanmoqda. Avval uni yakunlang, keyin qayta urinib koʻring.',
  connectLocked: 'Ombor qulflangan. Uni SSH Key Managerda oching va qayta urinib koʻring.',
  connectNotRunning: 'SSH Key Manager ishlamayapti. Uni oching va qayta urinib koʻring.',
  connectFailed: 'Ulanib boʻlmadi. Qayta urinib koʻring.',

  menuLabel: 'Saqlangan loginlar',
  menuLocked: 'Toʻldirish uchun SSH Key Managerni oching',
  menuHint: 'SSH Key Manager bu maydonni toʻldira oladi. Tanlash uchun pastga strelkasini bosing.',
  noUsername: 'Foydalanuvchi nomi yoʻq',

  saveTitle: '{site} uchun login saqlansinmi?',
  updateTitle: '{title} uchun parol yangilansinmi?',
  save: 'Saqlash',
  update: 'Yangilash',
  notNow: 'Hozir emas',
  saved: 'SSH Key Managerda saqlandi',
  updated: 'Parol SSH Key Managerda yangilandi',
  saveLocked: 'SSH Key Managerda omborni oching, keyin yana «Saqlash»ni tanlang.',
  saveFailed: 'Saqlab boʻlmadi. Qayta urinib koʻring.',
  close: 'Yopish',
};

export const LOCALES = { en, ru, uz } as const;
export type Language = keyof typeof LOCALES;

/** The first of the user's languages that the extension speaks. */
export function pickLanguage(preferred: readonly string[]): Language {
  for (const tag of preferred) {
    const base = tag.toLowerCase().split('-')[0];
    if (base === 'en' || base === 'ru' || base === 'uz') return base;
  }
  return 'en';
}

const language = pickLanguage(
  typeof navigator === 'undefined' ? [] : (navigator.languages ?? [navigator.language]),
);

export function t(key: Key, values: Record<string, string> = {}): string {
  return LOCALES[language][key].replace(/\{(\w+)\}/g, (match, name: string) =>
    name in values ? (values[name] ?? match) : match,
  );
}

export function currentLanguage(): Language {
  return language;
}
