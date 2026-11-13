// The extension's words in the app's three languages. The language is the
// first of the user's preferred languages the app speaks, else English.
// `{name}` marks a value filled in by `t`.

import type { Problem } from './client';

const en = {
  appName: 'SSH Key Manager',
  checking: 'Checking…',
  openApp: 'Open SSH Key Manager',
  connect: 'Connect',
  tryAgain: 'Try again',

  noHostTitle: 'Browser autofill isn’t set up',
  noHostText: 'Get the free SSH Key Manager app, then turn on Browser autofill in its Settings.',
  downloadApp: 'Download SSH Key Manager',
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

  suggestionsTitle: 'Browser’s own suggestions',
  suggestionsText:
    'Turn off so {browser} stops offering to save passwords and suggesting earlier entries under login fields.',
  suggestionsLocked: 'Set by your organization or another extension.',
  suggestionsSaved:
    'Passwords already saved in {browser} are still suggested. Import them into SSH Key Manager, then delete them in the browser.',
  suggestionsOpen: 'Open the browser’s passwords',
  suggestionsDenied: 'Not changed: the browser didn’t allow it.',

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
  connectOutdatedApp: 'The SSH Key Manager app is out of date. Update the app, then try again.',
  connectFailed: 'Couldn’t connect. Try again.',

  menuLabel: 'Saved logins',
  menuLocked: 'Unlock SSH Key Manager to fill',
  menuHint: 'SSH Key Manager can fill this field. Press Down Arrow to choose.',
  noUsername: 'No username',
  fillConfirm: 'Confirm in SSH Key Manager to fill this login.',
  fillDenied: 'Not filled: declined in SSH Key Manager.',
  fillExpired: 'Not filled: no answer in SSH Key Manager. Choose the login again.',
  fillBusy: 'Answer the question open in SSH Key Manager first.',
  fillTooMany: 'Too many tries. Wait a minute, then choose the login again.',

  saveTitle: 'Save login for {site}?',
  updateTitle: 'Update password for {title}?',
  save: 'Save',
  update: 'Update',
  notNow: 'Not now',
  saved: 'Saved in SSH Key Manager',
  updated: 'Password updated in SSH Key Manager',
  saveLocked: 'Unlock the vault in SSH Key Manager, then choose Save again.',
  saveFailed: 'Couldn’t save. Try again.',
  usernameLabel: 'Username for this login',
  usernamePlaceholder: 'Username or email (optional)',
  siteLogins: 'Logins for {site}',
  siteLoginsNone:
    'No saved logins for this site yet. Sign in on the site and choose Save when asked.',
  siteLoginsFailed: 'Couldn’t load the logins for this site. Close the popup and open it again.',
  editLogin: 'Edit {login}',
  edit: 'Edit',
  usernameField: 'Username',
  newPassword: 'New password',
  newPasswordHint: 'Leave empty to keep the current password.',
  showPassword: 'Show password',
  hidePassword: 'Hide password',
  cancel: 'Cancel',
  keepLogin: 'Keep login',
  loginChanged: 'Saved. The old version stays in the entry’s history.',
  moveToBin: 'Move to recycle bin',
  moveToBinConfirm: 'Move {login} to the recycle bin? You can restore it in SSH Key Manager.',
  movedToBin: 'Moved to the recycle bin in SSH Key Manager. You can restore it there.',
  changeLocked: 'Unlock the vault in SSH Key Manager, then try again.',
  changeNotFound:
    'This login was removed or moved to another site in SSH Key Manager. Close the popup and open it again.',
  changeTooMany: 'Too many changes. Wait a minute, then try again.',
  changeFailed: 'Couldn’t save the change. Try again.',
  outdatedApp: 'Update SSH Key Manager to edit or remove logins from the browser.',

  signInFailedTitle: 'Couldn’t sign in?',
  signInFailedText: 'The password saved for {login} may be out of date.',
  signInRemove: 'Remove from vault',
  signInUpdateHint:
    'Type the current password and sign in. SSH Key Manager will then offer to update the saved one.',
  loginTitle: '“{title}”',
  loginTitleUser: '“{title}” ({username})',
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

  noHostTitle: 'Автозаполнение не настроено',
  noHostText:
    'Установите бесплатное приложение SSH Key Manager и включите в его настройках «Автозаполнение в браузере».',
  downloadApp: 'Скачать SSH Key Manager',
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

  suggestionsTitle: 'Подсказки самого браузера',
  suggestionsText:
    'Выключите, чтобы {browser} не предлагал сохранять пароли и не подсказывал прежние значения под полями входа.',
  suggestionsLocked: 'Задано вашей организацией или другим расширением.',
  suggestionsSaved:
    'Пароли, уже сохранённые в {browser}, он подсказывает по-прежнему. Импортируйте их в SSH Key Manager и удалите в браузере.',
  suggestionsOpen: 'Открыть пароли браузера',
  suggestionsDenied: 'Не изменено: браузер не дал разрешения.',

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
  connectOutdatedApp:
    'Приложение SSH Key Manager устарело. Обновите приложение и попробуйте снова.',
  connectFailed: 'Не удалось подключиться. Попробуйте ещё раз.',

  menuLabel: 'Сохранённые логины',
  menuLocked: 'Разблокируйте SSH Key Manager, чтобы заполнить',
  menuHint: 'SSH Key Manager может заполнить это поле. Нажмите стрелку вниз, чтобы выбрать.',
  noUsername: 'Без имени пользователя',
  fillConfirm: 'Подтвердите в SSH Key Manager, чтобы заполнить этот логин.',
  fillDenied: 'Не заполнено: отклонено в SSH Key Manager.',
  fillExpired: 'Не заполнено: в SSH Key Manager не ответили. Выберите логин ещё раз.',
  fillBusy: 'Сначала ответьте на открытый вопрос в SSH Key Manager.',
  fillTooMany: 'Слишком много попыток. Подождите минуту и выберите логин снова.',

  saveTitle: 'Сохранить логин для {site}?',
  updateTitle: 'Обновить пароль для {title}?',
  save: 'Сохранить',
  update: 'Обновить',
  notNow: 'Не сейчас',
  saved: 'Сохранено в SSH Key Manager',
  updated: 'Пароль обновлён в SSH Key Manager',
  saveLocked: 'Разблокируйте хранилище в SSH Key Manager и снова нажмите «Сохранить».',
  saveFailed: 'Не удалось сохранить. Попробуйте ещё раз.',
  usernameLabel: 'Имя пользователя для этого логина',
  usernamePlaceholder: 'Имя пользователя или email (необязательно)',
  siteLogins: 'Логины для {site}',
  siteLoginsNone:
    'Для этого сайта пока нет сохранённых логинов. Войдите на сайте и нажмите «Сохранить», когда расширение предложит.',
  siteLoginsFailed:
    'Не удалось загрузить логины для этого сайта. Закройте окно расширения и откройте снова.',
  editLogin: 'Изменить {login}',
  edit: 'Изменить',
  usernameField: 'Имя пользователя',
  newPassword: 'Новый пароль',
  newPasswordHint: 'Оставьте пустым, чтобы не менять пароль.',
  showPassword: 'Показать пароль',
  hidePassword: 'Скрыть пароль',
  cancel: 'Отмена',
  keepLogin: 'Оставить логин',
  loginChanged: 'Сохранено. Прежняя версия осталась в истории записи.',
  moveToBin: 'Переместить в корзину',
  moveToBinConfirm: 'Переместить {login} в корзину? Его можно восстановить в SSH Key Manager.',
  movedToBin: 'Перемещено в корзину SSH Key Manager. Там его можно восстановить.',
  changeLocked: 'Разблокируйте хранилище в SSH Key Manager и попробуйте снова.',
  changeNotFound:
    'Этот логин удалили или привязали к другому сайту в SSH Key Manager. Закройте окно расширения и откройте снова.',
  changeTooMany: 'Слишком много изменений. Подождите минуту и попробуйте снова.',
  changeFailed: 'Не удалось сохранить изменение. Попробуйте ещё раз.',
  outdatedApp: 'Обновите SSH Key Manager, чтобы изменять и удалять логины из браузера.',

  signInFailedTitle: 'Не получилось войти?',
  signInFailedText: 'Возможно, пароль, сохранённый для {login}, устарел.',
  signInRemove: 'Удалить из хранилища',
  signInUpdateHint:
    'Введите действующий пароль и войдите. SSH Key Manager предложит обновить сохранённый.',
  loginTitle: '«{title}»',
  loginTitleUser: '«{title}» ({username})',
  close: 'Закрыть',
};

const uz: Strings = {
  appName: 'SSH Key Manager',
  checking: 'Tekshirilmoqda…',
  openApp: 'SSH Key Managerni ochish',
  connect: 'Ulash',
  tryAgain: 'Qayta urinish',

  noHostTitle: 'Avtomatik toʻldirish sozlanmagan',
  noHostText:
    'Bepul SSH Key Manager ilovasini oʻrnating va uning Sozlamalarida «Brauzerda avtomatik toʻldirish»ni yoqing.',
  downloadApp: 'SSH Key Managerni yuklab olish',
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

  suggestionsTitle: 'Brauzerning oʻz takliflari',
  suggestionsText:
    '{browser} parollarni saqlashni taklif qilmasligi va kirish maydonlari ostida avval kiritilganlarni koʻrsatmasligi uchun oʻchiring.',
  suggestionsLocked: 'Tashkilotingiz yoki boshqa kengaytma tomonidan belgilangan.',
  suggestionsSaved:
    '{browser}da saqlangan parollar avvalgidek taklif qilinadi. Ularni SSH Key Managerga import qiling va brauzerda oʻchiring.',
  suggestionsOpen: 'Brauzer parollarini ochish',
  suggestionsDenied: 'Oʻzgartirilmadi: brauzer ruxsat bermadi.',

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
  connectOutdatedApp:
    'SSH Key Manager ilovasi eskirgan. Ilovani yangilang va qayta urinib koʻring.',
  connectFailed: 'Ulanib boʻlmadi. Qayta urinib koʻring.',

  menuLabel: 'Saqlangan loginlar',
  menuLocked: 'Toʻldirish uchun SSH Key Managerni oching',
  menuHint: 'SSH Key Manager bu maydonni toʻldira oladi. Tanlash uchun pastga strelkasini bosing.',
  noUsername: 'Foydalanuvchi nomi yoʻq',
  fillConfirm: 'Bu loginni toʻldirish uchun SSH Key Managerda tasdiqlang.',
  fillDenied: 'Toʻldirilmadi: SSH Key Managerda rad etildi.',
  fillExpired: 'Toʻldirilmadi: SSH Key Managerda javob berilmadi. Loginni qayta tanlang.',
  fillBusy: 'Avval SSH Key Managerdagi ochiq savolga javob bering.',
  fillTooMany: 'Urinishlar juda koʻp. Bir daqiqa kuting, keyin loginni qayta tanlang.',

  saveTitle: '{site} uchun login saqlansinmi?',
  updateTitle: '{title} uchun parol yangilansinmi?',
  save: 'Saqlash',
  update: 'Yangilash',
  notNow: 'Hozir emas',
  saved: 'SSH Key Managerda saqlandi',
  updated: 'Parol SSH Key Managerda yangilandi',
  saveLocked: 'SSH Key Managerda omborni oching, keyin yana «Saqlash»ni tanlang.',
  saveFailed: 'Saqlab boʻlmadi. Qayta urinib koʻring.',
  usernameLabel: 'Bu login uchun foydalanuvchi nomi',
  usernamePlaceholder: 'Foydalanuvchi nomi yoki email (ixtiyoriy)',
  siteLogins: '{site} uchun loginlar',
  siteLoginsNone:
    'Bu sayt uchun hali saqlangan login yoʻq. Saytga kiring va taklif qilinganda «Saqlash»ni tanlang.',
  siteLoginsFailed:
    'Bu sayt loginlarini yuklab boʻlmadi. Kengaytma oynasini yoping va qayta oching.',
  editLogin: 'Tahrirlash: {login}',
  edit: 'Tahrirlash',
  usernameField: 'Foydalanuvchi nomi',
  newPassword: 'Yangi parol',
  newPasswordHint: 'Joriy parolni saqlab qolish uchun boʻsh qoldiring.',
  showPassword: 'Parolni koʻrsatish',
  hidePassword: 'Parolni yashirish',
  cancel: 'Bekor qilish',
  keepLogin: 'Loginni qoldirish',
  loginChanged: 'Saqlandi. Oldingi versiya yozuv tarixida qoladi.',
  moveToBin: 'Savatga koʻchirish',
  moveToBinConfirm: '{login} savatga koʻchirilsinmi? Uni SSH Key Managerda tiklash mumkin.',
  movedToBin: 'SSH Key Manager savatiga koʻchirildi. Uni oʻsha yerda tiklash mumkin.',
  changeLocked: 'SSH Key Managerda omborni oching va qayta urinib koʻring.',
  changeNotFound:
    'Bu login SSH Key Managerda oʻchirilgan yoki boshqa saytga bogʻlangan. Kengaytma oynasini yoping va qayta oching.',
  changeTooMany: 'Oʻzgarishlar juda koʻp. Bir daqiqa kuting va qayta urinib koʻring.',
  changeFailed: 'Oʻzgarishni saqlab boʻlmadi. Qayta urinib koʻring.',
  outdatedApp: 'Brauzerdan loginlarni tahrirlash va oʻchirish uchun SSH Key Managerni yangilang.',

  signInFailedTitle: 'Kirib boʻlmadimi?',
  signInFailedText: '{login} uchun saqlangan parol eskirgan boʻlishi mumkin.',
  signInRemove: 'Ombordan olib tashlash',
  signInUpdateHint:
    'Amaldagi parolni kiriting va tizimga kiring. Shunda SSH Key Manager saqlanganini yangilashni taklif qiladi.',
  loginTitle: '«{title}»',
  loginTitleUser: '«{title}» ({username})',
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

/** What to say when a login couldn't be edited or removed. */
export function changeProblem(problem: Problem | undefined): Key {
  switch (problem) {
    case 'locked':
      return 'changeLocked';
    case 'notFound':
      return 'changeNotFound';
    case 'tooMany':
      return 'changeTooMany';
    case 'outdatedApp':
      return 'outdatedApp';
    default:
      return 'changeFailed';
  }
}

/** A login named as the extension's texts quote it: “Title” (username). */
export function loginName(login: { title: string; username: string }): string {
  return login.username
    ? t('loginTitleUser', { title: login.title, username: login.username })
    : t('loginTitle', { title: login.title });
}
