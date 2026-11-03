# Chrome Web Store texts: Russian

Add Russian from the language menu at the top of **Store listing**. Only the
description and screenshots differ per language. Category, links, icon and promo
tile are shared, and the **Privacy** and **Test instructions** tabs exist once per
item, filled in English from [en.md](en.md).

## Package (read only)

The store takes these from the zip's `_locales/ru/messages.json`.

| Field   | Value                                                                                                                                            |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| Title   | SSH Key Manager                                                                                                                                  |
| Summary | Заполняет и сохраняет пароли из хранилища SSH Key Manager — только на их сайтах. Работает с приложением SSH Key Manager. (120 of 132 characters) |

## Store listing

### Description

```text
SSH Key Manager подставляет сохранённые логины в формы входа и предлагает сохранить новые. Логины остаются в хранилище паролей приложения SSH Key Manager на вашем компьютере.

Как это работает
• Нажмите на поле входа — появятся логины, сохранённые для этого сайта. Выберите нужный, и он заполнится.
• Вошли с новым или изменённым паролем? Нажмите «Сохранить» или «Обновить» в появившемся окне.
• Если хранилище заблокировано, меню предложит разблокировать его в приложении.
• Кнопка расширения показывает, подключён ли браузер и разблокировано ли хранилище.

Только на своём сайте
• Логин предлагается только на том сайте, для которого он сохранён. Сайты сравниваются точно, поэтому похожие адреса ничего не получат.
• Логин, сохранённый для https, никогда не предлагается на http.
• Ничего не заполняется, пока вы не выберете логин.

Конфиденциальность
• Расширение общается только с приложением SSH Key Manager на вашем компьютере, через механизм native messaging браузера. Ничего не уходит в интернет. Без аккаунтов, аналитики и рекламы.
• Каждый браузер подключается один раз: браузер и приложение показывают шестизначный код, и вы подтверждаете, что он совпадает. Все сообщения после этого зашифрованы.
• Хранилище — зашифрованный файл KeePass (KDBX 4). Из всех ваших паролей расширение получает только пароль выбранного логина.
• Отключить браузер можно в любой момент — в расширении или в настройках приложения.

Что нужно
• Бесплатное приложение SSH Key Manager версии 0.4.0 или новее для macOS, Windows или Linux: https://github.com/nuriddin2468/ssh-key-manager
• В приложении откройте «Настройки» и включите «Автозаполнение в браузере». Затем нажмите кнопку расширения и выберите «Подключить».

SSH Key Manager — программа с открытым исходным кодом (лицензия AGPL-3.0).
Политика конфиденциальности (на английском): https://github.com/nuriddin2468/ssh-key-manager/blob/main/PRIVACY.md
```

### Screenshots

`images/ru/1-fill.png`, `2-save.png`, `3-connect.png`, `4-popup.png`, in order. They
show the extension in Russian.

## Uzbek

The Chrome Web Store has no Uzbek listing language, so there is no `uz.md`. The
extension itself still speaks Uzbek wherever the browser uses it, from
`_locales/uz` and its own strings.
