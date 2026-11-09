# Publishing on addons.mozilla.org

The Firefox add-on is the same extension as the Chrome one, built from the same
sources into `extension/dist/firefox`. Its id, `autofill@sshkeymanager.dev`, is set by
`browser_specific_settings.gecko.id` in `extension/manifest.json`, and the app already
lets it in (`FIREFOX_EXTENSION_ID` in `src-tauri/src/browser/mod.rs`). So unlike the
Chrome Web Store, there's no id to send back before a release: the first version can
go up as soon as the listing is ready.

The first version goes up by hand, through the
[Developer Hub](https://addons.mozilla.org/developers/), because that creates the
add-on and its listing. Later versions go up with each release
([automatic publishing](README.md#automatic-publishing)).

## 0. Check it in Firefox

```bash
node extension/e2e.mjs --firefox
```

That runs the whole end-to-end test in Firefox (see
[extension/README.md](../README.md#end-to-end-test)). By hand: install the app,
start Firefox once, then turn on **Settings → Browser autofill** in the app. Load
`extension/dist/firefox/manifest.json` with **Load Temporary Add-on** on
`about:debugging#/runtime/this-firefox`. The app registers with Firefox only once
Firefox has a profile, so if you started Firefox for the first time after turning
autofill on, restart the app.

## 1. Account

Sign in to the Developer Hub with a Mozilla account. It doesn't accept disposable
email addresses. Accept the Firefox Add-on Distribution Agreement, and turn on
two-step authentication if the Hub asks for it.

## 2. Build the package and the source

On the commit you submit, with a clean working tree (a release tag, or for the first
version `main` once Firefox's manifest settings are merged):

```bash
pnpm install
```

```bash
pnpm extension:package
```

```bash
git archive --format=zip -o extension/dist/ssh-key-manager-source.zip HEAD
```

`pnpm extension:package` writes `extension/dist/ssh-key-manager-firefox-<version>.zip`,
the add-on. `git archive` writes the source archive. Reviewers need the source because
the scripts are bundled with Vite. The package and the source must come from the same
commit. `release.yml` makes the same two files for each release.

## 3. Submit a New Add-on

| Step                 | What to do                                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------------------------------- |
| How to distribute    | **On this site**                                                                                                      |
| Upload               | `ssh-key-manager-firefox-<version>.zip`. Validation errors stop you here; warnings don't.                             |
| Compatibility        | **Firefox** only. Clear **Firefox for Android**: it has no native messaging, so the add-on can't reach the app there. |
| Source code          | **Yes**, and upload `ssh-key-manager-source.zip`                                                                      |
| Name, Summary        | Taken from the package ([below](#name-and-summary)); leave them as they are                                           |
| Add-on URL           | `ssh-key-manager` if it's free                                                                                        |
| Description          | [Description](#description)                                                                                           |
| Experimental         | Off                                                                                                                   |
| Requires payment…    | Off. The app it needs is free and open source.                                                                        |
| Firefox categories   | **Privacy & Security**                                                                                                |
| Support email        | An address you're happy to show publicly, or leave empty                                                              |
| Support website      | `https://github.com/nuriddin2468/ssh-key-manager/issues`                                                              |
| License              | **GNU Affero General Public License v3.0 only** (the project's `AGPL-3.0-only`)                                       |
| Has a privacy policy | On, and paste [PRIVACY.md](../../PRIVACY.md) as it is                                                                 |
| Notes for reviewers  | [Notes for reviewers](#notes-for-reviewers)                                                                           |

Then **Submit Version**.

## 4. The rest of the listing

After the submission, open the add-on's listing editor (**Edit Product Page**):

| Section     | What to do                                                                                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Icon        | The package's icon is used. If the editor asks, upload `images/icon-128.png`.                                                               |
| Screenshots | `images/en/1-fill.png` to `4-popup.png`, in order (1280×800, the size AMO recommends), with the [captions](#screenshot-captions)            |
| Homepage    | `https://github.com/nuriddin2468/ssh-key-manager`                                                                                           |
| Russian     | Switch the editor's language to Russian; check the name and summary, and paste the [Russian description](#russian-description) and captions |

There is one set of screenshots for every language; only the captions are translated.
AMO has Uzbek too, but there's no Uzbek listing text yet.

## 5. Automatic publishing

On addons.mozilla.org, **Tools → Manage API Keys** gives a JWT issuer and secret. Add
them as `AMO_JWT_ISSUER` and `AMO_JWT_SECRET` to the `extension-stores` environment
(see [README.md](README.md#automatic-publishing)). From then on, each release uploads
the new version with its source archive and sends it to review.

## 6. After approval

Send the add-on's page address, so the app's **Settings → Browser autofill** and the
READMEs can link to it next to the Chrome Web Store.

## Data collection

Firefox shows, when the add-on is installed, the data the manifest says it collects:
`browser_specific_settings.gecko.data_collection_permissions`. The manifest declares
**authentication information** and **personally identifying information** as
required, the same two categories the Chrome Web Store's
[Data usage](en.md#data-usage) answers tick:

- Mozilla counts data as transmitted when it is handled "outside the add-on or the
  local browser", with no exception for the user's own computer.
- The add-on policies say that their consent rules apply to data sent to a native
  application too.
- Logins go between the page and the app: the username and password of the login you
  pick, and a login you typed, to be saved. Usernames are often email addresses.

Firefox shows this list itself from Firefox 140, so the manifest asks for Firefox 140
or later (`strict_min_version`). Older versions would need a consent page of the
add-on's own.

## Texts

### Name and summary

The Hub takes these from the package's `_locales/<language>/messages.json`.

| Field   | English                                                                                                                        |
| ------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Name    | SSH Key Manager                                                                                                                |
| Summary | Fill and save passwords from your SSH Key Manager vault, only on the sites they belong to. Works with the SSH Key Manager app. |

| Field   | Russian                                                                                                                  |
| ------- | ------------------------------------------------------------------------------------------------------------------------ |
| Name    | SSH Key Manager                                                                                                          |
| Summary | Заполняет и сохраняет пароли из хранилища SSH Key Manager — только на их сайтах. Работает с приложением SSH Key Manager. |

### Description

The description takes some Markdown: lists, bold and links. Check the preview after
saving.

```markdown
SSH Key Manager fills your saved logins into sign-in forms and offers to save new ones. Your logins stay in the password vault of the SSH Key Manager app, on your computer.

**How it works**

- Click a login field to see the logins saved for that site, and pick one to fill it.
- Signed in with a new or changed password? Choose Save or Update in the banner that appears.
- If the vault is locked, the menu offers to unlock it in the app.
- The extension's button shows whether this browser is connected and whether the vault is unlocked.

**Only on the right site**

- A login is offered only on the site it was saved for. Sites are compared exactly, so look-alike addresses get nothing.
- A login saved for https is never offered on http.
- Nothing is filled until you pick a login.

**Private by design**

- The extension talks only to the SSH Key Manager app on your computer, through Firefox's native messaging. Nothing goes over the internet. No accounts, analytics or ads.
- Firefox lists authentication and personally identifying information when you install it: these are the usernames and passwords the extension passes between web pages and the app. They stay on your computer.
- You connect each browser once, after checking that the browser and the app show the same 6-digit code. Every message after that is encrypted.
- The vault is an encrypted KeePass (KDBX 4) file. Of your passwords, the extension only ever receives the one for the login you pick.
- Disconnect a browser at any time, from the extension or from the app's Settings.

**What you need**

- The free SSH Key Manager app, version 0.4.0 or later, for macOS, Windows or Linux: [github.com/nuriddin2468/ssh-key-manager](https://github.com/nuriddin2468/ssh-key-manager)
- In the app, open Settings and turn on Browser autofill. Then click the extension's button and choose Connect.

SSH Key Manager is open source (AGPL-3.0 license).
```

### Russian description

```markdown
SSH Key Manager подставляет сохранённые логины в формы входа и предлагает сохранить новые. Логины остаются в хранилище паролей приложения SSH Key Manager на вашем компьютере.

**Как это работает**

- Нажмите на поле входа — появятся логины, сохранённые для этого сайта. Выберите нужный, и он заполнится.
- Вошли с новым или изменённым паролем? Нажмите «Сохранить» или «Обновить» в появившемся окне.
- Если хранилище заблокировано, меню предложит разблокировать его в приложении.
- Кнопка расширения показывает, подключён ли браузер и разблокировано ли хранилище.

**Только на своём сайте**

- Логин предлагается только на том сайте, для которого он сохранён. Сайты сравниваются точно, поэтому похожие адреса ничего не получат.
- Логин, сохранённый для https, никогда не предлагается на http.
- Ничего не заполняется, пока вы не выберете логин.

**Конфиденциальность**

- Расширение общается только с приложением SSH Key Manager на вашем компьютере, через механизм native messaging Firefox. Ничего не уходит в интернет. Без аккаунтов, аналитики и рекламы.
- При установке Firefox сообщает, что расширение работает с данными для входа и личными данными: это логины и пароли, которые оно передаёт между сайтами и приложением. Они не покидают ваш компьютер.
- Каждый браузер подключается один раз: браузер и приложение показывают шестизначный код, и вы подтверждаете, что он совпадает. Все сообщения после этого зашифрованы.
- Хранилище — зашифрованный файл KeePass (KDBX 4). Из всех ваших паролей расширение получает только пароль выбранного логина.
- Отключить браузер можно в любой момент — в расширении или в настройках приложения.

**Что нужно**

- Бесплатное приложение SSH Key Manager версии 0.4.0 или новее для macOS, Windows или Linux: [github.com/nuriddin2468/ssh-key-manager](https://github.com/nuriddin2468/ssh-key-manager)
- В приложении откройте «Настройки» и включите «Автозаполнение в браузере». Затем нажмите кнопку расширения и выберите «Подключить».

SSH Key Manager — программа с открытым исходным кодом (лицензия AGPL-3.0).
```

### Screenshot captions

| Screenshot    | English                                         | Russian                                                   |
| ------------- | ----------------------------------------------- | --------------------------------------------------------- |
| 1-fill.png    | Pick a saved login under the field to fill it   | Выберите сохранённый логин под полем, чтобы заполнить его |
| 2-save.png    | Save a new login right after signing in         | Сохраните новый логин сразу после входа                   |
| 3-connect.png | Connect the browser once, after checking a code | Подключите браузер один раз, сверив код                   |
| 4-popup.png   | See whether autofill is ready                   | Проверьте, готово ли автозаполнение                       |

### Notes for reviewers

```text
HOW TO BUILD
The scripts are bundled from TypeScript with Vite (not minified); the attached source is the whole repository at the release tag. To rebuild them: Node 22 or later, then `corepack enable`, `pnpm install --frozen-lockfile` and `pnpm extension:package` in the repository's root. The add-on is in extension/dist/firefox; extension/README.md says more.

HOW TO TEST
The add-on needs the free SSH Key Manager desktop app (0.4.0 or later), which holds the password vault; it talks to the app through native messaging and makes no network requests. Without the app, its popup says that browser autofill is off.

1. Start Firefox once, so it has a profile. Then install SSH Key Manager from https://github.com/nuriddin2468/ssh-key-manager/releases/latest (macOS .dmg, Windows installer, or Linux .deb/.AppImage) and open it.
2. Open Passwords, enter any master password twice and choose Create vault. Tick "I've saved my recovery key" and choose Continue.
3. Choose New entry and keep the Login kind. Set Title "Test", User name "tomsmith", Password "SuperSecretPassword!", Website "https://the-internet.herokuapp.com", and choose Add entry.
4. Open Settings and turn on "Fill passwords in your browser" under Browser autofill. This registers the app's native messaging host with Firefox. (If Firefox was started for the first time after this, quit and reopen the app.)
5. In Firefox, click the add-on's button (under the Extensions button in the toolbar) and choose Connect. A page shows a 6-digit code, and the app shows the same code; choose Connect in the app.
6. Open https://the-internet.herokuapp.com/login and click the Username field. A menu lists "Test"; pick it to fill both fields.
7. To see saving: sign in on any other site with a login form. After sending the form, a "Save login for <site>?" banner appears; choose Save, and the login appears in the app under Passwords.
8. Lock the vault in the app (the lock button in Passwords) and click a login field again: the menu offers to unlock SSH Key Manager instead.
```
