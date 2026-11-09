# Chrome Web Store texts: English

English is the listing's default language. The **Privacy** and **Test instructions**
tabs exist once per item, not per language, so their texts are only here.

Copy each block as it is. The store shows the description as plain text, so the
bullets are `•` characters, not Markdown.

## Package (read only)

The store takes these from the zip's `_locales/en/messages.json`; there is nothing to
type.

| Field   | Value                                                                                                                                                  |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Title   | SSH Key Manager                                                                                                                                        |
| Summary | Fill and save passwords from your SSH Key Manager vault, only on the sites they belong to. Works with the SSH Key Manager app. (126 of 132 characters) |

## Store listing

### Description

```text
SSH Key Manager fills your saved logins into sign-in forms and offers to save new ones. Your logins stay in the password vault of the SSH Key Manager app, on your computer.

How it works
• Click a login field to see the logins saved for that site, and pick one to fill it.
• Signed in with a new or changed password? Choose Save or Update in the banner that appears.
• If the vault is locked, the menu offers to unlock it in the app.
• The extension's button shows whether this browser is connected and whether the vault is unlocked.

Only on the right site
• A login is offered only on the site it was saved for. Sites are compared exactly, so look-alike addresses get nothing.
• A login saved for https is never offered on http.
• Nothing is filled until you pick a login.

Private by design
• The extension talks only to the SSH Key Manager app on your computer, through your browser's native messaging. Nothing goes over the internet. No accounts, analytics or ads.
• You connect each browser once, after checking that the browser and the app show the same 6-digit code. Every message after that is encrypted.
• The vault is an encrypted KeePass (KDBX 4) file. Of your passwords, the extension only ever receives the one for the login you pick.
• Disconnect a browser at any time, from the extension or from the app's Settings.

What you need
• The free SSH Key Manager app, version 0.4.0 or later, for macOS, Windows or Linux: https://github.com/nuriddin2468/ssh-key-manager
• In the app, open Settings and turn on Browser autofill. Then click the extension's button and choose Connect.

SSH Key Manager is open source (AGPL-3.0 license).
Privacy policy: https://github.com/nuriddin2468/ssh-key-manager/blob/main/PRIVACY.md
```

### Category

```text
Privacy & Security
```

(Under "Make Chrome Yours". If the list differs, choose **Tools** under Productivity.)

### Language

```text
English
```

### Graphic assets

| Field            | File                                                                           |
| ---------------- | ------------------------------------------------------------------------------ |
| Store icon       | `images/icon-128.png`                                                          |
| Screenshots      | `images/en/1-fill.png`, `2-save.png`, `3-connect.png`, `4-popup.png`, in order |
| Small promo tile | `images/promo-small-440x280.png`                                               |
| Marquee promo    | leave empty (only needed to be featured)                                       |
| YouTube video    | leave empty                                                                    |

### Additional fields

| Field          | Value                                                    |
| -------------- | -------------------------------------------------------- |
| Official URL   | None (it needs a site verified in Search Console)        |
| Homepage URL   | `https://github.com/nuriddin2468/ssh-key-manager`        |
| Support URL    | `https://github.com/nuriddin2468/ssh-key-manager/issues` |
| Mature content | Off                                                      |

## Privacy

### Single purpose description

```text
Fill and save the user's website logins from their SSH Key Manager password vault, only on the sites the logins belong to.
```

### Permission justification: nativeMessaging

```text
The extension talks to the SSH Key Manager desktop app on the user's computer, which holds the encrypted password vault. Native messaging is its only way to reach the app: it has no other source of logins and makes no network requests. The app's native messaging host accepts only this extension's id.
```

### Permission justification: storage

```text
After the user sends a login form, the username and password wait in chrome.storage.session (memory only, never written to disk) until the user answers the "Save login for <site>?" banner, which may appear on the next page. They are removed when the user answers, closes the tab or quits the browser, and are offered for three minutes at most. The username sent with the first step of a two-step sign-in waits there too, for five minutes, to name the password sent on the next page. So do the title and username (never the password) of the login last filled in a tab, for ten minutes: they name the login a password-change form updates, and tell when a sign-in with it seems to have failed. The extension uses no local or sync storage.
```

### Permission justification: activeTab

```text
When the user opens the extension's popup, it reads the address of the tab they are on, to list the logins saved for that site and let the user change a login's username or password, or move it to the vault's recycle bin. The popup reads nothing else of the tab, and only when the user opens it.
```

### Permission justification: privacy

The dashboard asks for this because of `optional_permissions`.

```text
Optional, and asked for only when the user turns off "Browser's own suggestions" in the extension's popup. The extension then sets privacy.services.passwordSavingEnabled and privacy.services.autofillAddressEnabled to false, so the browser's own password offers and suggestions don't cover the extension's menu under login fields. Turning the switch on again clears both settings, which gives them back to the user's own choice. The extension reads and changes no other setting.
```

### Host permission justification

The dashboard asks for this because the content script runs on `https://*/*` and
`http://*/*`.

```text
The content script finds login fields on whichever site the user signs in to, shows the logins saved for that site in a menu under the field, fills the login the user picks, and offers to save a new login after the user signs in. Logins can belong to any site, including intranet and local addresses on http, so the matches can't be narrowed to a fixed list. The menu has to appear as soon as the user clicks a field, without a click on the toolbar button, so activeTab isn't enough. It runs in all frames because many sign-in forms are in iframes. The script reads only login form fields: it fills nothing until the user picks a login, and reads a typed password only when the user sends the form. Which logins a page gets is decided by the origin Chrome reports for the frame, never by the page.
```

### Remote code

Choose **No, I am not using remote code**. Leave the justification empty. Every script
is bundled in the package, there are no remote scripts, `eval` or `new Function`, and
the extension makes no network requests.

### Data usage

Tick exactly these two under "What user data do you plan to collect from users now or
in the future?":

| Tick | Category                            | Why                                                                                                                 |
| ---- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| ☑    | Personally identifiable information | The username typed into a login form is often an email address.                                                     |
| ☑    | Authentication information          | Usernames and passwords filled into login forms from the vault, and those typed in to be saved there.               |
| ☐    | Health information                  | Not handled.                                                                                                        |
| ☐    | Financial and payment information   | Not handled.                                                                                                        |
| ☐    | Personal communications             | Not handled.                                                                                                        |
| ☐    | Location                            | Not handled.                                                                                                        |
| ☐    | Web history                         | Not collected: the site (origin) of a page with a login field is used for one lookup in the local app and not kept. |
| ☐    | User activity                       | Not handled: no clicks, keystrokes or scrolling are recorded.                                                       |
| ☐    | Website content                     | Not handled: only login form fields are read.                                                                       |

"Collect" covers data handled only on the user's computer too, which is why the first
two are ticked even though nothing leaves the computer. If a reviewer asks about the
page address, tick **Web history** as well.

Tick all three certifications:

- ☑ I do not sell or transfer user data to third parties, outside of the approved use
  cases
- ☑ I do not use or transfer user data for purposes that are unrelated to my item's
  single purpose
- ☑ I do not use or transfer user data to determine creditworthiness or for lending
  purposes

### Privacy policy URL

```text
https://github.com/nuriddin2468/ssh-key-manager/blob/main/PRIVACY.md
```

This link works once the `browser-autofill` branch is merged into `main`. Before
that, use
`https://github.com/nuriddin2468/ssh-key-manager/blob/browser-autofill/PRIVACY.md`
and change it after the merge.

## Distribution

| Field      | Value          |
| ---------- | -------------- |
| Payments   | Free of charge |
| Visibility | Public         |
| Regions    | All regions    |

## Test instructions

Leave **Username** and **Password** empty: the extension has no account. Paste this
into **Additional instructions**:

```text
The extension needs the free SSH Key Manager desktop app (0.4.0 or later), which holds the password vault. Without it, the extension's popup says that browser autofill isn't set up, with a button to download the app.

1. Install SSH Key Manager from https://github.com/nuriddin2468/ssh-key-manager/releases/latest (macOS .dmg, Windows installer, or Linux .deb/.AppImage) and open it.
2. Open Passwords, enter any master password twice and choose Create vault. Tick "I've saved my recovery key" and choose Continue.
3. Choose New entry and keep the Login kind. Set Title "Test", User name "tomsmith", Password "SuperSecretPassword!", Website "https://the-internet.herokuapp.com", and choose Add entry.
4. Open Settings and turn on "Fill passwords in your browser" under Browser autofill.
5. In Chrome, click the extension's button and choose Connect. A page shows a 6-digit code, and the app shows the same code; choose Connect in the app.
6. Open https://the-internet.herokuapp.com/login and click the Username field. A menu lists "Test"; pick it to fill both fields.
7. To see saving: sign in on any other site with a login form. After sending the form, a "Save login for <site>?" banner appears; choose Save, and the login appears in the app under Passwords.
8. Lock the vault in the app (the lock button in Passwords) and click a login field again: the menu offers to unlock SSH Key Manager instead.
```
