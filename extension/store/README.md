# Publishing in the Chrome Web Store

Everything the
[Developer Dashboard](https://chrome.google.com/webstore/devconsole) asks for is in
this folder, in the order the dashboard asks for it:

- `en.md`: the English listing, and the Privacy and Test instructions tabs (filled in
  once, in English);
- `ru.md`: the Russian listing;
- `images/`: the store icon, the screenshots for each language and the promo tile;
- `images.mjs`: the script that remakes the images (see the top of the file).

The store has no Uzbek listing language. The extension still speaks Uzbek wherever the
browser does.

## The order, and why

The app must know the extension's store id before the store version can talk to it,
and reviewers need a working app to test with. So:

1. Upload once to create the item, then send us its id and public key.
2. We add them, merge, and release the app as 0.4.0, with the extension at 0.4.0.
3. Upload the 0.4.0 package and submit it for review.

Fill in the listing, Privacy and other tabs whenever you like and save them as a
draft. Only **Submit for review** waits for step 3.

## 1. Build the package

On this branch (later, on the 0.4.0 release commit):

```bash
pnpm install
```

```bash
pnpm extension:package
```

This writes `extension/dist/ssh-key-manager-chromium-<version>.zip`, for example
`ssh-key-manager-chromium-0.3.1.zip`. It is the Chromium build without the manifest's
`key`: the store assigns its own id and key. The same build always gives the same zip.

## 2. Account

**Account** in the dashboard's menu:

| Field          | What to do                                                      |
| -------------- | --------------------------------------------------------------- |
| Contact email  | Verify it; the dashboard won't submit until you do.             |
| Publisher name | Shown under the listing as "Offered by".                        |
| Trader status  | If you're asked (EU Digital Services Act), answer for yourself. |

## 3. Create the item

**Items → New item**, choose the zip, then **Upload**. If the upload names
`_locales/uz` as a problem, remove that folder from the zip and upload again:

```bash
zip -d extension/dist/ssh-key-manager-chromium-0.3.1.zip '_locales/uz/*'
```

Then **send the item id and the public key**:

- **Item id:** 32 letters (`a` to `p`), at the top of the item's page and in its URL.
- **Public key:** **Package → View public key**. Copy everything between
  `-----BEGIN PUBLIC KEY-----` and `-----END PUBLIC KEY-----`.

The key goes into `extension/manifest.json` as `key`, so unpacked dev builds get the
store's id too. The id goes into `CHROMIUM_EXTENSION_IDS` in
`src-tauri/src/browser/mod.rs`, so the app's native messaging host lets the store
version in. Both are public; neither is a secret.

## 4. Store listing

**Store listing**, with **English** selected in the language menu at the top:

| Field                     | Paste from                                           |
| ------------------------- | ---------------------------------------------------- |
| Title, Summary            | Nothing: taken from the package                      |
| Description               | [en.md → Description](en.md#description)             |
| Category                  | [en.md → Category](en.md#category)                   |
| Language                  | [en.md → Language](en.md#language)                   |
| Store icon                | `images/icon-128.png`                                |
| Global promo video        | Leave empty                                          |
| Screenshots               | `images/en/1-fill.png` to `4-popup.png`, in order    |
| Small promo tile          | `images/promo-small-440x280.png`                     |
| Marquee promo tile        | Leave empty                                          |
| Official URL              | None                                                 |
| Homepage URL, Support URL | [en.md → Additional fields](en.md#additional-fields) |
| Mature content            | Off                                                  |

Then choose **Russian** in the language menu and fill in:

| Field       | Paste from                                        |
| ----------- | ------------------------------------------------- |
| Description | [ru.md → Description](ru.md#description)          |
| Screenshots | `images/ru/1-fill.png` to `4-popup.png`, in order |

**Save draft.**

## 5. Privacy

| Field                            | Paste from                                                                                                       |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Single purpose description       | [en.md → Single purpose description](en.md#single-purpose-description)                                           |
| Justification: `nativeMessaging` | [en.md → nativeMessaging](en.md#permission-justification-nativemessaging)                                        |
| Justification: `storage`         | [en.md → storage](en.md#permission-justification-storage)                                                        |
| Host permission justification    | [en.md → Host permission justification](en.md#host-permission-justification)                                     |
| Are you using remote code?       | **No, I am not using remote code** ([why](en.md#remote-code))                                                    |
| Data usage                       | Tick **Personally identifiable information** and **Authentication information** only ([table](en.md#data-usage)) |
| Certifications                   | Tick all three                                                                                                   |
| Privacy policy URL               | [en.md → Privacy policy URL](en.md#privacy-policy-url)                                                           |

The privacy policy is [PRIVACY.md](../../PRIVACY.md). Its `main` link works once this
branch is merged; until then use the branch link given in en.md.

**Save draft.**

## 6. Distribution

[en.md → Distribution](en.md#distribution): free of charge, public, all regions.
**Save draft.**

## 7. Test instructions

Leave Username and Password empty. Paste
[en.md → Test instructions](en.md#test-instructions) into **Additional instructions**.
The steps download SSH Key Manager 0.4.0, so this tab is only useful once 0.4.0 is
released. **Save draft.**

## 8. Submit, after the app's 0.4.0 release

1. Build the 0.4.0 package on the release commit (step 1). Then use
   **Package → Upload new package** with `ssh-key-manager-chromium-0.4.0.zip`.
2. Choose **Submit for review**.
3. In the dialog, **clear the box that publishes the item automatically after
   review** (deferred publishing). The extension then goes live only when you choose
   **Publish**, after checking that the app release is out. You have 30 days after
   approval; after that the submission goes back to draft.

If you submit before 0.4.0 is out, defer publishing for sure. Reviewers who can't
make the extension work without the app may reject it; the test instructions point
them to the release.

## Later updates

For each app release, `pnpm extension:package` on the release commit, then
**Package → Upload new package**, then **Submit for review**. The extension's version
always matches the app's; a test checks it.
