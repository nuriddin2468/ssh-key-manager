# Publishing in the Chrome Web Store

For addons.mozilla.org, see [firefox.md](firefox.md).

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

1. ~~Upload once to create the item, then send us its id and public key.~~ Done: see
   [step 3](#3-create-the-item-done).
2. ~~Merge, and release the app as 0.4.0, with the extension at 0.4.0.~~ Done.
3. ~~Upload the 0.4.0 package and submit it for review.~~ Done: the extension is
   approved and published. Later versions go to the store with each release
   ([automatic publishing](#automatic-publishing)).

Fill in the listing, Privacy and other tabs whenever you like and save them as a
draft. Only **Submit for review** waits for step 3.

## 1. Build the package

On the 0.4.0 release commit (and later, on each release commit):

```bash
pnpm install
```

```bash
pnpm extension:package
```

This writes `extension/dist/ssh-key-manager-chromium-<version>.zip`, for example
`ssh-key-manager-chromium-0.4.0.zip`. It is the Chromium build without the manifest's
`key`, which the store keeps itself. The same build always gives the same zip.

## 2. Account

**Account** in the dashboard's menu:

| Field          | What to do                                                      |
| -------------- | --------------------------------------------------------------- |
| Contact email  | Verify it; the dashboard won't submit until you do.             |
| Publisher name | Shown under the listing as "Offered by".                        |
| Trader status  | If you're asked (EU Digital Services Act), answer for yourself. |

## 3. Create the item: done

The item is `lkmgdcanagjeajepncgokapkbihahddb`. Its store page is
<https://chromewebstore.google.com/detail/ssh-key-manager/lkmgdcanagjeajepncgokapkbihahddb>; **Settings → Browser autofill** in the app links to it
(`CHROME_WEB_STORE` in `src/features/browser/BrowserAutofillSection.tsx`).

- Its public key (**Package → View public key**) is the `key` in
  `extension/manifest.json`, so unpacked dev builds get the store's id too.
- Its id is in `CHROMIUM_EXTENSION_IDS` in `src-tauri/src/browser/mod.rs`, so the
  app's native messaging host lets the store version in. A test checks that the key
  gives this id.

Both are public; neither is a secret.

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
| Justification: `privacy`         | [en.md → privacy](en.md#permission-justification-privacy)                                                        |
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
   **Package → Upload new package** with `ssh-key-manager-chromium-0.4.0.zip`. If the
   upload names `_locales/uz` as a problem, remove that folder from the zip and upload
   again:

   ```bash
   zip -d extension/dist/ssh-key-manager-chromium-0.4.0.zip '_locales/uz/*'
   ```

2. Choose **Submit for review**.
3. In the dialog, **clear the box that publishes the item automatically after
   review** (deferred publishing). The extension then goes live only when you choose
   **Publish**, after checking that the app release is out. You have 30 days after
   approval; after that the submission goes back to draft.

If you submit before 0.4.0 is out, defer publishing for sure. Reviewers who can't
make the extension work without the app may reject it; the test instructions point
them to the release.

## Later updates

Each app release sends the extension to the stores by itself; see
[Automatic publishing](#automatic-publishing). By hand, for a store without its
secrets: `pnpm extension:package` on the release commit, then
**Package → Upload new package**, then **Submit for review**. The extension's version
always matches the app's; a test checks it, and so does the release.

The listing and the Privacy tab never change by themselves. When a release adds a
permission (optional ones too) or changes what the extension stores, paste the new
answers from [en.md → Privacy](en.md#privacy) into the dashboard **before** the release:
the store refuses to publish a package with a permission it has no justification for
(`INVALID_ITEM_METADATA`). A test checks that en.md has an answer for every permission,
and `pnpm release` names the permissions added since the last release. If the publish
step failed anyway, the package is already uploaded: fix the dashboard, then choose
**Submit for review** there.

## Automatic publishing

`release.yml` builds the extension in a job without secrets: the Chromium zip, the
Firefox zip and, for Firefox reviewers, the source (the repository at the tag). Once
the app's release is published, the `extension-stores` job uploads them with
[.github/scripts/extension_stores.py](../../.github/scripts/extension_stores.py) and
submits each for review. Only the package changes; listings and screenshots stay as the
stores have them. A store goes live with the new version when its review approves it.

The job reads its secrets from the `extension-stores` environment (**Settings →
Environments**), so no other job can. Under **Deployment branches and tags**, allow only
the tags `v*`, so only a release can use them. Add the secrets of each store you publish
to; a store without them is skipped with a notice. Required reviewers on the environment
make each release wait for a yes before anything is uploaded.

| Store            | Secrets                                                                       | Before the first run                                             |
| ---------------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| Chrome Web Store | `CWS_CLIENT_ID`, `CWS_CLIENT_SECRET`, `CWS_REFRESH_TOKEN`, `CWS_PUBLISHER_ID` | The item exists and was published once by hand                   |
| Firefox Add-ons  | `AMO_JWT_ISSUER`, `AMO_JWT_SECRET`                                            | The add-on exists, with its listing ([firefox.md](firefox.md))   |
| Edge Add-ons     | `EDGE_CLIENT_ID`, `EDGE_API_KEY`, `EDGE_PRODUCT_ID`                           | The product exists in Partner Center                             |

- **Chrome Web Store.** In a Google Cloud project, enable the Chrome Web Store API. Set
  up the OAuth consent screen (**External**) and make an OAuth client of type **Web
  application** with the redirect URI `https://developers.google.com/oauthplayground`.
  Then set the consent screen's publishing status to **In production**: in **Testing**,
  refresh tokens stop working after seven days. In the
  [OAuth 2.0 Playground](https://developers.google.com/oauthplayground), choose **Use
  your own OAuth credentials** (the gear), enter the scope
  `https://www.googleapis.com/auth/chromewebstore`, sign in as the publisher's account
  and exchange the code for tokens: that gives the refresh token. The publisher id is
  under **Publisher → Settings** in the Developer Dashboard. The account needs two-step
  verification.
- **Firefox Add-ons.** **Tools → Manage API Keys** on addons.mozilla.org: the JWT issuer
  and secret.
- **Edge Add-ons.** Partner Center → Microsoft Edge → **Publish API**: enable the new
  experience, then **Create API credentials** for the client id and API key. The key
  expires; renew it there and update the secret. The product id is on the extension's
  overview page.

If a store refuses the package after the upload, finish that store by hand: it already
has the version, so running the job again fails there.
