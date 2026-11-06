# SSH Key Manager for browsers

A Manifest V3 extension for Chrome, Edge, Brave and Firefox that fills logins from the
SSH Key Manager vault and offers to save new ones. Install it from the
[Chrome Web Store](https://chromewebstore.google.com/detail/ssh-key-manager/lkmgdcanagjeajepncgokapkbihahddb). It talks to the app through the
app's native messaging host; see [SECURITY.md](../SECURITY.md#browser-autofill) for the
threat model and [docs/architecture.md](../docs/architecture.md#browser-extension) for
how the pieces fit.

```text
src/background.ts     the only part that talks to the app for pages
src/content.ts        login fields, the menu and the save banner (content/)
src/popup.ts          the toolbar popup: connection state and one action
src/connect.ts        the page that pairs this browser with the app
src/shared/channel.ts pairing and sealing with WebCrypto (mirrors sshkm-core)
manifest.json         one manifest; build.mjs adjusts it per browser
package.mjs           the Chrome Web Store zip
store/                the store listing, privacy answers and images
```

## Build

```bash
pnpm extension:build
```

This writes `extension/dist/chromium` and `extension/dist/firefox`.

## Try it with a dev build

1. Build the app (`pnpm app:dev`, or `cargo build -p sshkm-app`), open **Settings →
   Browser autofill** and turn it on. This registers the running executable as the
   native messaging host with each installed browser.
2. Load the extension:
   - Chrome, Edge, Brave: open `chrome://extensions`, turn on Developer mode, choose
     **Load unpacked** and pick `extension/dist/chromium`. Its id is
     `lkmgdcanagjeajepncgokapkbihahddb`, the Chrome Web Store item's: the `key` in
     `manifest.json` is the item's public key. The host manifest allows only that id.
   - Firefox (128 or newer): open `about:debugging#/runtime/this-firefox`, choose
     **Load Temporary Add-on** and pick `extension/dist/firefox/manifest.json`.
3. Click the extension's icon and choose **Connect**. Check that the app shows the same
   code, then choose **Connect** in the app.

On macOS, browsers may not start programs from `~/Documents`, `~/Desktop` or
`~/Downloads`: a dev build there hangs as soon as the browser starts it, because macOS
waits for a permission the browser doesn't have. Build from another folder, or copy
the built `sshkm-app` elsewhere and turn autofill off and on again from that copy.
Installed apps in `/Applications` are not affected.

## End-to-end test

`e2e.mjs` drives Chrome through pairing, filling (and the app's question before it),
exact-site matching, the daily key change, saving, updating, the locked vault and
disconnecting. It runs against `src-tauri/examples/autofill_bridge.rs`, a bridge over a
throwaway vault that approves pairings and fills by itself, with Chrome in a temporary
profile: your browser profile and your vault are never touched. Quit the app first, since the bridge takes over its endpoint
file while the test runs.

```bash
cargo build -p sshkm-app --bin sshkm-app --example autofill_bridge
pnpm extension:build
node extension/e2e.mjs
```

Pass the path of another Chromium browser as the first argument, and a folder as the
second to keep screenshots of each step.

## Publishing

```bash
pnpm extension:package
```

This writes `extension/dist/ssh-key-manager-chromium-<version>.zip` for the Chrome Web
Store and Edge Add-ons (the Chromium build without the manifest's `key`, which the store
keeps itself) and `ssh-key-manager-firefox-<version>.zip` for addons.mozilla.org. Each
release sends them to the stores by itself (see
[store/README.md](store/README.md#automatic-publishing)).
[store/README.md](store/README.md) walks through the dashboard, with the listing texts,
privacy answers and images in [store/](store/). The item's id,
`lkmgdcanagjeajepncgokapkbihahddb`, is in `CHROMIUM_EXTENSION_IDS` in
`src-tauri/src/browser/mod.rs`, so the app lets it in.
