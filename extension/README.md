# SSH Key Manager for browsers

A Manifest V3 extension for Chrome, Edge, Brave and Firefox that fills logins from the
SSH Key Manager vault and offers to save new ones. It talks to the app through the
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
     `hklpabjhanmldimfcgoamipkmedjfpla`, fixed by the `key` in `manifest.json`; the
     host manifest allows only that id.
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

`e2e.mjs` drives Chrome through pairing, filling, exact-site matching, saving,
updating, the locked vault and disconnecting. It runs against
`src-tauri/examples/autofill_bridge.rs`, a bridge over a throwaway vault that approves
pairings by itself, with Chrome in a temporary profile: your browser profile and your
vault are never touched. Quit the app first, since the bridge takes over its endpoint
file while the test runs.

```bash
cargo build -p sshkm-app --bin sshkm-app --example autofill_bridge
pnpm extension:build
node extension/e2e.mjs
```

Pass the path of another Chromium browser as the first argument, and a folder as the
second to keep screenshots of each step.

## Publishing

Not done yet. The stores assign their own extension ids; add them to
`CHROMIUM_EXTENSION_IDS` in `src-tauri/src/browser/mod.rs` before shipping a build that
should talk to them.
