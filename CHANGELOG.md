# Changelog

What changed in each version of SSH Key Manager. The app shows these notes in your language before it updates, and once more after.

<!-- Made from changelog/releases.json by scripts/changelog.mjs: edit that file, then run `node scripts/changelog.mjs write`. -->

## 0.7.0 (2026-11-06)

### Before you update

- On macOS and Windows, closing the window no longer quits the app: it keeps running in the tray (the menu bar on macOS). To quit, choose Quit SSH Key Manager in its menu, or turn this off in Settings → Background.

### New

- With the window closed, browser autofill, your devices and terminal sessions keep working. The tray menu shows whether the vault is locked, locks it and connects to recent hosts.
- Unlock in SSH Key Manager, in the browser extension, now asks in the app, with Touch ID, Windows Hello or a small window of its own, so the master password is never typed in the browser.
- The browser extension is in the Chrome Web Store, for Chrome, Edge, Brave and other Chromium browsers.

## 0.6.0 (2026-11-04)

### Security

- Before a browser fills a login on a page for the first time, the app asks with Touch ID, Windows Hello or a system dialog, so neither a page nor a program that copied the extension’s keys can answer for you.
- Fixes from a security review of the whole app: lines in ~/.ssh/config that run a program are confirmed even when unusual characters hide them, and Nearby, the vault and browser autofill are harder to misuse. SECURITY.md has the details.

### New

- Nearby: send a password or a host to another computer on the same network. The other computer sees what it is and saves it only if you accept.
- My devices: move the vault to your new computer and keep hosts in step between your computers with Sync now. Two different vaults are never merged.
- Keys on the server…, in a host’s menu, lists the keys in the server’s authorized_keys, adds one of yours and removes one after asking. It never offers to remove this computer’s only way in.

### Improved

- Hosts are cards that show whether each server lets you in, with Check and Connect, and the editor lists recent connections.
- Saved key passphrases and host passwords show in place, masked, with show and copy, and a locked vault opens in a dialog on the page you’re on.

### Fixed

- Check no longer says the server refused your keys when a key only needs its passphrase: the app asks for it first.
- Dialogs no longer scroll sideways.

## 0.5.0 (2026-11-03)

### Security

- Saved key passphrases and host-key answers never go to a prompt the server wrote, and older OpenSSH versions no longer fill in saved secrets through a jump host.
- Touch ID unlock turns off when fingerprints change, and Windows Hello unlock is bound to a Windows Hello key.
- Changes that make ssh run a program, weaken the vault’s protection or add or remove a key’s passphrase are confirmed in a system dialog.
- Browser autofill ignores events a page makes up, refuses sandboxed frames and won’t accept a pick the page has covered or moved.

## 0.4.0 (2026-11-03)

### New

- Browser autofill: an extension for Chrome, Edge and Firefox fills in a site’s logins from the vault on that site only, and offers to save new ones.
- Move hosts file entries between groups by dragging them.

## 0.3.1 (2026-11-03)

### Fixed

- The installed app no longer opens to a blank window.

## 0.3.0 (2026-11-03)

### New

- Password vault: keep server passwords, key passphrases and 2FA codes encrypted with a master password, and unlock it with Touch ID or Windows Hello. It can be imported, exported and kept in a folder of your choice.
- A terminal in the app connects to your hosts and fills in their saved passwords and passphrases.

### Improved

- The host editor is grouped around how you sign in, and Settings moved into the sidebar menu.

## 0.2.2 (2026-11-02)

### New

- Hosts file: view, check and edit /etc/hosts, with groups and temporary entries.

### Fixed

- On Linux, the window no longer lags on computers with an NVIDIA graphics card.

## 0.2.1 (2026-11-02)

### Fixed

- On Linux, the app no longer refreshes over and over while it watches ~/.ssh.

## 0.2.0 (2026-11-02)

### New

- Manage your SSH keys, the hosts in ~/.ssh/config, known_hosts and ssh-agent on macOS, Windows and Linux.
- The app checks for updates and installs them itself.

### Fixed

- On Windows, the app finds ssh-agent through the OpenSSH pipe when SSH_AUTH_SOCK isn’t one.
