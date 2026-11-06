# Changelog

What changed in each version of SSH Key Manager. The app shows these notes in your language before it updates, and once more after.

<!-- Made from changelog/releases.json by scripts/changelog.mjs: edit that file, then run `node scripts/changelog.mjs write`. -->

## 0.8.0 (2026-11-06)

### Before you update

- From this version, ⇧⌘Space (Ctrl+Shift+Space on Windows and Linux) opens quick search from any app. If another app of yours uses it, change or turn it off in Settings → Quick search.

### New

- Quick search: ⇧⌘Space (Ctrl+Shift+Space) or the tray menu opens a small window from any app to connect to a host, copy a password or 2FA code, or unlock the vault.
- Command palette: press ⌘K (Ctrl+K) to find a host, key, password or action and run it from the keyboard.
- Key rotation: replace an old SSH key with a new Ed25519 key on every server that uses it. The app installs and checks the new key, updates your hosts, and removes the old key only where the new one works.
- When a connection fails, the app explains why — a key the server refused, a changed host key, a timeout, an unknown name — and offers the fix, such as installing the key or checking the port.
- Secret environments: keep your projects’ .env variables in the vault (dev, staging, prod), import and export .env, JSON, YAML and Kubernetes files, compare environments, open a terminal with one, and send it over Nearby to a computer with this version or later.
- New Tools page. Its secret generator makes database, shell-safe and .env passwords, API tokens, UUIDs, JWT secrets, framework keys (Laravel, Django, Rails), Wi-Fi passwords, passphrases and PINs.
- Network tools: SSH ping with the server’s version, a port check, a DNS lookup that shows what your hosts file changes, and a TLS certificate check.
- More SSH tools: a ProxyJump wizard for reaching servers through a bastion, a key converter for PuTTY .ppk and PEM keys, and an authorized_keys line builder with options.
- SSH tunnels: save local, remote and SOCKS port forwards, switch them on and off, and see their state, also from the tray menu.
- The audit checks ~/.ssh/config for risky settings — StrictHostKeyChecking no, UserKnownHostsFile /dev/null, ForwardAgent yes for every host, and too many agent keys without IdentitiesOnly — and fixes them in one click.
- Optional breach check: the audit can look up your saved passwords in Have I Been Pwned. It stays off until you turn it on, and only the first 5 characters of each password’s hash leave your computer.
- If you allow it, the Hosts page suggests servers you often connect to, from your shell history, ready to add. It runs only on your computer, and your commands and any passwords in them stay private.
- Browser extension: a switch in its popup turns off the browser’s own offers to save passwords and its form suggestions, so only SSH Key Manager shows under login fields.
- Before an update, What’s new shows what each version since yours changed, in your language, with what to know first and security fixes at the top. You update from there.
- After an update, the app says once what changed. Settings → Updates lists what changed in each version.

### Improved

- The audit page is clearer: its colour follows the most serious problem, password findings count in the total, cards and chips filter by area and severity, safe fixes run with one button, and a list shows every check that ran.
- Importing passwords starts with where they are now — your browser, Bitwarden, 1Password, KeePassXC, LastPass or any CSV file — and shows how to export them from there.
- Unlock Vault in the tray menu asks for Touch ID, Windows Hello or the master password in a small window instead of opening the whole app.
- Browser extension: the login menu no longer opens over a login that’s already filled in; press Down Arrow to open it anyway. Logins for the username you typed come first.
- Browser extension: the “Save login” banner lets you type or correct the username, and sign-ins that ask for the username and the password on separate pages are saved with both.
- Before installing an update, the app saves a copy of your vault, ~/.ssh/config and known_hosts with its other backups.

### Fixed

- On the Nearby page, the This computer card no longer shrinks to a thin strip when several devices are listed.

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
