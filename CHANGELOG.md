# Changelog

What changed in each version of SSH Key Manager. The app shows these notes in your language before it updates, and once more after.

<!-- Made from changelog/releases.json by scripts/changelog.mjs: edit that file, then run `node scripts/changelog.mjs write`. -->

## 0.11.0 (2026-11-13)

### Before you update

- Connecting a new browser now takes this version of SSH Key Manager and of its browser extension: the code you compare covers the keys of both. Browsers already connected keep working. Until your browser’s extension store offers the extension update, which can take a few days, a new browser can’t be connected.
- More ~/.ssh/config lines now need your yes in a system dialog: RemoteCommand, SendEnv beyond the language settings, every RemoteForward, GatewayPorts, forwards on all addresses, and a ControlPath outside your home folder.
- A system dialog now asks before an environment's secret values go into a terminal or a .env file (once per environment until the vault locks), before logins are read from a browser for import, before the Key converter writes an encrypted key without a passphrase, and for each secret shown or copied beyond ten in a row (one more is free every six minutes).
- Virtual .env files are served by this version only, on macOS and Linux: update the app on your other computers for them to appear there too.
- Files kept only while the vault is unlocked are written by this version only: update the app on your other computers for them to appear there too.
- Run in terminal now opens in the environment's folder (its part's folder, else where its .env file is, else the project's first folder) instead of your home folder.
- Older versions of the app read a shared variable as the text of its reference ({REF:…}), would write that into its .env files, and list shared values among the passwords: update the app on your other computers before sharing variables.
- Environments now belong to a project (or Personal) directly, as logins do, and groups are gone. On update, a project that held a group gets its environments; the group's name becomes their part (backend, frontend…), shown only when a project has more than one. Nothing moves in KeePass: KeePassXC shows a project/<name> tag. Older versions still see the groups.
- The app now has a light theme and follows your system’s appearance, so if your system is set to light, the app turns light after this update. To keep it dark, choose Dark in Settings → Appearance → Theme. The browser extension follows your browser’s theme too.
- While Nearby is open and the vault is unlocked, your paired computers and devices can see that you’re online and write to you. Others on the network see only a name that keeps changing. Both computers need this version to chat.
- Nearby: your own computers sync with each other only when both have this version or later, so update the app on all of them. Sending a password or an environment, adding a device, saving a received host that would get access to this computer, and a terminal with variables that run code now ask in a system dialog.
- Nearby: syncing with your own devices now brings the vault too — passwords, environments, shared values, files and folders — not only hosts. Both computers need this version, also to move the vault to a new one. A vault in a cloud folder (iCloud Drive, Dropbox…) keeps syncing through it instead.
- The sidebar starts with your projects and Personal; Keys, Hosts, Passwords and Environments move to Library, and Overview is gone: its summary is at the top of Audit. Projects sync to your other devices only once they have this version too.
- For hosts reached through a program that may run another ssh (a ProxyCommand of the host or of a jump host, a LocalCommand, a KnownHostsCommand, or a jump host the app can't read), the app now asks in a system dialog before it fills in a saved or typed password, 2FA code or passphrase.
- Links in the terminal now open with ⌘-click (Ctrl-click on Windows and Linux), as in other terminals, and pointing at one shows where it leads.
- Saving a tunnel that listens on all addresses, or a remote tunnel, now asks first in a system dialog that says who can connect and what they reach. Renaming a tunnel or turning auto-reconnect on or off doesn't ask again.
- On Windows, tunnels no longer offer to save a password or passphrase you type, as the terminal there doesn't: the app can't tell for sure that signing in worked.
- On Windows, Run in terminal in Environments now opens PowerShell instead of Command Prompt. To keep Command Prompt, choose it in Settings → Terminal → Default shell.

### Security

- Browser autofill is harder to trick: pages can't read the logins in its menu and banners, a page that shrinks or hides the menu gets no fill, and a program with a copy of the extension's keys is caught even if it changes them. Saving and updating from the browser count toward its ten changes a minute and no longer push out vault backups.
- Notes and environment names written as comments in exported files and virtual .env files stay on their own line, so no tool reads a hidden variable from them.
- Managed .env files are written only into the folder the app checked, even if a folder on the way is swapped while it writes; a virtual .env file gives out no values once the vault locks; and files kept only while the vault is unlocked are removed before an update installs and after a crash, however far the app got.
- Environments: before Run in terminal or a project's terminal starts a shell with variables that make it or the programs it starts run code, such as PATH, NODE_OPTIONS or GIT_SSH_COMMAND, a system dialog lists them with their values, and asks again when they change.
- When the app asks Git whether a .env file is ignored or committed, and when the Leak scanner lists the files of a repository, a project's own Git settings can no longer make Git run a program.
- Nearby and its chats connect only to computers on your local network. This computer hides after pairing with it is broken off three times before a code shows, and no longer gives away its device key on the port your own devices use.
- Nearby: a received server password is used only for a host here that leads to the same server, variables that make programs run code are left out of a received environment and named, and a received server key is never added for a host your system's known_hosts already trusts.
- Private files stay private in more cases: vault and environment exports and keys saved from Key converter are readable only by you even when they replace an older file or a link, a key whose passphrase you remove becomes readable only by you, and on macOS no private file takes read access that its folder grants to others.
- Tunnels save a typed password only after ssh itself reports the sign-in, keys go only to an ssh-agent running as you or the system, host names starting with a dash are refused, and on Windows ssh is never run from the folder the app was started in.
- Text pasted into the terminal arrives without control characters, so a paste never runs anything before you press Enter.
- The app installs an update only if its signature names the version it is offered as, so an older release can't be passed off as a newer one.
- Passwords: vault files are checked more strictly before they are opened, and KeePass 1 files are refused. A damaged vault.keys no longer hides the lock screen: the recovery key opens the vault and makes a new one, keeping the damaged file next to it.
- Passwords: master password checks run one at a time, and after three wrong ones in a row the next try has to wait a moment, a little longer after each further wrong one, so the password can't be guessed quickly through the app.
- Passwords: quitting the app clears a copied password the clipboard still holds, locking when idle counts the time the computer slept, and a new recovery key leaves the screen when the vault locks. Until you confirm it's saved, the app reminds you after unlocking and shows it again after a yes in a system dialog.

### New

- Environments can keep AI tools from reading a project folder’s .env files: with your yes for that folder, the app adds them where Cursor, Windsurf, Aider, Gemini CLI, Cline, Roo Code, Continue and JetBrains AI read their ignore files, and to Claude Code’s settings, and does so for files added there later.
- Projects show where each environment's .env files stand: on a project's page a line under the environment says the files are in sync or how many need attention, and leads to them. On All projects, a project's card counts its .env files that need attention among its problems. An environment's files also list the names .env.example has that it lacks.
- On macOS and Linux a .env file can be virtual: nothing is kept on disk, and while the app runs it hands the values to each tool that reads the file, or says the vault is locked. Checked with Node dotenv, python-dotenv, Docker Compose, direnv, Vite and Next.js.
- A .env file can be kept on disk only while the vault is unlocked: it’s written when you unlock and removed when the vault locks or the app quits, and after a crash too. Time Machine, Dropbox and iCloud Drive skip it. Remote environments can have such a file.
- A part of a project can have its own folder: the project page shows its folders as a tree, with each part's stages. Open terminal in a folder with several parts asks which environment to use, and New environment can take a .env file it finds in the chosen folder.
- A variable can be shared with other environments, of any project: they use one value, so changing it once, in the app or in any of their .env files, changes it in all of them and in their files, with Undo. “Use its own value here” takes one back.
- Audit: the leak scanner finds your vault's secrets where they shouldn't be — in the history of Claude Code, Codex and other AI tools, in your shell history, and in project files Git would commit. It reads files on this computer only, names the secret, file and line, never the value, and can redact the value in an AI session.
- Environments: write a local environment to .env files in its projects' folders with Add file…, and they stay in sync both ways: an edit in the file reaches the vault (with Undo), a change in the app rewrites the file, and if both changed you compare and choose. The Files view shows each file's state, files Git or a cloud folder would take, and .env files to take under management.
- Chats in Nearby: write to a paired computer or one of your devices, send a secret that is hidden and wiped after an hour, a day or a week, share variables, or offer a login, a host or a key. Messages go only while Nearby is open on both computers.
- Nearby: when both computers changed the same password or environment, the sync shows which fields differ and lets you keep either version; the other stays among the entry’s earlier versions. Variables that make programs load code need your yes in a system dialog.
- Projects: names from the hosts file can be part of a project. Its page shows their entries (name → address) and flags a name the file no longer has. A switch per entry, or one for all of them, goes through the usual review and administrator password, and Undo puts the backup back. Add names from Add or a Hosts file entry's menu; suggestions offer those of a project's hosts and domains.
- All projects is the new home: the app opens there and ⌘1 comes back. A card per project, Personal first, shows what it holds, its problems (audit findings, things missing on this computer) and quick actions: open a terminal in its folder, show it in Finder, Explorer or Files, connect to its host. Audit's numbers, an Unlock prompt and suggested projects sit on top.
- Projects: group the hosts, keys, logins, environments and folders of one piece of work, then connect, copy, run or open a terminal in its folder from its page. The app suggests projects from your environments, code folders, ~/.ssh/config and vault; nothing changes until you accept one.
- Terminal: open a shell on this computer next to your ssh sessions, with Local shell or from New session. Choose which one opens in Settings → Terminal: PowerShell, Command Prompt, Git Bash or a WSL distribution on Windows; zsh, bash, fish and others on macOS and Linux. Environments can run their variables in any of them too.

### Improved

- Environments are listed by project, then by part. New environment asks for a project, an optional part and the stage; when a project gets its second part, it asks what to call the first. An environment's menu has Move to project… and Rename part…, and Compare offers only the stages of the same part.
- The browser extension is now on Firefox Add-ons too: Settings → Browser autofill links to it next to the Chrome Web Store.
- When the other computer can’t take what you send in Nearby, or sends something this version can’t open, Nearby says which app needs updating instead of “the connection broke”.
- Nearby: more than five deletions a day from your other devices, all of them together, need your yes, whether they come in one sync or several, and the app keeps your SSH config and vault as they were before them for 30 days. A device a sync adds to your devices is named in the sync's summary and in My devices.
- Project page: each card shows five rows, problems first, with Show all for the rest, and the two columns no longer push each other down. Click a host, key, login or environment to open it in its section; ← takes you back. Add also makes a new host, key, login or environment right there. A project folder can be shown in Finder, Explorer or Files.

### Fixed

- Environments: Export… as a .env file puts a value with $, a backslash or a backtick in single quotes, so Docker Compose, Vite, Next.js and the shell read it exactly as stored instead of expanding it.
- Nearby can send an environment in Personal that has no part. The other computer needs this version too.

## 0.10.0 (2026-11-09)

### Before you update

- The browser extension now offers to update a saved password when you change it on a site's password-change form. And if signing in with a filled password fails, it asks “Couldn't sign in?” once, with Update and Remove from vault (to the recycle bin).

### New

- Import passwords now reads Chrome, Edge, Brave, Vivaldi and Firefox directly, after the system asks your permission, so no plain-text export file is needed. Where a browser can't be read (Safari, or passwords Chrome on Windows keeps to itself), the CSV guide is still there.
- The browser extension's popup lists the logins saved for the site you're on: change a login's username or password, or move it to the vault's recycle bin. The previous version stays in the entry's history. This needs the new version of both the app and the extension.

### Improved

- Importing passwords again finds logins whose password changed: they're marked “Different password”, and importing updates the entry, keeping the old password in its history, instead of adding a copy. Compare shows both passwords and, where the file says, when each changed. New logins are listed first.

### Fixed

- Nearby: after you sent something to another computer, or received something, the window didn't close on Done, and new pairings and sends were refused until the app restarted. It closes now. Cancel while connecting also stops at once, and nothing is sent after it.

## 0.9.0 (2026-11-09)

### New

- Settings → Background → Open at login: SSH Key Manager starts when you log in and waits in the menu bar or tray without its window, so browser autofill works right away. It's off until you turn it on.

### Improved

- When the browser extension can't find SSH Key Manager, its popup and connect page now offer to download the app, not only to turn on Browser autofill.

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
