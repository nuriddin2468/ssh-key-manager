# Privacy policy

This policy covers SSH Key Manager, the desktop app, and the SSH Key Manager browser
extension for Chrome, Edge and Firefox. Both are open source; this repository holds all
of their code.

**In short:** neither the app nor the extension sends your data to us or to anyone
else. There are no accounts, no servers of ours, no analytics and no ads. The
extension talks only to the app on your own computer. (The app's optional breach
check sends 5 characters of each password's hash to Have I Been Pwned; see below.)

## The browser extension

The extension fills logins from your SSH Key Manager vault and offers to save new ones.
It works only together with the app.

### What it reads on web pages

On http and https pages it looks for login forms:

- **Form fields.** To find a login form, it checks each input field's type, its `name`
  and `id`, its `autocomplete` hint and whether it's visible. It doesn't read the
  page's text, images or links.
- **The page's site.** When you move into a login field, it uses the site's address
  as your browser reports it, such as `https://example.com`. It uses only the scheme,
  name and port, never the path or the rest of the URL.
- **A login you type.** When you send a login form (with a click or the Enter key), it
  reads the username and password typed into that form, to offer "Save in SSH Key
  Manager?".

It doesn't record what you type anywhere else, the pages you visit, or your browsing
history.

### What it sends, and to whom

Only to the SSH Key Manager app on the same computer, through your browser's native
messaging. That is a local channel between the browser and a program on your
computer, not a network connection. Every message is encrypted with keys that only
this browser and the app hold, created when you connect them.

- **To the app:**
  - the site of the page you are on;
  - the login you picked in the menu;
  - a login you typed, so the app can tell whether it's new, changed or already
    saved, and save it if you choose **Save** or **Update**;
  - when you connect, the browser's name (for example "Google Chrome"), so you can
    tell browsers apart in the app's Settings.
- **Back from the app:**
  - the titles and usernames of logins saved for that site;
  - the username and password of the one login you pick, which the extension fills
    into the page.

Nothing is sent over the internet, and nothing is sent to us or to any third party.

### What it stores

- **Pairing:** in the extension's own database in your browser: a random id for this
  browser, two encryption keys (stored so that they can't be read back out) and the
  date you connected. Web pages can't reach it.
- **A login waiting for your answer:** after you send a login form, the username and
  password wait in the browser's session storage, which is kept in memory and never
  written to disk. They're offered for three minutes at most. They're removed when you
  answer the save banner or close the tab, at the next page load after three minutes,
  and when the browser quits.
- **A username from a two-step sign-in:** when a site asks for the username on one
  page and the password on the next, the username waits in the same session storage
  for five minutes, for that tab only, to go with the password.
- **Recent site lookups:** the titles and usernames of a site's logins are reused from
  memory for up to ten seconds, so the menu opens quickly. They're never written to
  disk.

Passwords are never stored by the extension. They stay in your vault, which the app
keeps encrypted.

### What it doesn't do

- No analytics, telemetry, crash reporting or ads.
- No remote code: everything it runs ships inside the extension.
- No network requests of its own.
- No change to your browser's settings, except its own password and form suggestions
  when you turn them off in the extension's popup. The browser asks you first, and
  turning them on again restores your own choice.
- No selling, sharing or transfer of your data, and no use of it for anything but
  filling and saving your logins.

The use of information received through the extension adheres to the
[Chrome Web Store User Data Policy](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq),
including the Limited Use requirements.

### Permissions it asks for

- **Native messaging:** to talk to the SSH Key Manager app on your computer.
- **Storage:** to keep a login you just typed in memory until you answer the save
  banner.
- **Access to http and https pages:** to find login forms, show the menu of your
  logins and fill the one you pick, on whichever site you sign in to.

## The app

The app keeps your data on your computer:

- Your SSH files stay where they are.
- The password vault is an encrypted KeePass file, in the app's data folder or a
  folder you choose.
- Tunnels you save are kept in `tunnels.json` in the app's data folder: their hosts,
  ports, addresses and names, never a password.

It goes online only:

- to check GitHub for a new version of itself, which you can turn off in
  **Settings → Updates**;
- when you ask it to reach a server: checking a host key, testing a connection or
  opening a terminal session;
- when you rotate a key: it signs in to the hosts you chose to add the new key, check
  that it works and, if you ask, remove the old one;
- for a DNS lookup when you ask where a name leads;
- when a connection failed and you click **Check port**: it opens one connection to
  the server's port and closes it at once, without sending anything;
- when you run a network check on the Tools page: SSH ping, the port check and the TLS
  check connect to the host you name, and the DNS lookup asks your computer's DNS
  servers about the name you type. Checking a certificate may make your system ask its
  issuer whether it was revoked. Nothing about the checks is stored;
- for each tunnel you turn on, for as long as it is on: it stays connected to that
  server, and the port it forwards carries what you and your apps send through it;
- if you turn on the audit's breach check (it is off until you do), to look up your
  saved passwords in [Have I Been Pwned](https://haveibeenpwned.com/Passwords). For
  each password it sends only the first 5 characters of the password's SHA-1 hash to
  `api.pwnedpasswords.com`, gets back the hashes known to start with them, and compares
  the rest on your computer. Your passwords, and their full hashes, never leave it. The
  service sees your IP address and those 5 characters. Have I Been Pwned's own
  [privacy policy](https://haveibeenpwned.com/Privacy) applies to it. The app keeps the
  results in memory until the vault locks, and stores only whether the check is on, in
  `breaches.json` in its data folder.

When a connection fails, the app explains why from what `ssh` printed. It keeps
that explanation only in memory, next to the test's result, and never stores or
sends it.

While you rotate a key, the app remembers on this computer which hosts you chose and
how far each got, so you can finish later: the names of the keys and hosts, their
fingerprints and the old public key. It forgets them once the rotation is done.

It talks to the local network only for **Nearby**, and only when you ask:

- While the Nearby page is open, it listens for other computers running the app on
  the same network (mDNS).
- When you click **Show for 10 minutes**, it announces your computer's name on that
  network for ten minutes and accepts connections from other copies of the app.
- When you pair two computers, they talk directly to each other over an encrypted
  connection. Nothing goes through a server, ours or anyone else's.
- When you send a password, a host, a group of your hosts file or your public key, it
  goes only to the computer you pick, and only after its user accepts it. A hosts file
  group goes with its addresses and names, without comments; a public key goes
  without its private key.
- When you add one of your own computers, the one that has your vault gives it the
  vault and its recovery key, after you compare the codes and confirm with Touch ID,
  Windows Hello or your master password.
- While your vault is unlocked and you have another computer of your own, the app
  is reachable by your computers on this network, under a name that keeps changing
  and tells others nothing. You can turn this off in **Nearby → My devices**. When
  you sync, your hosts (without your keys or anything else of the computer's own),
  the server keys you trust for them and the list of your computers go to your other
  computer, and its come back.

Each computer you pair with is recorded in your vault with the name it gave and the
date, and so is each of your own computers. You can remove them on the Nearby page.
The key that identifies your computer to paired ones is kept in your system's
credential store. A public key you receive is saved in `~/.ssh`, and its fingerprint
in `nearby.json` in the app's data folder, so the app knows the key is someone
else's. For each of your other computers, the app keeps what it needs to tell what
changed since the last sync: hashes, never the hosts themselves, in the same folder.

If you say yes to **Find hosts in your shell history?** on the Hosts page, the app reads
your zsh, bash, fish and PowerShell history on this computer when you open Hosts, to
suggest servers you connect to. Only the servers (user, address, port and a few
connection options) are taken from it; your commands, and passwords typed into them,
are never shown, kept or sent anywhere. The app keeps your answer and the suggestions
you dismissed, as hashes rather than the servers, in `shell-history.json` in its data
folder. You can turn this off in **Settings → Shell history**.

For each browser you connect, the app records in your vault the browser's name, your
computer's name and the date you connected. You can disconnect a browser in
**Settings → Browser autofill**. [SECURITY.md](SECURITY.md) describes in detail how the
app and the extension protect your data.

## Removing your data

- **Disconnect** in the extension's popup or in the app's Settings removes the
  pairing.
- Removing the extension deletes everything it stored. The app lists that browser
  until you disconnect it there too.
- Logins you saved stay in your vault until you delete them in the app.

## Changes

Changes to this policy are published in this file, and its history shows every
earlier version.

## Contact

Questions about privacy: [open an issue](https://github.com/nuriddin2468/ssh-key-manager/issues/new).
Security problems: report them privately through
[GitHub security advisories](https://github.com/nuriddin2468/ssh-key-manager/security/advisories/new).

Last updated: 6 November 2026.
