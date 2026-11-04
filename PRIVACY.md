# Privacy policy

This policy covers SSH Key Manager, the desktop app, and the SSH Key Manager browser
extension for Chrome, Edge and Firefox. Both are open source; this repository holds all
of their code.

**In short:** neither the app nor the extension sends your data to us or to anyone
else. There are no accounts, no servers of ours, no analytics and no ads. The
extension talks only to the app on your own computer.

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
- **Recent site lookups:** the titles and usernames of a site's logins are reused from
  memory for up to ten seconds, so the menu opens quickly. They're never written to
  disk.

Passwords are never stored by the extension. They stay in your vault, which the app
keeps encrypted.

### What it doesn't do

- No analytics, telemetry, crash reporting or ads.
- No remote code: everything it runs ships inside the extension.
- No network requests of its own.
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

It goes online only:

- to check GitHub for a new version of itself, which you can turn off in
  **Settings → Updates**;
- when you ask it to reach a server: checking a host key, testing a connection or
  opening a terminal session;
- for a DNS lookup when you ask where a name leads.

It talks to the local network only for **Nearby**, and only when you ask:

- While the Nearby page is open, it listens for other computers running the app on
  the same network (mDNS).
- When you click **Show for 10 minutes**, it announces your computer's name on that
  network for ten minutes and accepts connections from other copies of the app.
- When you pair two computers, they talk directly to each other over an encrypted
  connection. Nothing goes through a server, ours or anyone else's.

Each computer you pair with is recorded in your vault with the name it gave and the
date. You can remove it on the Nearby page. The key that identifies your computer to
paired ones is kept in your system's credential store.

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

Last updated: 3 November 2026.
