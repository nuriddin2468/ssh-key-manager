# Security

SSH Key Manager handles private keys, so its design keeps the attack surface small.

## Security model

- **Private keys never reach the UI.** The webview only receives metadata and public keys.
  Decrypted keys exist only inside the Rust process, are zeroized when dropped, and are
  passed straight to `ssh-agent`.
- **Key passphrases are not stored**, unless you save them in the password vault. They
  travel from the form to the Rust process for one operation and are held in
  `secrecy::SecretString`. They are never logged.
- **The password vault** (optional) is a standard KeePass file, `vault.kdbx`, in the
  app's data folder or a folder you choose.
  - Format: KDBX 4.1 with Argon2id key derivation and ChaCha20 encryption; password
    fields are additionally protected inside the file, as KeePass does.
  - Its password is a random 256-bit recovery key shown once when the vault is made.
    The master password does not encrypt the database directly: it opens a copy of
    the recovery key kept in `vault.keys`, encrypted with XChaCha20-Poly1305 under a
    key derived with Argon2id (128 MiB, 3 passes). There is no way back without the
    master password or the recovery key.
  - While unlocked, the decrypted database is held only by the Rust process and is
    dropped when the vault locks: on request, after inactivity, after sleep, and
    optionally when the window is minimised. Lists and details sent to the interface
    carry no passwords or 2FA secrets; a password reaches the interface only when you
    choose to reveal it.
  - Copying a password or 2FA code goes from Rust straight to the clipboard, marked so
    clipboard history (and Windows' cloud clipboard) skip it, and is cleared after
    30 seconds by default if nothing else was copied.
  - Changes are written atomically and the previous file is backed up (20 copies,
    still encrypted). A write over a change made elsewhere is refused and saved as a
    separate copy.
  - A saved key passphrase goes from the vault straight to `ssh-agent` or `ssh` inside
    the Rust process; the interface never receives it. To say "saved, but the vault is
    locked", the interface remembers the fingerprints (public) of keys with saved
    passphrases in its local storage.
  - Touch ID / Windows Hello adds one slot per computer, opened by a random key in that
    computer's Keychain or Credential Manager, used only after the system prompt
    succeeds. A new recovery key removes every such slot.
  - Exports: the KeePass copy stays encrypted (it opens with the recovery key). The CSV
    export is plain text: it needs the master password, is written with mode 0600 and
    never into `~/.ssh` or over the vault's own files. Imported CSV files can be moved
    to the Trash right after import.
- **Answering `ssh` prompts.** To log in with a password or one-time code, the app acts
  as `ssh`'s askpass program.
  - The secret goes over a local socket only this user can reach (a private 0700
    directory; on Windows a named pipe that refuses remote clients), and only to an
    `ssh` run holding that run's random token.
  - Host keys are never accepted this way, a rejected password is not retried, and a
    prompt that names another account, such as a `ProxyJump` host's, is refused.
  - The in-app terminal uses the same channel with an interactive session. A saved
    secret is given once and only to prompts for the host's own account; everything else
    (a secret not saved, a rejected one, a jump host's password) is asked of you in a
    dialog that names the host. A new host key is trusted only when you choose "Trust"
    after seeing its fingerprint, which answers `ssh`'s own question; a changed host key
    stops the connection. An answer you choose to save goes into the vault only after
    the session has signed in. Terminal output and answers are never logged.
- **Browser autofill** (optional, off by default) lets the SSH Key Manager extension for
  Chrome, Edge and Firefox fill and save logins from the vault. See
  [Browser autofill](#browser-autofill) below.
- **Minimal network access.** The app sends none of your data anywhere. Its only
  requests are:
  - the update check, which downloads `latest.json` from this repository's GitHub
    Releases at startup and every six hours (can be turned off in Settings);
  - `ssh-keyscan` and `ssh` when you explicitly check a host key, test a connection or
    open a terminal session;
  - a DNS lookup when you ask where a name leads.
- **Signed updates.** An update is installed only if its signature matches the public key
  built into the app (`plugins.updater.pubkey` in `src-tauri/tauri.conf.json`).
- **Standard files only.** The app edits the OpenSSH files in place.
  - Writes are atomic (temp file plus rename), keep the file's permissions, and follow
    symlinks.
  - `config` and `known_hosts` are backed up before every write.
  - Private keys are deliberately not backed up, because a backup taken before adding a
    passphrase would leave an unencrypted copy behind.
- **Deletions are recoverable.** Removed keys go to the system Trash.
- **Administrator rights only to save the hosts file, and only when you save.** The app
  itself never runs with administrator rights.
  - Changes to the hosts file are collected first and shown as a diff. Saving writes the
    approved text to a private temporary file and asks the system to run one fixed
    script with administrator rights: `osascript … with administrator privileges` on
    macOS, `pkexec` on Linux, a UAC prompt on Windows.
  - The script copies the text somewhere only an administrator can change, checks its
    SHA-256 against the text you approved and only then puts it in place, so another
    program cannot swap the temporary file in between. Nothing you type goes into the
    script: it receives only two paths and the checksum, as arguments on macOS and
    Linux (`quoted form of` on macOS) and as quoted strings on Windows.
  - A hosts file that is a symbolic link (managed by `NixOS`, a container runtime and
    the like) or not UTF-8 is never written.
  - The hosts file is backed up before every change, and any backup can be restored.
  - On Windows the elevated step runs Windows PowerShell, so the UAC prompt names
    Microsoft as the publisher.
- **Locked-down webview**
  - Strict Content Security Policy and a frozen JavaScript prototype.
  - Only the Tauri capabilities the UI needs are granted (`src-tauri/capabilities`).
  - Permission fixes are limited to paths inside `~/.ssh`.

## Browser autofill

```text
extension ──native messaging──▶ host (the app's executable) ──socket / pipe──▶ app
```

Turning on **Settings → Browser autofill** writes a native messaging manifest for each
installed browser. The manifest names the app's executable and only this extension
(by its Chrome ids and its Firefox add-on id). Turning it off removes the manifests and
stops the listener. Nothing listens while it is off.

**What the extension can get.**

- The app answers four questions, each about one page:
  - which logins belong to it: titles and usernames only;
  - the username and password of the one login the user picked there;
  - whether a login typed there is new, changed or already saved;
  - saving or updating that login.
- Every lookup checks the login's address against the page's origin:
  - same registrable domain, compared exactly after IDNA normalisation, from the
    Public Suffix List with its private section (`github.io` users don't share
    logins);
  - a login saved for `https` is never offered on `http`;
  - ports must match;
  - IP addresses and single-label names must match exactly.
- Look-alike and punycode domains get nothing. A login picked by its id is checked
  again, so a browser cannot ask for another site's password by naming its id.
- Nothing is filled until the user picks a login in the menu with a real click or key
  press. Pages get no automatic fill on load, so an invisible form, or a script
  injected into a site, can't harvest passwords.
- Nothing else of the vault is reachable: not other entries, 2FA secrets, notes, key
  passphrases or the vault's settings.

**Which page is asking.** The content script runs in each http(s) frame. The background
script names the page by the origin the browser reports for the sending frame, never
by what the page or the content script says. A frame from another site gets that
site's logins only. Opaque origins (`null`, `data:`, sandboxed frames) get nothing.
The menu and the save banner live in closed shadow roots, so page scripts can't read
the logins listed. A password the user typed waits for the banner in the background's
`storage.session` (memory only) for at most three minutes, and never goes back to a
page.

**Pairing.**

- A browser must be paired before it gets anything but the vault's lock state.
- The extension makes a P-256 key pair and a random client id. Both the extension and
  the app show a six-digit code computed from them, and the user connects in the app
  after checking that the codes match.
- Pairing needs an unlocked vault. Only one pairing waits at a time, for at most two
  minutes.
- Both sides derive two AES-256-GCM keys (requests, responses) with HKDF-SHA-256 from
  the ECDH secret. The app's key pair is used once and dropped.
- The app keeps a pairing in the vault's encrypted custom data
  (`sshkm.browser.<id>`), so it can only be checked while the vault is unlocked and it
  goes away with the vault.
- The extension keeps its keys in its IndexedDB as non-extractable `CryptoKey`s.
  Content scripts can't reach that database.
- **Settings → Browser autofill** lists paired browsers and can disconnect each one.
  The extension's own Disconnect also removes its pairing from the vault when the vault
  is unlocked; when it's locked, only the extension forgets its keys.

**Messages.**

- Every request after pairing is sealed with the request key, a random 96-bit nonce
  and the client id as associated data.
- A request is refused if:
  - it opens with no paired browser's key;
  - it is more than two minutes old or new;
  - its nonce was seen in the last five minutes.
- Each response is sealed with the response key and bound to the request's nonce.
- The native host and the browser see only ciphertext. The one secret that leaves the
  app is the password of the login being filled, sealed for that browser and opened by
  the extension's background script, which passes it to the content script of the
  frame that asked.
- Logs never contain messages.
- Listing logins and checking a typed login don't count as activity, so they don't
  keep the vault from locking itself; filling and saving do.

**The local channel.**

- The app listens on a Unix socket in a fresh private (0700) directory, or on Windows
  on a named pipe with a random name that rejects remote clients.
- It writes where to an endpoint file in its local data folder, which only this user
  can write. Other users therefore can't point the host somewhere else, or squat a
  well-known name.
- On macOS and Linux the host also checks that the socket's directory belongs to the
  user and is private.

**Outside this model.**

- Malware running as the same user can read the browser profile, including the
  extension's pairing keys, or the app's memory. It can also impersonate the user to
  the app. Browser autofill does not protect against it, and neither does any password
  manager's browser integration.
- A compromised browser renderer for a site can ask for that site's logins without a
  click, but no other site's.
- A site you log in to sees the password you fill there, as it would if you typed it.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub security advisories](https://github.com/nuriddin2468/ssh-key-manager/security/advisories/new).
You will get an answer within a few days.
