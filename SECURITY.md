# Security

SSH Key Manager handles private keys, so its design keeps the attack surface small.

## Security model

- **Private keys never reach the UI.** The webview only receives metadata and public keys.
  Decrypted keys exist only inside the Rust process, are zeroized when dropped, and are
  passed straight to `ssh-agent`.
- **Key passphrases are not stored**, unless you save them in the password vault. They
  travel from the form to the Rust process for one operation and are held in
  `secrecy::SecretString`. They are never logged. Adding a passphrase to a key that has
  none, or removing one, is confirmed in a system dialog.
- **Imported keys hold nothing but the key.** A file with anything after the key, or one
  that isn't a well-formed key, is refused; the app writes the key and its public line
  out again rather than copying the file. Names OpenSSH reserves (`authorized_keys`,
  `rc`, `config`, …) are refused in any letter case. Keys that ask for more than 1024
  bcrypt rounds are refused before decrypting.
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
    optionally when the window is minimised. Showing an entry or its 2FA code doesn't
    count as activity, so it doesn't keep the vault open. Lists and details sent to the
    interface carry no passwords or 2FA secrets; a password reaches the interface only
    when you choose to reveal it.
  - Copying a password, a 2FA code or the recovery key goes from Rust straight to the
    clipboard, marked so clipboard history (and Windows' cloud clipboard) skip it, and
    is cleared after 30 seconds by default if nothing else was copied. Locking the vault
    clears it at once.
  - Changes are written atomically and the previous file is backed up (20 copies,
    still encrypted). A change to nothing but a paired browser's keys takes no backup,
    so the daily key change doesn't push out the backups taken before real changes. A
    write over a change made elsewhere is refused and saved as a separate copy; a write
    over key slots changed elsewhere is refused.
  - Key derivation settings read from `vault.keys` or a `.kdbx` header are capped
    before use, so a tampered file can't make unlocking run for hours.
  - A new recovery key re-encrypts the app's backups and conflict copies, so the old key
    stops opening them. Exports, cloud versions and Time Machine copies made before still
    open with the old key. Changing the master password doesn't change the recovery
    key: an old copy of `vault.keys` still opens with the old master password, so make a
    new recovery key if the password may have leaked.
  - Turning off or loosening auto-lock, lock on sleep, screen lock or minimise, or
    clipboard clearing; turning off device unlock; and moving the vault or switching to
    another file are each confirmed in a system dialog, which the page can't answer.
  - A saved key passphrase goes from the vault straight to `ssh-agent` or `ssh` inside
    the Rust process; the interface never receives it. To say "saved, but the vault is
    locked", the interface remembers the fingerprints (public) of keys with saved
    passphrases in its local storage.
  - Touch ID / Windows Hello adds one slot per computer to `vault.keys`; a new recovery
    key removes every such slot.
    - **Windows**: the slot's key is derived (HKDF-SHA256) from a Windows Hello signature
      of a fixed per-vault challenge. The signing key is an RSA key Windows Hello keeps
      (in the TPM when there is one) and uses only after your PIN, face or fingerprint.
      Nothing that opens the slot is stored on disk or in the Credential Manager, so
      another program running as you can't unlock the vault silently: it would have to
      make Windows show the Hello prompt and get you to confirm it. Adding a fingerprint
      or face keeps the key; resetting Windows Hello (removing the PIN) destroys it, and
      device unlock must be turned on again. Slots made by earlier versions (a random key
      in the Credential Manager) are upgraded the first time they are used, and the old
      Credential Manager item is deleted.
    - **macOS**: the slot's key is random and kept in the login keychain. Only this app,
      as identified by its code signature, reads the item without macOS asking for the
      login keychain password. Touch ID is a confirmation the app asks for before
      reading it, not a lock on the item itself, so device unlock is as strong as your
      macOS login password. Device unlock turns itself off when fingerprints are added or
      removed. Binding the key to Touch ID itself needs the data-protection keychain,
      which requires a provisioning profile the app doesn't have yet.
    - **Linux**: not offered.
  - Exports: the file is chosen in a system dialog the app opens itself, and both
    exports need the master password. The KeePass copy stays encrypted (it opens with
    the recovery key). The CSV export is plain text: it is readable only by you (mode
    0600; on Windows by you, SYSTEM and Administrators), never written into `~/.ssh` or over the
    vault's own files (compared by file identity, so links and firmlinks don't get
    around it), and cells that a spreadsheet would run as a formula are defused, except
    passwords. Files to import are also picked in a system dialog. Imported CSV files can
    be moved to the Trash right after import.
- **Answering `ssh` prompts.** To log in with a password or one-time code, the app acts
  as `ssh`'s askpass program.
  - The secret goes over a local socket only this user can reach (a private 0700
    directory; on Windows a named pipe that refuses remote clients), and only to an
    `ssh` run holding that run's random token.
  - Host keys are never accepted this way, a rejected password is not retried, and a
    prompt that names another account, such as a `ProxyJump` host's, is refused.
  - A prompt the server writes (keyboard-interactive, which OpenSSH 8.5 and later marks
    with the account) can only ever get the host's password or one-time code: never a
    key passphrase, and never an answer to a host-key or yes/no question, whatever its
    text says. When only key passphrases are saved, a test or key install turns
    keyboard-interactive off, so the server can't ask anything.
  - Before OpenSSH 8.5 (Windows 10's built-in 8.1, Debian 11's 8.4) `ssh`'s own prompts
    and a server's look alike, so saved secrets are not filled in through a
    `ProxyJump` or `ProxyCommand`, and saved key passphrases are not filled in while
    keyboard-interactive is on.
  - The in-app terminal uses the same channel with an interactive session. A saved
    secret is given once and only to prompts for the host's own account; everything else
    (a secret not saved, a rejected one, a jump host's password) is asked of you in a
    dialog that names the account the prompt is for. Text that comes from `ssh` or a
    server is shown quoted and is never presented as the app's own question.
  - A new host key is trusted only when you choose "Trust" after seeing its
    fingerprint, which answers `ssh`'s own question. A changed host key stops the
    connection, and so does a new key of another type for a host whose key is already
    known. Anything else `ssh` adds to the question is shown as a warning.
  - An answer you choose to save goes into the vault only after the session has signed
    in. On Windows, where the app can't tell when that happens, the terminal never saves
    answers. Terminal output and answers are never logged.
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
  - The update check runs in Rust. The page can ask for a check or an install, but can't
    change the server, proxy or headers.
  - Release builds use GitHub Actions pinned to commit SHAs. The signing key is only in
    the environment of the steps that bundle and sign, after everything has been
    compiled without it.
- **Standard files only.** The app edits the OpenSSH files in place.
  - Writes are atomic (temp file plus rename), keep the file's permissions, and follow
    symlinks.
  - `config` and `known_hosts` are backed up before every write. An edit is tied to the
    version of the file it was made on and refused if the file changed meanwhile.
  - A change that adds or alters a directive that runs a program, loads a library,
    includes another file, or gives the server access (`ProxyCommand`, `LocalCommand`,
    `KnownHostsCommand`, `Match exec`, `PKCS11Provider`, `SecurityKeyProvider`,
    `Include`, `IdentityAgent`, `ForwardAgent`, `ForwardX11`, …), or a host name with
    shell syntax, is confirmed in a system dialog that shows it. A script in the page
    can't answer that dialog.
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
    length and SHA-256 against the text you approved and only then puts it in place, so
    another program cannot swap the temporary file in between. It reads the temporary
    file only if it is a regular file, and at most one byte more than the approved text.
  - Right before replacing the hosts file it checks that the file is still the one your
    changes were made on. If another program changed it while the password prompt was
    open, nothing is written and the app shows the changes again over the new file.
  - Nothing you type goes into the script: it receives only paths, the length and
    checksums, as arguments on macOS and Linux (`quoted form of` on macOS) and as
    Base64 text decoded inside the script on Windows.
  - A hosts file that is a symbolic link (managed by `NixOS`, a container runtime and
    the like) or not UTF-8 is never written.
  - The hosts file is backed up before every change, and any backup can be restored.
  - On Windows the elevated step runs Windows PowerShell, so the UAC prompt names
    Microsoft as the publisher. PowerShell, `pkexec` and the other system tools the app
    starts are run by their full path in the system folders, never looked up on `PATH`.
- **Locked-down webview**
  - Strict Content Security Policy: only the app's own scripts run, and no `eval`.
  - Tauri's frozen JavaScript prototype (`freezePrototype`) is off: the terminal
    (xterm.js) assigns its own `toString` while loading, which a frozen prototype
    forbids, and the whole page then failed to start in 0.3.0.
  - Only the Tauri capabilities the UI needs are granted (`src-tauri/capabilities`).
  - The window only shows the app's own page: navigating elsewhere is refused and new
    windows can't open. Links open in your browser, and only `http` and `https` links.
  - Permission fixes apply only what the app's own audit found inside `~/.ssh`, and only
    ever remove permissions.

## Browser autofill

```text
extension ──native messaging──▶ host (the app's executable) ──socket / pipe──▶ app
```

Turning on **Settings → Browser autofill** writes a native messaging manifest for each
installed browser. The manifest names the app's executable and only this extension
(by its Chrome ids and its Firefox add-on id). Turning it off removes the manifests and
stops the listener. Nothing listens while it is off. A manifest never points into a
temporary folder, where another user could later put a program of their own: an
AppImage is registered by the AppImage file itself, and a copy running from a temporary
folder isn't registered at all.

**What the extension can get.**

- The app answers four questions, each about one page:
  - which logins belong to it: titles and usernames only;
  - the username and password of the one login the user picked there;
  - whether a login typed there is new, changed or already saved;
  - saving or updating that login.
- One more question needs no pairing and carries nothing from the vault: whether two
  origins are the same site, by the same rules as below. The extension asks it to tell
  how much a save offer may show on the page.
- Every lookup checks the login's address against the page's origin:
  - same registrable domain, compared exactly after IDNA normalisation, from the
    Public Suffix List with its private section (`github.io` users don't share
    logins);
  - a login saved for `https` is never offered on `http`;
  - ports must match;
  - IP addresses and single-label names must match exactly.
- Look-alike and punycode domains get nothing. A login picked by its id is checked
  again, so a browser cannot ask for another site's password by naming its id.
- Before a login first fills a page, the app asks the user: with Touch ID or Windows
  Hello where the computer has it, otherwise in a native dialog. The question names
  the browser, the login and the page, and its text comes from the vault and the app;
  the page only picked the login. The system draws it outside the browser, so neither
  a page nor a program holding the extension's keys can answer it. (A program running
  as the user can click a plain dialog on Windows and under X11; macOS asks the user
  before it lets one, and Wayland doesn't let one.)
  - The answer covers that login on that page from that browser for the rest of the
    user's session: until the vault is locked by hand, the screen locks, the computer
    sleeps or the vault changes, and for at most 12 hours. Locking after inactivity or
    on minimise doesn't end it.
  - One question is open at a time. A browser waits at most a minute for the answer;
    a yes given later lets the next pick fill at once.
  - A browser may ask at most five times a minute, so a program holding its keys can't
    wear the user down with questions.
- Nothing is filled until the user picks a login in the menu with a real click or key
  press. Pages get no automatic fill on load.
  - The menu opens and moves only on events the browser marks as the user's own; events
    a page script makes up are ignored.
  - A pick counts only once the menu has been on screen for half a second, uncovered at
    the point clicked, and only while the page hasn't restyled, moved or hidden it, so
    a page can't slip it under a click or key press meant for something else. A layer
    the page opens later over the menu sends the menu back to the front, and the wait
    starts again.
  - In Chrome and Edge the browser also confirms that nothing covers the menu, not even
    a layer that lets clicks through. Firefox has no way to tell that, so there a
    script on the site could still lay a see-through decoy over the menu; the app's
    question then still names the login before anything is filled.
  - Fields that are nearly transparent, smaller than 8 pixels, or outside the window get
    no menu.
- Nothing else of the vault is reachable: not other entries, 2FA secrets, notes, key
  passphrases or the vault's settings.

**Which page is asking.** The content script runs in each http(s) frame. The background
script names the page by the origin the browser reports for the sending frame, never
by what the page or the content script says. A frame from another site gets that
site's logins only. Opaque origins (`null`, `data:`, sandboxed frames) get nothing:
the background falls back to the frame's address only when the browser reports no
origin at all. The menu and the save banner live in closed shadow roots on a plain
`div`, so page scripts can't read the logins listed. A password the user typed waits
for the banner in the background's `storage.session` (memory only). It is offered for
at most three minutes, dropped at the next page load after that or when the tab
closes, and never goes back to a page. On a page of another site, for example after a
sign-in that sends you on, the banner names only the site where it was typed, not the
username or the saved login's title. A tab can send
typed logins to check at most about once a second.

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
  Content scripts can't reach that database. Non-extractable only keeps scripts from
  reading them: they are in the browser profile on disk.
- The keys change once a day. The extension makes a new key pair and runs ECDH with a
  new key pair of the app over the sealed channel, as in pairing. The app keeps the new
  keys alongside the current ones until the extension first uses them, then retires the
  old ones; it keeps the last 30 retired keys. A request sealed with retired keys and
  sent after they were retired means someone else holds a copy of them: the app forgets
  the pairing at once and tells the user. One sent before (a late request of the
  extension itself) is refused, nothing more. While the keys change, the extension
  holds back its other requests (a Web Lock shared by its background and its pages),
  so none goes out with the old keys afterwards. Key changes take no backup of the
  vault.
- **Settings → Browser autofill** lists paired browsers and can disconnect each one.
  The extension's own Disconnect also removes its pairing from the vault when the vault
  is unlocked; when it's locked, only the extension forgets its keys.

**Messages.**

- Every request after pairing is sealed with the request key, a random 96-bit nonce
  and the client id as associated data.
- A request is refused if:
  - it opens with no paired browser's key;
  - it is more than two minutes old or new;
  - its nonce was seen in the last five minutes. When too many nonces are held, the
    oldest makes room, and every request sent no later than it stays refused for as
    long as it would have been remembered.
- Each response is sealed with the response key and bound to the request's nonce.
- The native host and the browser see only ciphertext. The one secret that leaves the
  app is the password of the login being filled, sealed for that browser and opened by
  the extension's background script, which passes it to the content script of the
  frame that asked.
- Logs never contain messages.
- Listing logins and checking a typed login don't count as activity, so they don't
  keep the vault from locking itself; filling and saving do.
- A browser may check at most ten typed logins a minute. The answer tells whether a
  password is the saved one, so without the limit a program holding the extension's
  keys could guess saved passwords through it.

**The local channel.**

- The app listens on a Unix socket in a fresh private (0700) directory, or on Windows
  on a named pipe with a random name that rejects remote clients.
- It writes where to an endpoint file in its local data folder, which only this user
  can write. Other users therefore can't point the host somewhere else, or squat a
  well-known name.
- On macOS and Linux the host also checks that the socket's directory belongs to the
  user and is private. On Windows it checks, before it sends anything, that the pipe
  is owned and served by this user, so another user can't take over a pipe name left
  behind by a crash.
- The app checks the `ssh-agent` pipe on Windows the same way before it sends a key:
  it must be served by this user or by the system, and it is opened with
  identification-only impersonation.

**Outside this model.**

- Malware running as the same user can read the browser profile, including the
  extension's pairing keys. With them, while the vault is open, it learns the titles
  and usernames of the logins of any site it names, and gets the passwords the user
  allowed that browser to fill in this session; any other password needs the user's
  yes. Once the extension changed its keys, using the copy revokes the pairing. Where
  it can read the app's memory (on Windows a program of the same user can; macOS
  protects the signed app, and many Linux distributions allow it only to the app's
  parent) or click the app's dialog, it gets more. No password manager's browser integration
  protects fully against malware running as the user.
- A compromised browser renderer for a site can ask for that site's logins without a
  click, but no other site's, and gets a password only after the user allowed it in
  the app.
- A site you log in to sees the password you fill there, as it would if you typed it.

## Nearby

Two copies of the app on the same local network pair, and later talk, over a direct
TCP connection. The cryptography is in `sshkm_core::p2p`, the networking in
`src-tauri/src/nearby/`.

- **Visible on request.** The app announces itself (mDNS, `_sshkm._tcp`) and accepts
  connections only for ten minutes after the user clicks **Show for 10 minutes**, under
  a random instance name with the device name in the TXT record; the device key is
  never announced. It browses for others only while the Nearby page is open.
- **Device key.** Each computer has a Curve25519 key pair, made on first use and kept
  in the system's credential store. Paired computers know each other by the public key.
- **Encrypted session.** Every connection starts with a `Noise_XX_25519_ChaChaPoly_SHA256`
  handshake (prologue `sshkm-p2p/1`): each side proves it holds its device key, and
  everything after is encrypted and authenticated. Messages are JSON of at most 1 MiB.
- **Pairing code.** Two computers that don't know each other both show a six-digit
  code, and each user says whether the other screen shows the same one. The code comes
  from the handshake hash and a nonce from each side; the side that connected commits
  to its nonce (SHA-256) before it sees the other's, and the other sends its own before
  it sees the first. Someone in the middle runs a separate handshake with each side, so
  the two codes match only by chance, one time in a million: they can't try keys until
  the codes agree, as they could if the code came from the handshake hash alone.
- **Both must agree.** A computer becomes a contact only when both users said the codes
  match. A "no", a cancel or a dropped connection on either side saves nothing.
  Contacts are kept in the vault (`sshkm.contact.<device key>` in its custom data), so
  pairing needs it unlocked.
- **One at a time.** While a pairing goes on, other connections are closed at once.
  The users have three minutes to compare the codes.
- **Sending.** After pairing, or straight away between contacts, the side that
  connected may send one item: a vault entry or a host. The UI only names it; the
  backend reads the secret from the vault. First goes a summary with nothing secret
  in it (title and username, or alias and address); the item itself goes only after
  the other user accepts. The receiver checks that the item matches the summary and
  that every name in a host is made of name characters only, refuses a host block
  that would add a directive running a program, and gives a taken alias a number.
  It never adds a server key for a host it already has keys for, since `ssh` would
  then accept the sender's key next to its own; it keeps its own and warns instead.
  A 2FA secret goes only if the sender ticks it; a key's passphrase never goes.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub security advisories](https://github.com/nuriddin2468/ssh-key-manager/security/advisories/new).
You will get an answer within a few days.
