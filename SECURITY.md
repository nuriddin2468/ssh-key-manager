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
    optionally when the window is minimised or closed. With **Settings → Background**
    on, closing the window only hides it and the app goes on in the tray (the menu bar
    on macOS), so browser autofill keeps working; the vault then locks by the same
    rules, and the tray menu shows whether it is unlocked and locks it. Showing an
    entry or its 2FA code doesn't
    count as activity, so it doesn't keep the vault open. Lists and details sent to the
    interface carry no passwords or 2FA secrets; a password (or a key's passphrase)
    reaches the interface only when you choose to reveal it. A 2FA secret never does:
    only the current code, computed in the Rust process.
  - Copying a password, a 2FA code or the recovery key goes from Rust straight to the
    clipboard, marked so clipboard history (and Windows' cloud clipboard) skip it, and
    is cleared after 30 seconds by default if nothing else was copied. Locking the vault
    clears it at once.
  - The secret generator on the Tools page makes its passwords, tokens and keys in Rust
    from the operating system's random number generator, as the vault does. It shows
    the value it made; copying it, or a `.env` line, an `export` or a connection URL
    around it, goes back through Rust to the clipboard in the same way. Nothing it makes
    is kept unless you save it to the vault, which needs the vault unlocked.
  - Changes are written atomically and the previous file is backed up (20 copies,
    still encrypted). A change to nothing but a paired browser's keys takes no backup,
    so the daily key change doesn't push out the backups taken before real changes. A
    write over a change made elsewhere is refused and saved as a separate copy; a write
    over key slots changed elsewhere is refused.
  - Key derivation settings read from `vault.keys` or a `.kdbx` header (memory, passes
    and lanes; each lane is a thread started for every quarter of every pass) are
    capped before use, so a tampered file can't make unlocking run for hours.
  - A 2FA secret the app can't make codes for (HOTP, a period of 0 or over 5 minutes,
    fewer than 6 or more than 10 digits), from an import, a contact or a KeePass file,
    is refused or kept as unreadable instead of crashing the app.
  - A new recovery key re-encrypts the app's backups and conflict copies, so the old key
    stops opening them. Exports, cloud versions and Time Machine copies made before still
    open with the old key. Changing the master password doesn't change the recovery
    key: an old copy of `vault.keys` still opens with the old master password, so make a
    new recovery key if the password may have leaked.
  - Turning off or loosening auto-lock, lock on sleep, screen lock or minimise, or
    clipboard clearing; turning off device unlock; and moving the vault or switching to
    another file are each confirmed in a system dialog, which the page can't answer or
    slip under a key press (see "Standard files only").
  - When it is used, a saved key passphrase goes from the vault straight to `ssh-agent`
    or `ssh` inside the Rust process; the interface receives it only when you choose to
    show it, like a password. Copying it goes from Rust straight to the clipboard. To
    say "saved, but the vault is locked", the interface remembers the fingerprints
    (public) of keys with saved passphrases in its local storage.
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
    the recovery key). The CSV export is plain text: it is readable only by you from the
    moment it is created (mode 0600; on Windows the file is created with an access list
    for you, SYSTEM and Administrators only, and no one else can open it while it is
    written). On a drive that can't keep such an access list (FAT or exFAT USB sticks,
    some network drives) both exports are refused and nothing is written. It is never
    written into `~/.ssh` or over the vault's own files (compared by file identity, so
    links and firmlinks don't get around it), and cells that a spreadsheet would run as
    a formula are defused, except passwords. Files to import are also picked in a
    system dialog. Imported CSV files can be moved to the Trash right after import.
  - Secret environments (the **Environments** page) are entries of the same vault:
    one per environment, in the group `Environments/<project>`, with a custom field
    per variable; a secret variable's field is protected like a password. Lists,
    details, import previews and comparisons sent to the interface carry names, flags
    and notes, never values: a value reaches it only when you choose to show it (or
    load it to edit it), and copying goes from Rust straight to the clipboard,
    cleared like a password when the variable is secret. Two environments are
    compared inside the Rust process; only the names that differ come out.
  - A `.env` file to import is picked in a system dialog the app opens itself and
    read again when you import, at most 1 MiB; nothing in it is expanded or run, and
    lines it can't read are reported by number, never quoted. The app never changes
    or deletes it.
  - Exporting an environment writes it in plain text (`.env`, JSON, YAML, shell
    `export` lines, a Docker env file, or a Kubernetes Secret, whose base64 hides
    nothing), to a file picked in a system save dialog, with the same protections as
    the CSV export: mode 0600 (or the private access list on Windows), never in
    `~/.ssh`, never over the vault's files. Shell lines quote every value in `'…'`,
    so sourcing the file runs nothing a value holds. When the file would be inside a
    Git working tree that doesn't ignore it (`git check-ignore`; without `git`, any
    working tree counts), nothing is written until you confirm in the app.
  - **Managed `.env` files.** A `local` environment can be written to files in the
    folders of the projects that hold it; a `remote` one never is. The interface names
    a file only as a project folder and a path in it. The app takes plain names ending
    in a `.env` file's name, never a template to commit (`.env.example`), resolves
    links on the way and refuses a file whose folder isn't that project folder or one
    inside it (by file identity), a file that is a link, a pipe or a device, and
    anything in `~/.ssh` or over the vault's files. A binding is checked again each
    time it is used, so one that arrives from another computer or an edited database
    is held to the same rules. A file is written by renaming a new private file over
    it (mode 0600, or the private access list on Windows; the temporary file is named
    `<file>.sshkm-….tmp`, so `.env*` ignore rules cover it, and one a crash leaves is
    removed on the next round), so a link put in its place is replaced, never written
    through; a file that isn't there is only ever created, never written over. It is
    read without following links, as a regular file only, and written only if its
    folder is still the one it was found in. A missing folder is never created.
  - Managed files and the vault are kept in step both ways. Per file, each computer
    keeps a keyed hash of the variables both last agreed on (`env-files.json` in the
    app's data folder; the key is in the vault, so the hashes say nothing without it).
    The revision is kept with the identity of the file's folder, so a folder swapped
    for another (a link put in its place) is a conflict, not an edit. An edit of the
    file goes to the vault and can be undone, and the entry's history keeps the
    previous version (trimmed to the database's history limit, 10 by default); these
    saves skip the vault's backup, so an editor saving often doesn't push out the
    backups of real changes. A variable whose line is deleted and written again gets
    back its secret flag and note from the history. A change in the vault rewrites
    only the lines of the variables that changed, in quotes every loader reads the
    same (single quotes for a value with `$`, `` ` ``, `\` or `"`). When both
    changed, nothing changes until you keep one side, as you saw it in the compare
    dialog: a file changed since is left alone. A file whose lines can't all be read
    (a quote that never closes, a line naming a variable without `=`), or that would
    remove half its variables or more at once, changes nothing until you say so.
    Values never reach the interface, errors or logs; the compare dialog compares only
    an environment's own files. Whether Git ignores or has committed a file is asked of `git` with
    `core.fsmonitor` off, so a repository's own settings can't make it run a program;
    a line goes into `.gitignore` only when you ask.
  - **Run in terminal** starts your own shell (`$SHELL` as a login shell, or
    `%ComSpec%` on Windows) in the in-app terminal with the variables added to its
    environment. Nothing is written to disk, but the shell and everything it starts
    hold the values in their environment: other programs running as you can read a
    process's environment (`/proc/<pid>/environ` on Linux, `ps -E` on macOS), and the
    shell may save the commands you type in its history.
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
    keyboard-interactive is on. The terminal then shows those prompts, and with
    keyboard-interactive on any prompt that names another account, as the sender's
    quoted text, never as the app's password or passphrase dialog.
  - The in-app terminal uses the same channel with an interactive session. A saved
    secret is given once and only to prompts for the host's own account; everything else
    (a secret not saved, a rejected one, a jump host's password) is asked of you in a
    dialog that names the account the prompt is for. Text that comes from `ssh` or a
    server is shown quoted and is never presented as the app's own question.
  - A new host key is trusted only when you choose "Trust" after seeing its
    fingerprint, which answers `ssh`'s own question. Before OpenSSH 8.5, with
    keyboard-interactive on or through a `ProxyJump` or `ProxyCommand`, a server can
    send the same question: the dialog then says so and quotes the host and
    fingerprint, and "Trust" only answers "yes", which trusts the key only if `ssh`
    asked. A changed host key stops the
    connection, and so does a new key of another type for a host whose key is already
    known. Anything else `ssh` adds to the question is shown as a warning.
  - An answer you choose to save goes into the vault only after the session has signed
    in. On Windows, where the app can't tell when that happens, the terminal never saves
    answers. Terminal output and answers are never logged.
  - Tunnels (Tools → Tunnels) use the same interactive channel: a saved secret is
    given once, a new host key is trusted only after your "Trust", and anything else is
    asked of you on the Tunnels page. A tunnel that reconnects by itself gets saved
    secrets again but never trusts a host key without you.
- **SSH tools.** The Tools page's SSH tools change nothing behind your back.
  - A tunnel is one `ssh -N` per forward, with `ExitOnForwardFailure` (no half-working
    tunnel) and no connection sharing (`ControlPath none`), so it neither rides on nor
    carries other `ssh` sessions. Local and SOCKS tunnels listen on `localhost` unless
    you pick "All addresses", which the app marks as open to your network. Every value
    that reaches `ssh` (alias, address, host, port) is checked first. Tunnels stop when
    the app quits and keep running while the window is closed to the tray, where the
    menu counts them and stops them all. Their definitions are in `tunnels.json` in the
    app's data folder (mode 0600): hosts, ports, names, never a secret.
  - The ProxyJump wizard and "Add to ~/.ssh/config" of a tunnel edit `~/.ssh/config`
    through the host editor's path: a backup first, refused if the file changed
    meanwhile, and a native confirmation for lines that say which server gets access.
  - The key converter decrypts keys in Rust only; the page sees fingerprints and the
    public key. Converted keys go into `~/.ssh` only as new files (0600), or where you
    pick in a system save dialog, never over a file in `~/.ssh`. New passphrases use
    the formats' strong options (OpenSSH bcrypt, PuTTY v3 Argon2id, PKCS#8 PBES2 with
    PBKDF2-SHA256 and AES-256); PEM, whose encryption is one round of MD5, is written
    only without a passphrase, and the app says so. The key derivation settings a file
    asks for (PuTTY's Argon2, PKCS#8's PBKDF2) are bounded, as bcrypt rounds are.
  - An `authorized_keys` line is built and checked in Rust and read back as `sshd`
    reads it before it is shown or installed. Installing it goes over stdin through the
    same script as installing a key, and never replaces a line that has the key
    already.
- **Quick search.** A system-wide key combination (⇧⌘Space on macOS,
  Ctrl+Shift+Space elsewhere; it can be changed or turned off in **Settings → Quick
  search**) or the tray menu opens a small window to connect to a host, copy a
  password, user name or 2FA code, or unlock the vault.
  - The combination is registered with the system (`tauri-plugin-global-shortcut`),
    which reports that one combination and no other keys. Running the app with
    `--quick-search` opens the same window in the running app (for desktops that
    give apps no global shortcuts, such as Wayland); it shows nothing to the
    program that ran it. A combination without
    Ctrl, Alt or ⌘ / the Windows key is refused, so it can't take a key used for
    typing.
  - The window's capability (`capabilities/quick.json`) allows only what it does:
    the hosts and the vault's entries without their secrets (`quick_items`, which
    doesn't count as activity), the vault's own copy (`vault_copy`: out of
    clipboard history, cleared after 30 seconds by default), the three unlock
    commands, connecting and closing. It can't reveal a password, read an entry's
    details or the config, or change anything; a test checks this.
  - A password never reaches the window: it goes from Rust to the clipboard as
    when copied in the main window. Unlocking asks for the master password, or
    Touch ID / Windows Hello, in the window itself, as the unlock window does.
  - The window stays above others and closes on Escape, after a copy, and when it
    loses the focus, so it doesn't stay open with the vault's entry names behind
    other windows. After Escape or a copy, the app that was in front gets the focus
    back.
  - The in-app command palette (⌘K) and quick search remember recently run items
    by id (`host:<alias>:connect`, `entry:<uuid>:password`) in the webview's local
    storage; never a secret or a query.
- **Browser autofill** (optional, off by default) lets the SSH Key Manager extension for
  Chrome, Edge and Firefox fill and save logins from the vault. See
  [Browser autofill](#browser-autofill) below.
- **Hosts from the shell history** (off until you say yes on the Hosts page) suggest
  servers you connect to.
  - The zsh, bash, fish and PowerShell history files are read by the Rust process, on
    this computer, only when the Hosts page asks (opening it while this is on, or
    **Look again**), never in the background, and at most their last 16 MiB.
  - Only `ssh`, `autossh`, `mosh`, `scp` and `sftp` commands are looked at. Of those, only
    the target (user, host, port), `-i`, `-J`, `-A` and a short list of `-o` options
    reach the interface; remote commands, file names and every other argument stay in
    Rust. Options that run programs or check servers less strictly (`ProxyCommand`,
    `LocalCommand`, `StrictHostKeyChecking`, `UserKnownHostsFile`, …) are never
    suggested, and nothing in a command is expanded or run (`$VAR`, `$(…)`).
  - Passwords typed into those commands (`sshpass -p`, `ssh://user:password@`, a `-o`
    option or a variable named like a password, also inside a `ProxyCommand`) are
    dropped and only counted per file, so the app can tell you to remove them.
  - A suggestion becomes a host only through the Add Host dialog, which shows the whole
    block and asks the same confirmations as any other host.
  - Your answer and the suggestions you dismissed are kept in `shell-history.json` in
    the app's data folder (mode 0600): a dismissed host as an HMAC-SHA-256 of its user,
    host and port under a random key of that file, never as the host or the command.
    Turning it off in **Settings → Shell history** stops all reading.
- **Minimal network access.** The app sends none of your data anywhere (the optional
  breach check sends 5 hex characters of each password's hash). Its only requests are:
  - the update check, which downloads `latest.json` from this repository's GitHub
    Releases at startup and every six hours (can be turned off in Settings);
  - `ssh-keyscan` and `ssh` when you explicitly check a host key, test a connection or
    open a terminal session;
  - a DNS lookup when you ask where a name leads;
  - `ssh` for each tunnel you turn on, for as long as it is on;
  - after a failed connection, when you choose "Check port": one TCP connection to the
    host's port (or its first jump host's), closed at once without sending anything.
    The address comes from `ssh -G` for a host alias, never from the page, so the page
    can't point it elsewhere.
  - the audit's breach check, only after you turn it on (off by default; see below).
  - the network checks on the Tools page, each when you click it, in Rust with
    timeouts and without running other programs:
    - SSH ping and the port check open TCP connections to the host and port you name
      and close them before sending anything; SSH ping reads the line the server sends
      first.
    - The TLS check makes a handshake with the host and checks its certificate with the
      system's certificate store (on macOS and Windows that may ask the certificate's
      issuer whether it was revoked). The handshake goes on even with a certificate the
      system doesn't trust, so the certificate can be shown; nothing is sent after it,
      and the connection is closed, so a server that isn't who it claims gets nothing.
    - The DNS lookup asks the DNS servers your computer is set up with
      (`/etc/resolv.conf`, or the network adapters' settings on Windows) for the name
      you type. An answer counts only if it comes from the server asked, carries the
      random id of the query and repeats its question.
- **Why a connection failed.** A connection test runs `ssh -v`, so a failure can say
  which keys were offered. The extra lines go no further than the app's memory: what
  you read leaves them out (and the server's pre-login banner, as before), and the
  diagnosis keeps only the lines about the failure, since others can hold the values
  of environment variables `ssh` sends (`SendEnv`). Answers never pass through them:
  they go through askpass. The terminal runs `ssh` without `-v` and reads its usual
  messages. A fix never trusts a host key for you: it opens the host key check. One
  that turns an old algorithm back on (`HostKeyAlgorithms +ssh-rsa`, …) only changes
  the host's block in the editor, for you to review and save, which confirms it like
  any other change.
- **Breach check (optional, off by default).** The audit can look up saved passwords in
  Have I Been Pwned's Pwned Passwords, with k-anonymity. The page only turns it on or
  off and asks for a check; the rest happens in Rust, and passwords and their hashes
  never reach the page.
  - For each password the vault rates (outside the recycle bin, not empty), the app
    computes its SHA-1 hash and sends only the first 5 hex characters to
    `https://api.pwnedpasswords.com/range/<prefix>`, with `Add-Padding: true` and the
    user agent `SSH-Key-Manager`. The server answers with the hash suffixes it knows
    under that prefix (hundreds of them, padded with made-up ones so the size of the
    answer says nothing either), and the app compares the rest of the hash on this
    computer. The service sees your IP address and which ranges you asked for, never a
    password or a whole hash.
  - Requests go over HTTPS only (no redirects, certificates checked against the
    system's roots), one at a time and at most ten a second; an answer larger than
    1 MiB or not in the range format is discarded. A failure stops the check and is
    shown; the audit then waits five minutes before trying by itself again.
  - Results stay in memory, keyed by an HMAC-SHA-256 of each password under a random
    key that exists only in memory, so unchanged passwords aren't asked about again
    while the vault is unlocked (the audit asks again after a day, "Check now" at
    once). Locking the vault drops them, with that key. Nothing about the check is
    written to disk except whether it is on (`breaches.json` in the app's data
    folder), and range prefixes are never logged.
- **Signed updates.** An update is installed only if its signature matches the public key
  built into the app (`plugins.updater.pubkey` in `src-tauri/tauri.conf.json`), and only
  if it is newer than the running version.
  - The signature names the version it was made for, and the app refuses an update whose
    signature doesn't name the version `latest.json` offers (`requireSignedVersion`), so
    an older release can't be offered as a newer one. Every release so far carries it.
  - The update check runs in Rust. The page can ask for a check or an install, but can't
    change the server, proxy or headers.
  - Release builds use GitHub Actions pinned to commit SHAs, and restore no caches: CI
    saves its caches after running development tools, so a release builds from the
    lockfiles alone.
  - The updater signing key is a secret of the `release` environment, which only the
    signing job uses, on version tags, after a maintainer approves it. That job runs on
    a fresh runner that never builds or installs the app's code. It downloads each
    platform's bundles into a folder of their own and stops if a build made a file of
    another kind, or a file of the same name as another build's. One step gets the key:
    it runs the Tauri CLI pinned in the lockfile (installed beforehand by pnpm, without
    running any package scripts) with an exact version of Node, and nothing else. The
    job then checks that each signature is by the key the app trusts and names the
    release's version, and writes `latest.json`. Code that runs while building (build
    scripts, proc macros, npm packages) never shares a machine with the key, though it
    could still change what the build jobs produce: code running in one build job has
    that run's artifact access, so it could replace the files another platform's job
    uploads before they are signed.
  - Apple code signing and notarization, when set up, run in the macOS build job, with
    secrets of an environment that only that job uses and only version tags can reach.
    Windows installers aren't code-signed yet.
  - CI checks the Rust dependencies with `cargo deny`: known advisories, crates from
    anywhere but crates.io, and licenses the app can't be shipped with (`deny.toml`).
- **Standard files only.** The app edits the OpenSSH files in place.
  - Writes are atomic (temp file plus rename), keep the file's permissions, and follow
    symlinks.
  - `config` and `known_hosts` are backed up before every write. An edit is tied to the
    version of the file it was made on and refused if the file changed meanwhile.
  - A change that adds or alters a directive that runs a program, loads a library,
    includes another file, or gives the server access (`ProxyCommand`, `LocalCommand`,
    `KnownHostsCommand`, `Match exec`, `PKCS11Provider`, `SecurityKeyProvider`,
    `Include`, `IdentityAgent`, `ForwardAgent`, `ForwardX11`, a dynamic
    `RemoteForward`, …), a host name with shell syntax, a change of which server gets
    such access (`HostName`, `Port`, `User`, `ProxyJump`, `HostKeyAlias` or the `Host`
    line of a block it applies to), or one that checks servers less strictly
    (`StrictHostKeyChecking no` or `accept-new`, `UserKnownHostsFile`,
    `GlobalKnownHostsFile`, `VerifyHostKeyDNS yes`), is confirmed in a system dialog
    that shows it. Lines are read as OpenSSH reads them (only spaces and tabs separate
    words; quoted keywords count), and text with control characters other than tabs
    and line ends is refused.
  - A script in the page can't answer that dialog, and a yes given less than a second
    after a dialog appeared doesn't count: the dialog is asked again (three times at
    most, then the answer is no), so a script can't open one under a key press meant
    for the page. This holds for every confirmation dialog in the app.
  - Whatever the page asks, the app runs `ssh` (connection tests, key installs, the
    in-app and system terminal) only with a host alias of letters, digits and
    `. _ - @ : [ ]`. OpenSSH before 9.6 puts the name as it is into the commands that
    `ProxyCommand`, `ProxyJump` and `Match exec` run through the shell, so a name with
    shell syntax could run as a command.
  - Private keys are deliberately not backed up, because a backup taken before adding a
    passphrase would leave an unencrypted copy behind.
- **Deletions are recoverable.** Removed keys go to the system Trash.
- **Rotating a key takes the old one away only where the new one works.**
  - The new key is added to a host by signing in as the host does now, with the old key.
  - Then the app signs in offering the new key first, with password and
    keyboard-interactive logins off, and counts the sign-in only if `ssh -v` logged
    that the server accepted the new key: the old key, still named in the config or
    held by the agent, would otherwise get in after the new one is turned down. The
    log goes to a new file only you can read in the temporary folder (`ssh -E`),
    removed right after, so nothing a jump host prints or a server sends as a banner
    reaches it. A server can still forge a line of it in a debug message, but only
    about itself.
  - Only then does the host's block in `~/.ssh/config` name the new key, through the
    usual edit with its revision check.
  - The old key comes off a server's `authorized_keys` only when you choose it, only
    for hosts whose new key passed that check and whose block names it, and never
    while another alias of the same account (same host name, port and user, or no
    user written) still signs in with the old key. The file is read back after the
    change and a key still in it counts as not removed.
  - The old key file is offered for the Trash only once no host in the rotation and
    no block of the config still uses it; it is also removed from `ssh-agent`.
  - A rotation in progress is kept in the interface's local storage so it can go on
    later: key and host names, fingerprints, the old public key and how far each host
    got. Nothing secret.
- **Administrator rights only to save the hosts file, and only when you save.** The app
  itself never runs with administrator rights.
  - Changes to the hosts file are collected first and shown as a diff. Saving writes the
    approved text to a private temporary file and asks the system to run one fixed
    script with administrator rights: `osascript … with administrator privileges` on
    macOS, `pkexec` on Linux, a UAC prompt on Windows. On macOS the text of the password
    dialog is the app's own, never the page's: it says whether the file is being
    updated or restored from a backup, and names the hosts whose address changes (the
    first five, then how many more).
  - The script copies the text somewhere only an administrator can read or change (a
    file only root can read on macOS and Linux, memory on Windows), checks its length
    and SHA-256 against the text you approved and only then puts it in place, so another
    program cannot swap the temporary file in between, and whatever it swaps in is never
    readable by anyone else. It reads the temporary
    file only if it is a regular file, and at most one byte more than the approved text.
  - Right before replacing the hosts file it checks that the file is still the one your
    changes were made on. If another program changed it while the password prompt was
    open, nothing is written and the app shows the changes again over the new file.
  - Nothing you type goes into the script: it receives only paths, the length and
    checksums, as arguments on macOS and Linux (`quoted form of` on macOS, where the
    dialog's text goes to `with prompt`, never to the shell) and as
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
  - Only the Tauri capabilities the UI needs are granted (`src-tauri/capabilities`),
    each window its own. Every command of the app needs a permission (`build.rs` lists
    them, and a test checks the list against the commands registered), so a window
    can call only what its capability names: the main window all of them, the
    browser's unlock window only the three that unlock the vault, the quick search
    window only what it lists and does (see "Quick search" above).
  - The window only shows the app's own page: navigating elsewhere is refused and new
    windows can't open. Links open in your browser, and only `http` and `https` links.
  - Permission fixes apply only what the app's own audit found inside `~/.ssh`, and only
    ever remove permissions.
  - Config fixes from the audit apply only what its rules offer for the file at that
    moment, and to the version of the file the page saw: they remove a
    `StrictHostKeyChecking no`, `UserKnownHostsFile /dev/null` or `ForwardAgent` line,
    or add `IdentitiesOnly yes` to blocks the audit names. They never add a directive
    that needs the confirmation above.

## Browser autofill

```text
extension ──native messaging──▶ host (the app's executable) ──socket / pipe──▶ app
```

Turning on **Settings → Browser autofill** writes a native messaging manifest for each
installed browser. The manifest names the app's executable and only this extension
(by its Chrome ids and its Firefox add-on id). Turning it off removes the manifests and
stops the listener. Nothing listens while it is off. A manifest never points where
another user could later put a program of their own: an AppImage is registered by the
AppImage file itself, and a copy running from a temporary folder isn't registered at
all, nor on macOS one running from a volume under `/Volumes` (its disk image, a USB
drive, a network share: once it is ejected, anyone can mount another under the same
name) or from where macOS runs a downloaded app until it is moved (App Translocation).
Settings then asks to move the app to Applications.

**What the extension can get.**

- The app answers these questions, each about one page:
  - which logins belong to it: titles and usernames only;
  - the username and password of the one login the user picked there;
  - whether a login the user typed there is new, changed or already saved;
  - saving or updating that login;
  - changing the username or password of one of its logins, or moving one to the
    vault's recycle bin (the popup, and the "couldn't sign in?" banner).
- Changing or removing a login sends no secret back and asks nothing in the app: the
  old version stays in the entry's history, and a removed login stays in the recycle
  bin, where the app restores it. Nothing is ever deleted for good from the browser.
  The extension asks the user before it removes one. A browser may change at most ten
  logins a minute, so a program holding its keys can't clear out a site's logins at
  once. An app from before these questions can't read them and answers `invalid`,
  which the extension shows as "update the app".
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
  - The menu opens only when the user clicks a login field, moves to it with Tab or
    presses Down Arrow in it, and moves only on events the browser marks as the user's
    own. A page's own focus (`focus()`, `autofocus`) opens nothing, though the browser
    marks it as trusted; events a page script makes up are ignored.
  - A pick counts only once the menu has been on screen for half a second, uncovered at
    the point clicked, and only while the page hasn't restyled, moved or hidden it, so
    a page can't slip it under a click or key press meant for something else. A layer
    the page opens later over the menu sends the menu back to the front, and the wait
    starts again.
  - In Chrome and Edge the browser also confirms that nothing covers the menu, not even
    a layer that lets clicks through. Firefox has no way to tell that, so there a
    script on the site could still lay a see-through decoy over the menu; the app's
    question then names the login before it first fills that page. Later fills of that
    login there in the same session aren't asked about.
  - Fields that are nearly transparent, smaller than 8 pixels, or outside the window get
    no menu.
- Nothing else of the vault is reachable: not other entries, 2FA secrets, notes, key
  passphrases or the vault's settings.

**Unlocking for the browser.**

- On a locked vault, **Unlock** in the login menu, and the save banner, ask the app to
  unlock it. The request (`unlock`) needs no pairing and carries nothing. The app then
  asks the user itself, never in the browser:
  - With Touch ID or Windows Hello set up for the vault, only the system prompt. Its
    text is the app's own, and an app in the tray stays there.
  - Otherwise, or if that prompt is dismissed or fails, a small window of the app's own
    asks for the master password (and offers Touch ID or Windows Hello again where it
    is set up). It stays above other windows, has no taskbar button, and closes once
    the vault is unlocked, whichever way that happened. The main window stays as it
    is.
  - A vault this computer opens only with its recovery key is unlocked in the main
    window, which comes forward on it.
- The master password is typed only in the app's own window. It never reaches the
  browser, the extension or the native host. A page can draw a look-alike of any
  dialog inside the browser, so the extension never asks for the password itself, and
  a page can't draw into the app's window. The window loads its own page
  (`unlock.html`), not the main window's, and has its own capability
  (`src-tauri/capabilities/unlock.json`): `vault_status`, `vault_unlock`,
  `vault_unlock_device` and closing itself, nothing else of the app.
- The browsers may ask at most five times a minute, all together. While the system
  prompt is up, asking again does nothing; while the window is open, asking again only
  brings it forward. So neither a page (the menu takes only the user's own clicks
  anyway) nor a program that can start the native host can bury the screen in
  windows.
- Where the system decides, the window may not get its way: on Windows a program in
  the background may be refused the focus (the app first sends a synthetic Alt key
  press, which Windows counts as the user's input to it), and on Wayland the
  compositor places windows and may keep the focus or the top for the browser. The
  window still opens; the user may have to click it.
- **Open app** in the extension's popup still brings the main window forward on the
  vault.
- Malware running as the user could draw a window that looks like the app's; as
  below, that is outside this model.

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
username or the saved login's title. Only a login the user put in themselves is sent to
be checked: its password typed, pasted or dropped into the field by the user (or filled
by the extension) and not set or changed by a page script since, and the form sent by
the user's own Enter, click or key press. A page that sets the values and calls
`requestSubmit()` gets nothing checked. A tab can send typed logins to check at most
about once a second. Whether the banner appears still tells the page whether the login
the user just typed there is saved, which is about a password the page was given
anyway; the banner's size is the same whether it offers to save or to update, whatever
the saved login's title. The banner's username is a field the user can change (a form
may send a password alone); key presses in it stop at the banner, but a page listening
in the capture phase still sees them, which tells it the username of its own login. A
login typed on another site gets no such field. The username sent with the first step
of a two-step login waits in `storage.session` for five minutes, for that tab only,
and names a password sent there without one on the same site.

A password-change form (a current password, then a new one and its copy) passes on the
new password, under the same rules: typed by the user and sent by them. A form that
names no username is matched to the login filled in that tab in the last ten minutes,
or to the site's only saved login; the banner then offers to update it. The title and
username of the login filled last in a tab (never its password) wait in
`storage.session` for that. If the user sends a form with a login the extension filled
and, within 20 seconds, the same origin shows its sign-in form again with an empty
password field and the same or no username, the top frame says the saved password may
be out of date: once per login per tab. **Update** only points the user at the page's
password field; **Remove from vault** asks first, and the background moves only the
login that banner named, on that page, to the recycle bin.

**The popup's logins.** With `activeTab`, the popup reads the address of the tab it was
opened on and lists that site's logins. The origin comes from the browser, and the app
checks each change against it like any other lookup, so the popup can't touch another
site's login either. A new password is sent only if the user typed one.

**The browser's own suggestions.** The popup can turn off the browser's "Offer to save
passwords" (and in Chromium its address and earlier-entry suggestions) with the
optional `privacy` permission, which it asks for only when the user turns them off.
Turning them on again hands the settings back to the user's own choice. A setting the
user's organization or another extension controls is left alone.

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
  keys, or a compromised renderer, could guess saved passwords through it. A page
  script can't ask: the extension checks only logins the user typed and sent.

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
  the app. It can also have typed logins checked against that site's, at most ten a
  minute, and learn from the banner whether one is saved.
- A site you log in to sees the password you fill there, as it would if you typed it.

## Nearby

Two copies of the app on the same local network pair, and later talk, over a direct
TCP connection. The cryptography is in `sshkm_core::p2p`, the networking in
`src-tauri/src/nearby/`.

- **Visible on request.** The app announces itself (mDNS, `_sshkm._tcp`) and accepts
  connections only for ten minutes after the user clicks **Show for 10 minutes** (or,
  without a vault, **Get it from my other computer**), under a random instance name
  with the device name in the TXT record; the device key is never announced. It
  browses for others only while the Nearby page is open. The user's own devices find
  each other another way (below).
- **Device key.** Each computer has a Curve25519 key pair, made on first use and kept
  in the system's credential store. Paired computers know each other by the public key.
  Each shows a computer it knows by the name it keeps for it in the vault, never by the
  name that computer gives itself now; only a computer it doesn't know yet is shown by
  its own name. Two contacts or devices of the same name are shown with the day each
  was paired.
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
  pairing needs it unlocked. A computer that was a contact already keeps the name it
  has here when the two pair again.
- **One at a time.** While a pairing, an adding or a sync goes on, other connections
  are closed at once.
  The users have three minutes to compare the codes.
- **Sending.** After pairing, or straight away between contacts, the side that
  connected may send one item: a vault entry, a secret environment, a host, a hosts
  file group or a public key. The UI only names it; the backend reads it from the vault, `~/.ssh` or the
  hosts file. First goes a summary with nothing secret in it (title and username,
  alias, address and jump host, a group's name, size and first names, or a key's name,
  type, fingerprint and comment); the item itself goes only after the other user
  accepts. Any computer can announce any name: when the user sends to a computer
  picked from the list and the one that answers is a contact (or one of the user's
  devices) the vault keeps under another name, the app asks whether to send to it all
  the same before even the summary goes; on a no nothing goes. The receiver checks
  that the item matches the summary and that every name in a host is made of name
  characters only, refuses a host block that would add a directive running a program,
  and gives an alias a number when `ssh` reaches that name already: a `Host` line of
  the config or of a file it includes names it, `known_hosts` trusts a key for it (its
  own or a certificate authority's), or a block that sets `HostName` or `HostKeyAlias`
  may cover it. A host with a number still leads where the sender's alias did. It
  never adds a server key for a host it already trusts a key for, its own or a
  certificate authority's, since `ssh` would then accept the sender's key next to its
  own; it keeps its own and warns instead. A 2FA secret
  goes only if the sender ticks it; a key's passphrase never goes.
- **An environment arrives as a new one.** Its summary names the project, the
  environment, how many variables (and secrets) it has and the first three names;
  the values go only after the other user accepts. The receiver checks every name
  (variable names are letters, digits and `_`), refuses control characters other
  than line breaks and tabs in values, and takes at most 1000 variables and 384 KiB.
  It is saved as a new environment: one of the same name in that project gets a
  number (`prod 2`), so a sender can never replace or add to an environment the
  receiver has.
- **A hosts file group is never written on arrival.** The hosts file decides where
  names lead for every program, so a received group only becomes a change on the
  Hosts file page: the user sees the diff and saves it with the administrator
  password, as any other change (see above). Its entries must be plain IP addresses
  (no `%scope`) and host names made of name characters, none of them one the system
  relies on (`localhost`, …); comments don't travel. At most 1000 entries come in
  one group. A group of the same name gets a number (`Staging 2`), so the sender
  can't add entries to a group already there.
- **A public key arrives as a key of someone else's.** Only the public half ever
  goes: the sender's private key is never read. The receiver parses the line as an
  OpenSSH public key (one line, not a certificate) and writes it out again from
  what was parsed, as `~/.ssh/<name>.pub`. A name either half of a pair has already
  gets a number, so a received key never pairs with a private key of this computer;
  a name `ssh` tries on its own (`id_ed25519`, …) gets the sender's device name
  added, since `ssh` would otherwise offer someone else's key to every server. A key
  that is there already is not written again. Its fingerprint is remembered in
  `nearby.json`, so the audit doesn't report it for having no private key.
- **Own devices.** The user's own computers are a separate, higher level of trust than
  contacts. They are listed in the vault (`sshkm.device.<device key>` in its custom
  data), this computer included, so every copy of the vault knows all of them; a
  removed one stays as a tombstone, which is final: a sync never brings it back, only
  adding it again on that computer does. Record times are checked as RFC 3339 UTC, and
  a record dated more than five minutes ahead of this computer's clock is not taken.
  The "own device"
  part of a conversation goes only to a peer whose `Hello` says it knows about own
  devices; older versions see nothing new.
- **Same vault, without telling it.** In its `Hello` each side sends an HMAC-SHA256
  over the session's handshake hash and its role, keyed with a key derived (HKDF) from
  32 random bytes the vault keeps in its encrypted custom data (`sshkm.own.key`). The
  vault makes them when the user first adds a device, and they travel inside the vault
  file. They never come from the vault secret or a password, so a peer learns nothing
  from the proof, not even something to test a guessed KeePass password against. A
  peer with the same vault checks it in constant time, and it can't be replayed in
  another session. A new recovery key replaces the key, so a computer that is gone
  fails the check.
- **Adding a device.** The computer with the vault connects to the other. Both users
  compare the code, always, even between contacts; then the first user confirms with
  Touch ID / Windows Hello or the master password. Only the app's own check of either
  counts: a yes from the page, or one left over from the code comparison, is never
  taken for it. Only then does it record both
  computers as the user's devices. Two different vaults are never merged: the
  conversation stops before the code. If the other computer has no vault yet (it
  waits for one, `join=1` in its announcement, and takes nothing but being added),
  it gets the vault file in parts (its size and SHA-256 first, at most 256 MiB) and
  then the vault secret. It checks that the secret opens the file, keeps both in
  memory only, and writes the file once its user has set a master password of its
  own. Someone else on the network who answers in place of that computer shows a
  code the user never sees on their own screen, and the real computer shows none.
- **Reachable by own devices.** While the vault is unlocked, there is another own
  device, and the user didn't switch it off, the app listens on a port of its own
  and announces it as `_sshkm-own._tcp` under an HMAC of its device key and the
  current ten-minute window, with nothing else in the record. The name changes and
  says nothing to others; the user's devices recognise it. On that port only a sync
  is taken, and only from a device that is one of the user's and proves it has the
  vault: anyone else is turned away right after the handshake, before this computer
  sends anything about its vault.
- **Syncing hosts.** Only `Host` blocks for single names go: never `Match`, `Host *`
  and other patterns, options before the first block or `Include`. A block goes
  without what belongs to the computer (`IdentityFile`, `CertificateFile`,
  `IdentityAgent`, `UseKeychain`, `IdentitiesOnly`, PKCS#11 and security key
  providers, control sockets, other `known_hosts` files) and without any value that
  names an absolute or home path. The receiver checks every id, keyword and value
  again, keeps its own options of the block where they are, and puts new blocks
  before `Host *`. What changed is told by a snapshot of each other device's last
  sync, kept as HMACs (keyed with a key derived from the device key) of each field,
  never the values. A change that would add a directive on the list under "Standard
  files only" above and more than five deletions at once are never made unasked: the
  user of the computer that started the sync decides there, and the other computer
  puts them off until its own user syncs from it. A change that adds such a directive,
  a conflict settled for the other computer's version included, is written only after
  that user allows it in a system dialog that lists the hosts and directives; on a no
  it waits for the next sync. A change turned down is not asked about again until it
  changes. A conflict is the user's choice too. Both files are backed up before a sync
  writes them, and a file changed meanwhile is not written.
- **Syncing server keys.** `known_hosts` only grows: a computer adds the other's keys
  for a host it has no key for, counting a matching `@cert-authority` line as one, and
  never adds a key it marked `@revoked`; such keys are shown as a difference. For a
  host it trusts another key of the same type for, it keeps its own and shows both
  fingerprints: one of the two may have met a server pretending.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub security advisories](https://github.com/nuriddin2468/ssh-key-manager/security/advisories/new).
You will get an answer within a few days.
