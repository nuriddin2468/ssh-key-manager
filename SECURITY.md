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
  - Strict Content Security Policy: only the app's own scripts run, and no `eval`.
  - Tauri's frozen JavaScript prototype (`freezePrototype`) is off: the terminal
    (xterm.js) assigns its own `toString` while loading, which a frozen prototype
    forbids, and the whole page then failed to start in 0.3.0.
  - Only the Tauri capabilities the UI needs are granted (`src-tauri/capabilities`).
  - Permission fixes are limited to paths inside `~/.ssh`.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub security advisories](https://github.com/nuriddin2468/ssh-key-manager/security/advisories/new).
You will get an answer within a few days.
