# Security

SSH Key Manager handles private keys, so its design keeps the attack surface small.

## Security model

- **Private keys never reach the UI.** The webview only receives metadata and public keys.
  Decrypted keys exist only inside the Rust process, are zeroized when dropped, and are
  passed straight to `ssh-agent`.
- **Passphrases are not stored.** They travel from the form to the Rust process for one
  operation and are held in `secrecy::SecretString`. They are never logged.
- **No network access.** The app makes no requests. The only network activity is
  `ssh-keyscan` and `ssh` when you explicitly check a host key or test a connection.
- **Standard files only.** The app edits the OpenSSH files in place.
  - Writes are atomic (temp file plus rename), keep the file's permissions, and follow
    symlinks.
  - `config` and `known_hosts` are backed up before every write.
  - Private keys are deliberately not backed up, because a backup taken before adding a
    passphrase would leave an unencrypted copy behind.
- **Deletions are recoverable.** Removed keys go to the system Trash.
- **Locked-down webview**
  - Strict Content Security Policy and a frozen JavaScript prototype.
  - Only the Tauri capabilities the UI needs are granted (`src-tauri/capabilities`).
  - Permission fixes are limited to paths inside `~/.ssh`.

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub security advisories](https://github.com/nuriddin2468/ssh-key-manager/security/advisories/new).
You will get an answer within a few days.
