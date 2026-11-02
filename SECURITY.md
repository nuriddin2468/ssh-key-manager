# Security

SSH Key Manager handles private keys, so its design keeps the attack surface small.

## Security model

- **Private keys never reach the UI.** The webview only receives metadata and public keys.
  Decrypted keys exist only inside the Rust process, are zeroized when dropped, and are
  passed straight to `ssh-agent`.
- **Passphrases are not stored.** They travel from the form to the Rust process for one
  operation and are held in `secrecy::SecretString`. They are never logged.
- **Minimal network access.** The app sends none of your data anywhere. Its only
  requests are:
  - the update check, which downloads `latest.json` from this repository's GitHub
    Releases at startup and every six hours (can be turned off in Settings);
  - `ssh-keyscan` and `ssh` when you explicitly check a host key or test a connection;
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

## Reporting a vulnerability

Please do not open a public issue. Report it privately through
[GitHub security advisories](https://github.com/nuriddin2468/ssh-key-manager/security/advisories/new).
You will get an answer within a few days.
