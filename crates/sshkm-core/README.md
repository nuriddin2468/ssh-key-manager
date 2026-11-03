# sshkm-core

Core library of SSH Key Manager. The desktop app (Tauri) calls it from its
commands; this crate does all the work on the files.

The app is a front-end over the **standard OpenSSH files**: keys in `~/.ssh`,
`~/.ssh/config`, `~/.ssh/known_hosts` and the system `ssh-agent`. There is no
agent of our own, so everything stays compatible with `ssh`, `ssh-keygen`,
`ssh-add`, git and IDEs. The optional password vault is a standard KeePass
file, so KeePassXC and other KeePass apps open it too.

## Modules

| Module | What it does |
|---|---|
| `paths` | `SshPaths` (`~/.ssh`, `%USERPROFILE%\.ssh`), `expand_tilde`, `display_path` (`~/…`). |
| `fsutil` | `atomic_write` (temp file + fsync + rename, keeps permissions, follows symlinks), `write_new` (never overwrites), `backup` (timestamped copies, newest 20 kept). |
| `keys` | `scan` a directory by content (OpenSSH, legacy PEM, PKCS#8, `.pub`), `inspect` one file, `generate` (Ed25519, RSA 3072/4096, ECDSA), `change_passphrase`, `load_private`, `regenerate_public`, `import`, `move_to_trash`. |
| `config` | Lossless `ssh_config` model: byte-for-byte round trip, read view of `Host`/`Match` blocks, minimal-diff edits (`upsert_host`, `delete_host`, `remove_identity_file`), `identity_usage`. |
| `known_hosts` | Lossless `known_hosts` model: plain and hashed (`\|1\|salt\|hash`) entries, markers, matching with `*`/`?`/`!` and `[host]:port`, `remove_host`, `remove_lines`. |
| `agent` | Synchronous `ssh-agent` client: status, list, add (lifetime / confirm constraints), remove, remove all. Unix socket or Windows named pipe. |
| `perms` | Permission checks and fixes: Unix modes; Windows ACLs via one batched PowerShell call, compared by SID, fixed with `icacls`. |
| `audit` | Findings (DSA, short RSA, no passphrase, open permissions, missing/mismatched `.pub`, duplicates, dangling `IdentityFile`, legacy format) with stable ids and one-click fixes. |
| `vault` | The password vault: a KeePass KDBX 4.1 database (Argon2id, ChaCha20) whose password is a random recovery key, plus a key slots file that opens it with the master password or a device key. Entries with history and recycle bin, links to SSH hosts and keys, 2FA codes, conflict-safe writes for synced folders, a password/passphrase generator and zxcvbn strength. |

All errors are one `Error` enum with a stable `code()` (`not_found`,
`already_exists`, `invalid_input`, `wrong_passphrase`, `passphrase_required`,
`agent_unavailable`, `agent_refused`, `unsupported`, `parse`, `io`,
`permission_denied`, `conflict`, `vault_locked`) that serialises as `{ "code": …, "message": … }`. Statuses
and findings are machine-readable kinds with parameters, so the UI can localise
them.

## TypeScript bindings

Every public data type is `serde::Serialize` with camelCase fields. With the
`ts` feature they also derive `ts_rs::TS`:

```sh
cargo test -p sshkm-core --features ts
```

writes one `.ts` file per type into the repository's `src/bindings/` (the path
is fixed relative to this crate, independent of the working directory).

## Security notes

- **No private key material leaves the crate in serialisable form.** `KeyInfo`
  holds only metadata and the public key. The one type holding a decrypted key,
  `keys::UnlockedKey`, is not `Serialize`, its `Debug` shows only the
  fingerprint, and the key is zeroized on drop (as are file contents read
  during key operations and the agent request buffer).
- Passphrases are `secrecy::SecretString`; `GenerateRequest.passphrase` is
  accepted from JSON but never serialised back.
- Keys are generated with the OS random number generator and written exactly
  like `ssh-keygen`: OpenSSH format, encrypted with bcrypt-pbkdf (16 rounds,
  16-byte salt) + aes256-ctr when a passphrase is given; private 0600, public
  0644, `~/.ssh` 0700. Existing files are never overwritten.
- Every write is atomic. Config and `known_hosts` are backed up before saving.
  Private keys are deliberately **not** backed up: a backup of a key taken
  before adding a passphrase would leave an unencrypted copy behind.
- Deleting keys moves them to the system trash/recycle bin (on macOS through
  `NSFileManager`, so no Finder automation permission is needed).
- Files are detected by content and read with a 64 KiB limit; parsers are
  total — malformed input is reported (skip reasons, config issues, invalid
  `known_hosts` lines) and preserved, never a panic. Non-UTF-8 config or
  `known_hosts` files are refused rather than rewritten lossily.
- Symlinked `~/.ssh/config` (dotfiles repositories) stays a symlink; the target
  file is updated.
- On Windows a rewritten file inherits the ACL of its directory. After writing
  a private key the crate re-applies the OpenSSH ACL (user, `SYSTEM`,
  `Administrators`); `audit` reports anything else. Child processes
  (`powershell.exe`, `whoami`, `icacls`) run with `CREATE_NO_WINDOW`.

## Limitations

- Encrypted legacy PEM / PKCS#8 keys are recognised but cannot be decrypted
  (convert them with `ssh-keygen -p -f <key>`); DSA PEM keys need their `.pub`
  for a fingerprint. `change_passphrase` works on OpenSSH-format keys only.
- `Match` blocks can be read and deleted, not edited.
- `Include`d files are listed, not loaded.
- PuTTY `.ppk` keys are reported (`putty`), not converted. Pageant is not
  supported as an agent (point `SSH_AUTH_SOCK` at a pipe it exposes, or use the
  OpenSSH agent service).
- `identity_usage` expands `~`, `%d`, `%%`, `%u`, `%h`, `%n`, `%r`, `%p` and
  `${VAR}`; paths with other tokens or relative paths are marked unresolved.

## Tests

```sh
cargo test -p sshkm-core --all-features
# compatibility checks against the real OpenSSH tools (temporary files and a
# private ssh-agent only, never ~/.ssh or your agent):
cargo test -p sshkm-core --all-features -- --ignored openssh_accepts_edited_config real_ssh_agent_round_trip ssh_keygen_reads_generated_keys
```

`trash_moves_file` (also ignored) moves a temporary file to your real trash.

The key fixtures in `src/keys/testdata/` are throw-away keys generated with
`ssh-keygen` and `openssl` for these tests.
