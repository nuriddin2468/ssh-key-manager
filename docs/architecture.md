# Architecture

```
React UI (src/)  ──invoke──▶  Tauri commands (src-tauri/)  ──▶  sshkm-core (crates/sshkm-core)
      ▲                              │                                  │
      └──── "ssh-files-changed" ─────┘ file watcher on ~/.ssh           ├─ ~/.ssh/*, config, known_hosts
                                                                         └─ ssh-agent socket / named pipe
```

## sshkm-core

A UI-free Rust library. Every function takes explicit paths, so tests never touch the
real `~/.ssh`. Its modules:

- `keys`: scans, inspects, generates, imports and re-encrypts keys.
  - OpenSSH format, plus unencrypted legacy PEM and PKCS#8.
  - Keys get the same SHA-256 fingerprints `ssh-keygen -l` prints.
- `config`: a lossless model of `ssh_config`.
  - Unmodified files round-trip byte for byte.
  - Edits change only the lines they touch.
  - New hosts go before a trailing `Host *` block, because the first match wins.
- `known_hosts`: a lossless model, including matching of hashed (`|1|`) entries.
- `agent`: a small synchronous client for the ssh-agent protocol.
  - Connects through a Unix socket (`SSH_AUTH_SOCK`), or on Windows a named pipe:
    `SSH_AUTH_SOCK` if it names one, else the OpenSSH agent's pipe.
- `perms`
  - Unix: checks and fixes file modes.
  - Windows: checks and fixes ACLs, using locale-independent SIDs through PowerShell and
    `icacls`.
- `audit`: pure rules over the data above. Findings carry machine-readable kinds and
  parameters, so the UI can localise them.
- `vault`: the password vault, two files side by side.
  - `vault.kdbx` is a standard KeePass database (KDBX 4.1, Argon2id, ChaCha20). Its
    password is the *vault secret*: a random 256-bit recovery key, shown once, which
    also opens the file in KeePassXC.
  - `vault.keys` holds key slots: the secret encrypted with XChaCha20-Poly1305 under a
    key derived from the master password (Argon2id, 128 MiB) and, optionally, under a
    random device key kept in the OS credential store for Touch ID / Windows Hello.
    Losing it loses nothing: the recovery key opens the database and sets a new
    master password.
  - Entry summaries and details never contain a password or 2FA secret; those are
    read one at a time.
  - Every change is written atomically after a backup. Before each operation the
    vault re-reads a database changed elsewhere (a synced folder); a write over such
    a change fails with `conflict` and is kept as a separate copy.

Errors have a stable `code` (`wrong_passphrase`, `agent_unavailable`, …) that the UI
translates.

## src-tauri

- **Commands.** Thin `#[tauri::command]` wrappers that run core calls on the blocking pool
  and combine results for the UI. For example, `list_keys` joins keys with agent state and
  the hosts that use each key.
- **Process helpers.** Run `ssh -V`, `ssh-keyscan` and `ssh` without a console window and
  with timeouts.
- **Watcher.** Watches `~/.ssh` so changes made in a terminal appear immediately.
- **Vault runtime.** The unlocked vault lives only in the Rust process. A timer locks
  it after inactivity or sleep; each lock emits `vault-locked`. Copied passwords go
  from Rust to the clipboard, marked to stay out of clipboard history, and are
  cleared after a while.
- **Menu.** The macOS menu bar with keyboard shortcuts.

## UI

- React 19 with TypeScript (strict), Tailwind CSS 4 and Radix primitives for accessible
  dialogs, menus and switches.
- TanStack Query caches every command. Any change invalidates everything, which is cheap
  because all data is local.
- Every section sets `data-section`, which drives its accent colour through CSS variables.
- i18next with English, Russian and Uzbek. A test keeps the translations' keys and
  placeholders in sync.
- `pnpm dev` in a browser uses `src/mocks/backend.ts` instead of Tauri, so the UI can be
  built and reviewed without the native shell. Production builds never include it.
