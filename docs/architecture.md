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
- `hosts_file`: a lossless, editable model of the system hosts file (`/etc/hosts`,
  `%SystemRoot%\System32\drivers\etc\hosts`).
  - Commented-out entries count as turned off, and for each address family the first
    line that lists a name wins, as in resolvers.
  - Groups live between `# >>> sshkm: <name>` and `# <<< sshkm: <name>`, and
    `sshkm-until=<time>` in a comment marks a temporary entry.
  - Changes name lines of a revision (the file's SHA-256), so edits made elsewhere in
    the meantime are never overwritten.
  - `install` writes the file with administrator rights; see SECURITY.md.
- `agent`: a small synchronous client for the ssh-agent protocol.
  - Connects through a Unix socket (`SSH_AUTH_SOCK`), or on Windows a named pipe:
    `SSH_AUTH_SOCK` if it names one, else the OpenSSH agent's pipe.
- `perms`
  - Unix: checks and fixes file modes.
  - Windows: checks and fixes ACLs, using locale-independent SIDs through PowerShell and
    `icacls`.
- `audit`: pure rules over the data above. Findings carry machine-readable kinds and
  parameters, so the UI can localise them.

Errors have a stable `code` (`wrong_passphrase`, `agent_unavailable`, …) that the UI
translates.

## src-tauri

- **Commands.** Thin `#[tauri::command]` wrappers that run core calls on the blocking pool
  and combine results for the UI. For example, `list_keys` joins keys with agent state and
  the hosts that use each key.
- **Process helpers.** Run `ssh -V`, `ssh-keyscan` and `ssh` without a console window and
  with timeouts.
- **Watcher.** Watches `~/.ssh` and the hosts file so changes made in a terminal appear
  immediately.
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
