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
- `vault`: the password vault, two files side by side.
  - `vault.kdbx` is a standard KeePass database (KDBX 4.1, Argon2id, ChaCha20). Its
    password is the _vault secret_: a random 256-bit recovery key, shown once, which
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

- `browser`: what the browser extension may see of the vault.
  - `origin` matches a login's address to a page: the same registrable domain (Public
    Suffix List), exactly; `https` logins stay off `http` pages; ports must agree.
  - `channel` pairs a browser (P-256 ECDH, HKDF-SHA-256) and seals every later message
    with AES-256-GCM, using only what WebCrypto offers. `channel-vectors.json` is shared
    with the extension's tests so both sides compute the same bytes.
  - `protocol` is the JSON. Paired browsers live in the vault's custom data.

Errors have a stable `code` (`wrong_passphrase`, `agent_unavailable`, …) that the UI
translates.

## src-tauri

- **Commands.** Thin `#[tauri::command]` wrappers that run core calls on the blocking pool
  and combine results for the UI. For example, `list_keys` joins keys with agent state and
  the hosts that use each key.
- **Process helpers.** Run `ssh -V`, `ssh-keyscan` and `ssh` without a console window and
  with timeouts.
- **Askpass.** The app executable doubles as `ssh`'s `SSH_ASKPASS` program, so `ssh` can
  ask for a password, one-time code or key passphrase without a terminal.
  - `main` runs the helper before Tauri starts when `SSHKM_ASKPASS_*` is set: it sends the
    prompt to the running app and prints the reply.
  - The app listens on a Unix socket in a private (0700) temp directory, or on a named
    pipe with a random name that rejects remote clients.
  - Each `ssh` run gets a session with a one-time 256-bit token and the caller's secrets.
    In a batch session (connection tests, installing a key) yes/no questions (an unknown
    host key) are always answered "no", each secret is given at most once, and prompts
    naming another account are refused.
  - An interactive session (the terminal) hands host-key questions, secrets asked again
    and other accounts' prompts to its responder too, saying which they are; other yes/no
    questions still get "no".
- **Terminal.** `src-tauri/src/terminal/`: one pseudo-terminal per session (`portable-pty`,
  ConPTY on Windows) running `ssh -o ConnectTimeout=10 -- <alias>`.
  - Output goes to the UI over a `tauri::ipc::Channel` as raw bytes; state changes and
    prompts go over the same channel as JSON events. Input, resizing, answers and closing
    are commands (`terminal_*`).
  - The prompt bridge answers from the vault once, then asks the user (five minutes at
    most) and saves answers the user chose to save after signing in.
  - A session is connected once `ssh` puts the terminal in raw mode (macOS, Linux), or
    on the first output after the last prompt that isn't `ssh`'s own (Windows). Exiting
    before that is a failure with a reason read from the prompts and `ssh`'s output.
  - Sessions end when the app quits or the page reloads; locking the vault doesn't end
    them.
- **Browser autofill.** `src-tauri/src/browser/`.
  - The app executable doubles as the extension's native messaging host: `main` runs
    it when a browser starts the executable with the extension's origin. It relays
    JSON to the app and never sees a secret in the clear.
  - While autofill is on, the app listens on a private socket or pipe, writes where to
    `browser-endpoint` in its local data folder, and keeps the browsers' host manifests
    pointing at itself.
  - The broker pairs a browser after the user's yes in a dialog, then answers sealed
    requests: logins for a page, the one picked, and saving or updating a typed login.
    It reaches the app through a small `Env` trait, so its tests run against a real
    vault without Tauri, and `examples/autofill_bridge.rs` serves a throwaway vault
    to the extension's end-to-end test.
- **Watcher.** Watches `~/.ssh` and the hosts file so changes made in a terminal appear
  immediately.
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
- The Terminal's sessions and their xterm.js instances live in a provider above the pages,
  so they keep running and keep their scrollback while other sections show. xterm uses
  its DOM renderer on Linux (WebKitGTK often renders on the CPU) and WebGL elsewhere.
- i18next with English, Russian and Uzbek. A test keeps the translations' keys and
  placeholders in sync.
- `pnpm dev` in a browser uses `src/mocks/backend.ts` instead of Tauri, so the UI can be
  built and reviewed without the native shell. Production builds never include it.

## Browser extension

`extension/`: Manifest V3, plain TypeScript, built by `extension/build.mjs` into
`extension/dist/chromium` and `extension/dist/firefox`.

- The background script is the only part that talks to the app for pages, and names each
  page by the origin the browser reports for the sending frame.
- The content script finds login fields, shows the saved logins in a menu in a closed
  shadow root, fills the one picked and passes sent login forms to the background, which
  offers to save them in a banner on the next page.
- The popup shows the connection state; the connect page pairs the browser. Keys stay in
  IndexedDB as non-extractable WebCrypto keys.
