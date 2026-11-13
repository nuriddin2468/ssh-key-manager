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
  - `convert` turns a key into another format (OpenSSH, PuTTY `.ppk` v2 and v3 in
    `ppk`, PEM, PKCS#8), encrypted ones included, and shows its SHA-256 and MD5
    fingerprints and randomart (`randomart`, as `ssh-keygen -lv` draws it).
- `config`: a lossless model of `ssh_config`.
  - Unmodified files round-trip byte for byte.
  - Edits change only the lines they touch.
  - New hosts go before a trailing `Host *` block, because the first match wins.
  - `jump` sets `ProxyJump` in several blocks at once, refusing circles.
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
  - Unix: checks and fixes file modes. On macOS it also empties a folder's access list
    (`perms/extended_acl.rs`, through the system library), for the private folders
    `fsutil` makes files in.
  - Windows: checks and fixes ACLs, using locale-independent SIDs through PowerShell and
    `icacls`. It also creates files meant for plain-text secrets (exports, converted
    keys) with a protected access list already in place, through Win32
    (`perms/private_file.rs`). These two modules, the Unix part of
    `vault/envs/files/pipes.rs` and the Windows part of `vault/envs/files/folder.rs`
    are the crate's only `unsafe` code.
- `fsutil`: atomic writes. Files in `~/.ssh` and the app's data folder are written
  through links (`atomic_write`; `atomic_write_private` for a private key, which keeps
  only its owner's permissions); secrets written where the user picks are never written
  through a link and are private from their first byte (`write_private`). On macOS a
  file for the user alone is made in a new folder of its own whose access list hands
  nothing down, then renamed into place (`fsutil/private_folder.rs`, through `rustix`).
- `audit`: pure rules over the data above. Findings carry machine-readable kinds and
  parameters, so the UI can localise them.
  - `audit/config_risks.rs` reads `ssh_config` settings (host key checking, agent
    forwarding, `IdentitiesOnly` against the number of agent keys) and applies the
    fixes it offers, and only those (`apply_config_fix`).
- `diagnose`: why an `ssh` run failed, read from what it printed (with `-v` for
  connection tests): a cause, the jump host it happened at, and the lines that show
  it. Its tests run over real OpenSSH output from macOS, Linux and Windows
  (`diagnose/testdata`). `probe` checks that a TCP port answers.
- `tunnels`: saved port forwards (local, remote, SOCKS), checked before anything
  reaches `ssh`, and the `ssh -N` arguments of each.
- `authorized_line`: one `authorized_keys` line with options (`restrict`, `from=`,
  `command=`, `expiry-time=`, the `no-…` flags), read back as `sshd` reads it.
- `vault`: the password vault, two files side by side, and the password generator
  (with the Tools page's presets: database, shell and `.env` passwords, tokens, UUIDs,
  framework keys, Wi-Fi passwords, passphrases and PINs).
  - `vault.kdbx` is a standard KeePass database (KDBX 4.1, Argon2id, ChaCha20). Its
    password is the _vault secret_: a random 256-bit recovery key, shown once, which
    also opens the file in KeePassXC.
  - `vault.keys` holds key slots: the secret encrypted with XChaCha20-Poly1305 under a
    key derived from the master password (Argon2id, 128 MiB) and, optionally, under a
    random device key kept in the OS credential store for Touch ID / Windows Hello.
    Losing or damaging it loses nothing: the recovery key opens the database and sets
    a new master password (a damaged file is kept aside; one from a newer app version is
    left alone). Master password checks run one at a time, and after a few
    wrong ones in a row the next waits a little (`vault/attempts.rs`).
  - Entry summaries and details never contain a password or 2FA secret; those are
    read one at a time.
  - `breach` checks passwords against Have I Been Pwned with k-anonymity: it makes
    the SHA-1 range prefixes to ask for and matches the answers, without networking,
    and keeps results under an HMAC of each password with a key held in memory.
  - Every change is written atomically after a backup. Before each operation the
    vault re-reads a database changed elsewhere (a synced folder); a write over such
    a change fails with `conflict` and is kept as a separate copy.
  - `envs`: secret environments, one entry per environment in
    `Environments/<project>`, a custom field per variable (protected when secret),
    marked by the entry's custom data. It reads `.env` files, guesses secrets, writes
    the export formats and compares two environments by value without returning
    values.
    - `envs::document` edits a `.env` file in place, as `config` does `~/.ssh/config`:
      an unchanged file comes out byte for byte, and a change touches only the lines
      of the variables it changes, keeping comments, order, quoting and `export`.
    - `envs::files` writes `local` environments to files in their projects' folders
      and keeps the two in step: a keyed revision per file and computer says which
      side changed; the file's edits go to the vault (with Undo from the entry's
      history), the vault's to the file; both changed is a conflict for the user.
      `files::disk` finds, reads and writes the files without following links or
      leaving the project's folder; `files::cloud` knows the cloud services' folders.

- `browser`: what the browser extension may see of the vault.
  - `origin` matches a login's address to a page: the same registrable domain (Public
    Suffix List), exactly; `https` logins stay off `http` pages; ports must agree.
  - `channel` pairs a browser (P-256 ECDH, HKDF-SHA-256; the extension commits to its
    key first, and the six-digit code covers both keys) and seals every later message
    with AES-256-GCM, using only what WebCrypto offers. `channel-vectors.json` is shared
    with the extension's tests so both sides compute the same bytes.
  - `protocol` is the JSON. Paired browsers live in the vault's custom data. One
    question goes unsealed and needs no pairing: whether two origins are the same site
    (`sameSite`), so the extension can keep a save offer on the site it came from.

- `net`: the Tools page's network checks, each blocking with a timeout; the tests run
  against loopback listeners.
  - `tcp` times connections (SSH ping) and tells open, closed and silent ports apart;
    `banner` reads the SSH server's version line and flags OpenSSH before 8.0.
  - `dns` is a small DNS client (UDP, TCP when the answer was cut) for A, AAAA,
    CNAME, MX and TXT, asking the servers of `/etc/resolv.conf` or, on Windows, the
    adapters' registry settings.
  - `tls` makes a rustls handshake that records the chain and the system verifier's
    verdict (`rustls-platform-verifier`) instead of enforcing it; `x509` reads the
    names, issuer and dates out of each certificate.

- `p2p`: two copies of the app talking over the local network, without the network
  itself, so the tests run over loopback sockets.
  - `identity` is the device's Curve25519 key pair.
  - `session` runs a Noise `XX` handshake over any byte stream, sends length-framed
    JSON messages, and agrees on the six-digit pairing code with a hash commitment
    (see SECURITY.md).
  - `protocol` is the messages. Contacts live in the vault's custom data
    (`vault::contacts`), and so do the user's own devices (`vault::own_devices`).
  - `own` tells whether two computers have the same vault (a proof bound to the
    session) and makes the names own devices announce themselves under, both from a
    random key the vault keeps (`sshkm.own.key`).
  - Large values (a vault file, a long manifest) go as their size and SHA-256, then
    in parts, so a message never passes 1 MiB.

- `sync`: keeping the user's own computers in step.
  - `merge` is a three-way merge of items made of fields, against a snapshot of keyed
    hashes of what both had after their last sync: what only one side changed goes
    its way, what both changed differently is a conflict.
  - `hosts` makes the items from `ssh_config` (`Host` blocks for single names, without
    what belongs to the computer) and applies changes, keeping the computer's own
    options in place and new blocks before `Host *`.
  - `host_keys` collects the server keys for those hosts and adds the other's where
    there are none, reporting different keys of one type.

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
- **Managed `.env` files.** `src-tauri/src/env_files.rs` runs a round of keeping files
  in step after every change of the vault (here, an unlock, or its file changed by
  another computer) and after a bound file changes: it watches the folders of the
  bound files for their names, so editors that save by renaming are seen. A round
  saves the files' edits to the vault first, then writes files, and tells the UI with
  `env-files-changed`. The revisions are kept in `env-files.json`. A file is read,
  written, made a pipe or removed through its folder, opened once and checked as it
  was opened (`vault/envs/files/folder.rs`: `openat`/`renameat` relative to that
  folder on macOS and Linux; on Windows the folder is held open, not to be renamed
  or deleted, and checked by its handle's path). A new file or pipe is made where
  it waits and then renamed into place: on macOS in a private folder of its own
  inside that folder (`fsutil/private_folder.rs`), on Linux under a temporary name
  in it.
  - A file kept only while the vault is unlocked (level 2) is written by the round
    after an unlock and removed before the vault locks (`VaultHooks::before_lock`
    runs one last round first) and when the app quits. Each round lists those files,
    as they are on disk (identity, size, time; no values), in
    `env-files-unlocked.json`, and lists each write there before it makes it (the
    file's temporary files, and a level-2 file as it will be); a file still as listed
    is removed, one edited since stays until the next unlock. A crash or a forced
    quit is caught by the guard
    (`src-tauri/src/env_guard.rs`): the app's own executable run with
    `--sshkm-env-guard`, which sweeps the list when the pipe from the app closes; the
    next start sweeps it too. Level-2 files get the Time Machine, Dropbox and File
    Provider exclusion attributes on their temporary file, before it holds anything.
  - Shared values (`vault/envs/shared.rs`): a value several environments use is a
    KeePass entry of its own (`sshkm.shared`, under `Environments/Shared`); a variable
    that uses it holds the KeePass field reference `{REF:P@I:<uuid>}`. The value
    lives in one entry, so merging entries converges; references are resolved
    wherever values leave the vault (files, terminal, exports, leak scanner, another
    computer), and an edit of a shared variable, in the app or a file, changes the
    shared entry, with Undo covering it.
  - AI tools' ignore rules (`files/agents.rs`, `commands/env_agents.rs`): with the
    user's yes for a project folder, each chosen tool's file gets a line per managed
    file where that tool reads it: `.cursorignore` and the like in the folder,
    `.aiderignore` at the top of the Git working tree, Claude Code's
    `permissions.deny` in the user's `~/.claude/settings.json` by full path (keys and
    line ends kept). The choice is kept per folder in `agent-rules.json` and followed
    for files bound or taken under management there later.
- **Terminal.** `src-tauri/src/terminal/`: one pseudo-terminal per session (`portable-pty`,
  ConPTY on Windows) running `ssh -o ConnectTimeout=10 -- <alias>`, or the user's own
  shell with a secret environment's variables in its environment (`local.rs`).
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
    pointing at itself: at the AppImage under an AppImage, and never at a temporary
    folder. On Windows the host checks who serves the pipe before it sends anything.
  - The broker pairs a browser after the user's yes in a dialog, then answers sealed
    requests: logins for a page, the one picked, and saving or updating a typed login.
    It reaches the app through a small `Env` trait, so its tests run against a real
    vault without Tauri, and `examples/autofill_bridge.rs` serves a throwaway vault
    to the extension's end-to-end test.
  - When the extension asks to unlock the vault, the app asks with Touch ID or
    Windows Hello, else in a small window of its own (`browser/unlock.rs`,
    `unlock.html`) whose capability allows only the unlock commands; the main
    window stays hidden.
  - A login fills a page only after the user allowed it, in Touch ID, Windows Hello
    or a native dialog (`browser/prompt.rs`); the yes lasts for the vault runtime's
    session, which ends when the vault is locked by hand, the screen locks or the
    computer sleeps. Each browser's keys change daily; the retired ones stay in the
    vault, so a request sealed with a copy of them revokes the pairing (as does one
    sealed with new keys that a second key change replaced before their first use).
- **Nearby.** `src-tauri/src/nearby/`.
  - Announces the device with mDNS for ten minutes when asked, and browses for
    others while the Nearby page is open (`mdns-sd`).
  - Pairs one device at a time, from either side, on its own thread. `pairing::converse`
    is the whole conversation; it reaches the app through a small `Side` trait, so its
    tests run two sides over loopback without Tauri.
  - `items` reads what is sent and saves what is received. A hosts file group waits
    in memory until the Hosts file page adds it to its draft (`nearby_received_group`)
    and shows the review; a public key goes to `~/.ssh` through `keys::add_public`,
    and its fingerprint to `nearby.json`, which the audit reads (`AuditInput::others`).
  - Every change goes to the UI as `nearby-changed` with the whole status.
  - `own` adds one of the user's devices after the code: the user confirms, both are
    recorded, and a computer without a vault gets it, held in memory until its user
    sets a master password (`Vault::join`).
  - `presence` announces this computer to the user's devices while the vault is
    unlocked, on a port that only takes a sync, and finds theirs.
  - `sync` is a sync's conversation: manifests both ways, each side's plan, the
    decisions of the user who started it, writing, and agreeing on the next snapshot,
    which `store` keeps per device in `sync/` in the app's data folder.
  - `examples/nearby_peer.rs` stands in for another computer, also as a new one
    (`--join`) and as one of the user's devices (`--sync`).
- **Watcher.** Watches `~/.ssh` and the hosts file so changes made in a terminal appear
  immediately.
- **Vault runtime.** The unlocked vault lives only in the Rust process. A timer locks
  it after inactivity (time asleep counts) or sleep; each lock emits `vault-locked`.
  Copied passwords go from Rust to the clipboard, marked to stay out of clipboard
  history, and are cleared after a while, when the vault locks and when the app quits.
- **Breach check.** `commands/audit_checks.rs`, off until the user turns it on. The
  vault audit starts it in the background for passwords without a result; it asks
  `api.pwnedpasswords.com` for one range at a time (reqwest, the updater's TLS), and
  its results are dropped on `vault-locked`. The page polls `breach_status`.
- **Menu.** The macOS menu bar with keyboard shortcuts.
- **Tunnels.** `src-tauri/src/tunnels/`: the Tools page's port forwards, defined in
  `sshkm_core::tunnels` and kept in `tunnels.json` in the app's data folder.
  - One supervisor thread per tunnel that is on runs `ssh -N` with the forward,
    `ExitOnForwardFailure` and `ServerAliveInterval`, its prompts answered by the
    terminal's prompt bridge through an interactive askpass session.
  - `LogLevel=VERBOSE`'s `Authenticated to …` line tells when signing in is done;
    `failure` reads why `ssh` stopped. With auto-reconnect a tunnel starts again
    after a growing wait, unless what stopped it needs the user.
  - Every change goes to the page as `tunnels-changed`, and to the tray menu. Tunnels
    stop when the app quits.
- **Quick search.** `src-tauri/src/quick/`: a system-wide shortcut
  (`tauri-plugin-global-shortcut`, saved in `quick.json`) or the tray menu opens a
  small window (`quick.html`, `src/quick/`) that connects to a host, copies through
  `vault_copy` and unlocks the vault; its capability allows only that. Starting the
  app with `--quick-search` opens it too, in the running app if there is one. Escape or a
  copy gives the focus back to the app that was in front (`sshkm_os::focus` on
  macOS).
- **Tray.** `src-tauri/src/tray/`: with **Settings → Background** on, closing the window
  hides it and an icon in the tray (the menu bar on macOS) stays. Its menu shows the
  vault's state and locks it, counts the tunnels that are on and stops them, connects
  to recent hosts, names a Nearby conversation waiting for the user, opens quick
  search, and quits. One worker rebuilds the menu when the vault, `~/.ssh`, a tunnel or
  Nearby change, or the language does. On Linux the icon needs the AppIndicator
  library, which `sshkm_os::tray` checks for first.
- **Open at login.** `src-tauri/src/autostart.rs`, through `auto-launch`: a launch agent
  on macOS, the `Run` key (current user) on Windows, an XDG autostart entry on Linux,
  each starting the app with `--autostart`. Started so, with the tray icon there, the
  app starts without its window (it is `visible: false` in `tauri.conf.json`, and
  `setup` shows it otherwise). Turning it on also turns on Background. Nothing is saved:
  the status is the system's entry, plus on macOS whether System Settings → Login Items
  lets it run (`sshkm_os::login_item`).
- **Permissions.** `build.rs` lists every command, so each gets a Tauri permission and a
  window calls only what its capability names: the main window all, the unlock window
  three, the quick search window seven. Of Tauri's own and the plugins' commands the main
  window gets only what its page uses (listening to events, dragging and maximising the
  window, opening http(s) links, writing the clipboard), not `core:default`; files are
  picked in dialogs and shown in the file manager by app commands
  (`commands/reveal.rs`), which find the path themselves.

## UI

- React 19 with TypeScript (strict), Tailwind CSS 4 and Radix primitives for accessible
  dialogs, menus and switches.
- TanStack Query caches every command. Any change invalidates everything, which is cheap
  because all data is local.
- Every section sets `data-section`, which drives its accent colour through CSS variables.
- The Terminal's sessions and their xterm.js instances live in a provider above the pages,
  so they keep running and keep their scrollback while other sections show. xterm uses
  its DOM renderer on Linux (WebKitGTK often renders on the CPU) and WebGL elsewhere.
  Links open on ⌘-click (Ctrl-click) and show their target while pointed at; pasted
  text loses its control characters before it reaches xterm (`features/terminal/screen.ts`).
- Nothing in the page parses text as HTML; a test (`src/test/textOnly.test.ts`) refuses
  HTML sinks in the app and the extension.
- i18next with English, Russian and Uzbek. A test keeps the translations' keys and
  placeholders in sync.
- The command palette (⌘K / Ctrl+K, `src/features/palette/`) searches hosts, keys,
  the unlocked vault's entries, pages, actions and tools: exact matches first, then
  prefixes, then the rest, recently run items first within each. `>`, `@` and `#`
  narrow it to actions, hosts or passwords. The quick search window uses the same
  search and list.
- `pnpm dev` in a browser uses `src/mocks/backend.ts` instead of Tauri, so the UI can be
  built and reviewed without the native shell. Production builds never include it.

## Browser extension

`extension/`: Manifest V3, plain TypeScript, built by `extension/build.mjs` into
`extension/dist/chromium` and `extension/dist/firefox`.

- The background script is the only part that talks to the app for pages, and names each
  page by the origin the browser reports for the sending frame.
- The content script finds login fields, shows the saved logins in a menu in a closed
  shadow root (on a plain `div` popover, so a page can't define the element; titles and
  usernames are CSS generated content, which find-in-page doesn't search), fills the
  one picked and passes sent login forms to the background, which offers to save them in
  a banner on the next page (naming only the site, if that page is another site's). It
  reacts only to trusted events, opens the menu only on the user's own click, Tab or
  Down Arrow (and over a password already filled in, only on Down Arrow), and passes on
  only logins whose password the user typed (or the extension
  filled) and that the user sent. A menu item or banner button counts only once the
  surface has been shown, uncovered, unscaled and untouched by the page, for half a
  second.
- The popup shows the connection state and can turn off the browser's own password
  suggestions (the optional `privacy` permission); the connect page pairs the browser.
  Keys stay in IndexedDB as non-extractable WebCrypto keys.
