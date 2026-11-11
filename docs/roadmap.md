# Roadmap: projects and environments

Where the app goes after the in-app terminal and secret environments: a **project**
gathers everything one piece of work needs — its SSH hosts and keys, vault logins,
environments and their `.env` files, local folders and terminal — and the app becomes the
one place that manages and syncs those `.env` files, locally, without a cloud.

Each step lands as its own pull request (or a few). A pull request that finishes a step
ticks it here, with its link.

## Decisions

- **Audience: the broad public.** Individual developers first, small teams next. No
  server, no account: the vault, the local network (Nearby) and Git carry everything.
- **Keep `.env` files; manage them.** The app is the source of truth and writes the files
  projects need, keeping them in sync both ways: an edit in an editor (or by an AI agent)
  lands in the vault, a change in the app lands in every file that uses it. Every tool,
  IDE and operating system keeps working.
- **Environments are `local` or `remote`.** `local` is the developer's own machine (what
  "dev" meant in the discussion). `remote` is everything else: a shared dev server,
  staging, production.
- **Protection levels per project**, chosen per environment file:

  | Level                               | On disk                                                      | Systems      | Default for |
  | ----------------------------------- | ------------------------------------------------------------ | ------------ | ----------- |
  | 1. File always                      | a regular `.env`                                             | all          | `local`     |
  | 2. File while the vault is unlocked | written on unlock, wiped on lock, sleep and quit             | all          | —           |
  | 3. Virtual file                     | nothing: a named pipe (FIFO) the app answers                 | macOS, Linux | —           |
  | No file                             | nothing; used through the app's terminal ("Run in terminal") | all          | `remote`    |

  A `remote` environment gets a file only when the user chooses level 2 for it, with a
  warning.
- **No CLI, no shell hook and no MCP server for now.** Files are the only channel; agents
  read them like any other tool. Agent protection rests on the agents' own ignore rules
  (added with consent) and on the leak scanner. MCP may come back later as an add-on.
- **Projects are labels, not folders.** An item can belong to several projects (a shared
  bastion, one GitHub key). **Personal** is everything in no project; it is never shared.
- **Projects are the main navigation.** A project's page is where things are _used_
  (connect, copy, run, open a terminal in its folder); the type sections — Keys, Hosts,
  Passwords, Environments — become a library where things are _managed_. Projects must
  replace navigation, not add a dimension next to it.
- **Projects are suggested, not built by hand**: from environments' project names, Git
  folders and remotes, `ProxyJump` chains, host name prefixes and domains, KeePass groups.

## Steps

### 1. Choose the shell — done ([#33](https://github.com/nuriddin2468/ssh-key-manager/pull/33))

Local shells in the Terminal (Local shell, New session → This computer) and for
Environments' Run in terminal: PowerShell 7, Windows PowerShell, Command Prompt, Git Bash
and WSL distributions on Windows; the user's shell, `/etc/shells` and Homebrew's on macOS
and Linux. Settings → Terminal → Default shell. `src-tauri/src/terminal/shells.rs`.

### 2. Projects — in review

The foundation for everything below.

1. **Model and storage** (`sshkm-core`): a project has a name, a color, folders, and
   members by reference — hosts by alias, keys by fingerprint, vault entries by KeePass
   tag, environments by their existing `Environments/<project>` group. Kept in the vault,
   so it syncs to the user's devices with it; a copy without secrets (names and
   references) shows projects while the vault is locked, as the SSH sections work then.
   Nothing is written into `~/.ssh/config` for membership. Done:
   [#34](https://github.com/nuriddin2468/ssh-key-manager/pull/34).
2. **Suggestions**: the app proposes projects from what it finds (see Decisions); the user
   confirms each. Done:
   [#35](https://github.com/nuriddin2468/ssh-key-manager/pull/35).
3. **Navigation and the project page**: projects (Personal first) at the top of the
   sidebar, the library below, system sections last. The project page: hosts (connect),
   environments (file state, run), logins (copy), keys (in the agent or not), folders
   (open a terminal there, in the default shell, with the `local` environment), tunnels,
   audit findings for the project. Adding items to a project from the library. Done:
   [#37](https://github.com/nuriddin2468/ssh-key-manager/pull/37).
4. **Project page polish**: cards show five rows, problems first, and Show all for the
   rest; two columns that don't push each other down; an item's name opens it in its
   Library section, with a way back to the project; Add also makes a new host, key, login
   or environment in the Library's own dialogs, and it joins the project; a project folder
   can be shown in Finder, Explorer or Files (the backend checks it is the project's). In
   review:
   [#39](https://github.com/nuriddin2468/ssh-key-manager/pull/39).
5. **Hosts file entries in projects**: a project holds names of the system hosts file
   (`hostsfile:<name>`, synced like its other members); its page shows their entries, name
   → address, each turned on or off through the hosts file's own review, admin rights and
   backups, and flags a name the file no longer has. Added from the Add menu or a Hosts
   file entry's menu; suggested from the names and domains of the project's hosts. One
   switch turns all of a project's entries on or off: one review that names what else it
   touches, one password, Undo through the backup. Lines that also list a system name
   (`127.0.0.1 localhost app.test`) are left as they are. Not yet: a name renamed in the
   Hosts file section isn't followed; the project flags the old one as gone. In review:
   [#41](https://github.com/nuriddin2468/ssh-key-manager/pull/41).

### 3. Managed `.env` files — in progress

Environments get files, inside projects. Core, commands and mocks (local or remote,
bindings, safe writes, lossless editing, two-way sync, the management center's data):
[#38](https://github.com/nuriddin2468/ssh-key-manager/pull/38). The UI (file bindings in
the Environments pane, the Files view, Undo, conflicts) in review:
[#40](https://github.com/nuriddin2468/ssh-key-manager/pull/40); the file-state line on the
project page follows 2.4.

- Bindings: environment → file(s) in the project's folders (`.env`, `.env.local`,
  `.env.development.local`…; several in a monorepo).
- Safe writes: atomic, owner-only permissions, never through a symbolic link, only inside
  the project's folder. Not ignored by Git → offer to add the line to `.gitignore`.
- Two-way sync: a file watcher picks up edits (editors that save by renaming included) and
  saves them to the vault with Undo; the app's changes rewrite the files. Edits change only
  the lines they touch — comments, order, quoting and `export` stay byte for byte. Both
  sides changed → the compare dialog. Files changed while the app was closed are caught
  at start by their hash. A removed line removes the variable, with Undo and the entry's
  history.
- Management center: per project and overall — files that differ from the vault, missing
  variables against `.env.example`, files Git doesn't ignore, files in cloud-synced
  folders, unmanaged `.env` files found on disk with "Take under management".

### 4. Protection

1. **Leak scanner — done** ([#36](https://github.com/nuriddin2468/ssh-key-manager/pull/36)): the vault knows the exact values, so it
   finds them without false positives — secret variables and entry passwords, as they are,
   escaped in JSON, percent-encoded or in base64, a private key by its lines; values too
   short or plain to mean anything are skipped. In AI tools' session history (Claude Code,
   Codex, Gemini CLI, Continue, Cline, Roo Code, Aider), the shell history, and folders the
   user picks: what Git would commit there, and `.env` files anywhere. In Audit, with
   rotation as the advice, Show file, and Redact in place for AI session files. No
   pre-commit check while there is no CLI. Cursor's chats (SQLite) aren't read yet.
   `crates/sshkm-core/src/leaks`, `src-tauri/src/commands/leaks.rs`.
2. **Level 2** (file only while unlocked), exclusion from backups where the system allows
   it (Time Machine, Dropbox), agents' ignore rules added with consent, and **shared
   secrets**: one value used by several environments, so changing a key once updates
   every file.
3. **Level 3**, the virtual `.env` on macOS and Linux: the app always in the tray; at once
   a placeholder when the vault is locked, never a hang; pipes removed on quit; one full
   answer per open; a list of tools it was checked with.

### 5. Teams

1. **Project file in the repository** (no secrets): hosts (HostName, User, Port,
   ProxyJump), their host key fingerprints, environment and variable names. Cloning a repo
   offers to add the hosts and trust their keys — no blind first connection. Risky options
   (`ProxyCommand`, `LocalCommand`, `Match exec`…) are refused (`config/risky.rs`).
2. **Share a project** with a colleague: through Nearby, or encrypted to their SSH public
   keys (age format) and committed to the repository.

### Later, maybe

- MCP server for AI agents (list, run without seeing values, ask the human for a value).
- CLI (`sshkm run`) and a shell hook.

## How each step is built

- UI work uses the design skills: `design:design-system` before building,
  `design:ux-copy` for wording (en, ru, uz), `design:accessibility-review` and
  `design:design-critique` on the result. The pull request says which ran.
- A user-visible change adds a note in `changelog/unreleased/` (see `changelog/README.md`);
  behaviour that changes on update without asking is a `notice`.
- Every command the page calls is registered in `src-tauri/build.rs` and `lib.rs` and has
  a mock in `src/mocks/` so the browser preview works; the change is checked there.
- Checks before a pull request: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test`, `pnpm lint`, `pnpm typecheck`, `pnpm test`,
  `node scripts/changelog.mjs check`.
- Files the app writes or reads are named by the user (dialogs, bindings they made), never
  by the page; secrets reach the UI one at a time, when the user asks.
