# Mobile app: Android first

The phone becomes one of the user's own devices: it holds the vault, syncs with the user's
computers over the local network, carries the vault (and hosts) to a new computer, fills
logins in other apps, and opens SSH sessions to the user's servers with a key of its own.
Android comes first; iPhone may follow on the same core.

Each step lands as its own pull request (or a few). A pull request that finishes a step
ticks it here, with its link.

## Decisions

Agreed with the user on 2026-11-16 and 2026-11-20.

- **Native UI, shared Rust core.** The UI is Kotlin with Jetpack Compose. The logic is the
  existing `sshkm-core` (vault, KDBX checks, Nearby protocol, three-way merge), reached
  through [UniFFI](https://mozilla.github.io/uniffi-rs/). No Kotlin Multiplatform for
  logic: a second implementation of the sync protocol and vault checks would have to match
  the first byte for byte and be audited twice. An iPhone app would use the same core
  through UniFFI's Swift bindings.
- **No Bluetooth.** Own devices sync over the local network with the protocol computers
  already speak (Noise `XXpsk0`, mDNS `v=2`, since 0.11.0). Where a network keeps devices
  apart (hotels, offices), the computer joins the phone's hotspot; that needs no code.
- **The phone is a full own device.** It keeps its own copy of the vault and its own sync
  snapshot per peer (`sync/<peer>.json`), so computer A ↔ phone ↔ computer B works through
  the existing three-way merge, deletions included. It edits entries, not only shows them.
  A new computer without a vault gets it from the phone the way it gets it from a computer
  today (the moved-vault flow), and sets its own master password.
- **The phone carries hosts and server keys too**: the host blocks and `known_hosts`
  entries computers sync (PR 1 of own-device sync), kept as text in the app's private
  storage. The terminal uses them; a new computer gets them from the phone.
- **The phone has its own SSH key; private keys never sync** (as for computers). The key is
  made in Android Keystore (StrongBox where the phone has it): P-256, never exportable,
  every new connection confirmed with the fingerprint or the screen lock. Ed25519 in
  Keystore needs a newer Android and isn't in StrongBox, so P-256 is the one kind.
- **SSH through `russh`**, not a bundled OpenSSH (Android doesn't let an app run programs
  from its own folder). Host keys are checked against the synced `known_hosts`; a different
  key stops the connection, as on computers; a new host shows its fingerprint and asks, and
  the answer syncs back. Of `ssh_config`, only HostName, User, Port, ProxyJump and keepalive
  options are honoured. ProxyCommand, LocalCommand, KnownHostsCommand and `Match exec` are
  never run (a host using them is marked "not available on the phone"), and agent
  forwarding is off. Passwords and one-time codes for servers come from the vault inside the
  process.
- **The terminal view** comes from Termux's `terminal-emulator` and `terminal-view`
  libraries (Apache 2.0), with a row of extra keys (Esc, Ctrl, Alt, Tab, arrows). Open
  sessions run in a foreground service with a notification.
- **Access follows the phone.** A computer that already reaches a server puts the phone's
  public key on it (the app's existing "install key", one screen with servers ticked,
  nothing changes on a server until "Add"). "Device lost" covers phones: revoking one
  removes its key from servers.
- **Where the code lives**: in this repository. `crates/sshkm-mobile` is the UniFFI crate;
  `mobile/android` is the Gradle project. A protocol change lands for computers and the
  phone in one pull request.
- **Android basics**: application id `dev.sshkeymanager.android`; minimum Android 10
  (API 29); UI text in English, Russian and Uzbek, as on computers; no third-party SDKs
  (no analytics, no crash reporting, no Firebase).

## Steps

Letters are the sessions that build them. A step starts once the steps it needs are merged.

| Step                                                 | Needs |
| ---------------------------------------------------- | ----- |
| A. Shared sync                                       | —     |
| B. Core on Android, UniFFI crate and the app's shell | —     |
| C. The vault on the phone                            | B     |
| D. SSH in the core                                   | B     |
| E. The phone as one of my devices: pairing and sync  | A, C  |
| F. Autofill                                          | C     |
| G. Environments and servers, to look at              | C     |
| H. The terminal                                      | C, D  |
| I. A new computer from the phone                     | E     |
| J. The phone's key on servers, and a lost phone      | E, H  |
| K. Release                                           | all   |

### A. Shared sync

Own-device sync runs in the desktop app today (`src-tauri/src/nearby`: `sync.rs`,
`pairing.rs`, `transfer.rs`, parts of `mod.rs`). Move the conversation (Hello, manifests,
vault copy, plan, decisions, apply, `agree`) into a crate both apps use, working over any
`Read + Write` stream (`p2p::Session` already does) instead of `TcpStream`, with what is
the app's business (asking the user, system dialogs, finding peers, files on disk) behind
traits. The desktop app's behaviour doesn't change; its tests keep passing, and the
conversation gets tests over in-memory pipes.

Done in [#75](https://github.com/nuriddin2468/ssh-key-manager/pull/75): the conversation is
`sshkm_core::p2p::conversation`, over any `p2p::connection::Connection`, and reaches the device
through `Side`: `User` (screens and system dialogs), `Device` (name, contacts, own devices, vault
proof) and `SyncStore` (host blocks and server keys, records, snapshots, the vault's entries).

### B. Core on Android, UniFFI crate and the app's shell

- `sshkm-core` builds for `aarch64-linux-android` and `x86_64-linux-android` (the
  emulator): what only computers use (ssh-agent, `~/.ssh` audit and permissions, the trash,
  browser import, shell history, terminals, `.env` files on disk) goes behind features that
  the desktop app turns on. `target_os = "android"` isn't `"linux"`; check each `cfg`.
- `crates/sshkm-mobile`: the UniFFI crate the app calls, with a narrow API that grows step
  by step. The generated scaffolding needs `unsafe`; the crate opts out of the workspace's
  `forbid` for it alone, as `sshkm-core` does for its five modules.
- `mobile/android`: the Gradle project (Kotlin, Compose, Material 3), building the Rust
  library with `cargo-ndk`, with an empty first screen that calls into the core.
- The app's security basics from the start: `FLAG_SECURE` on every window, no Android
  backup of app data (`allowBackup="false"` and data extraction rules that exclude
  everything), no permissions beyond what a step needs.
- CI builds the APK and runs the Android checks.

### C. The vault on the phone

Opening a vault the phone has (it gets one in E; until then a test vault), unlocking with
the master password and with the fingerprint (a key slot whose key lives in Keystore,
invalidated when a new fingerprint is enrolled), lock after a timeout and when the app
leaves the screen for long; logins: list, search, view, edit, add, delete; one-time codes;
the password generator. Copy marks the clipboard as sensitive and clears it after a time.
Secret fields turn off the keyboard's learning.

### D. SSH in the core

A client on `russh` in the core: connect by host alias from the carried host blocks
(the whitelist above), ProxyJump chains through direct-tcpip channels, host key check
against the carried `known_hosts` with the same rules as computers, authentication with a
key whose signing is done outside the core (Keystore, through a UniFFI callback), with a
password or keyboard-interactive answers from the vault, and one-time codes. A session
gives the app bytes in and out and a resize call. No UI.

### E. The phone as one of my devices: pairing and sync

The computer shows a QR code for "Add a device"; the phone scans it and the two pair as
own devices (the code-compare rules of own-device pairing still hold; the QR carries what
the six digits carry today). Sync over Wi‑Fi from the phone's Devices screen: vault
entries, host blocks, `known_hosts`, device and project records, with the conflict and
mass-deletion reviews computers have. The phone finds computers through mDNS (Android's
multicast lock) and is reachable only while its sync screen is open.

### F. Autofill

An Android Autofill service that offers the vault's logins in other apps and in browsers,
matching web domains with the same rules as the browser extension and apps by package name
and signing certificate; filling needs the vault unlocked.

### G. Environments and servers, to look at

Environments (variables, values one at a time, copy) and servers (hosts the phone carries,
their server keys), read only.

### H. The terminal

The phone's key (made on first use, in Keystore), the terminal screen on D, extra keys,
copy and paste, several sessions, the foreground service, reconnect after the network
changes.

### I. A new computer from the phone

A computer without a vault gets the vault, hosts and server keys from the phone (the
moved-vault flow, confirmed on the phone with the fingerprint).

### J. The phone's key on servers, and a lost phone

The phone's public key reaches computers with its device record; a computer offers to put
it on the servers it reaches. "Device lost" for a phone removes its key from servers and
renews the own-device key, as for a computer.

### K. Release

Where the app is published (Google Play, the APK in GitHub Releases, F-Droid), its signing
key and release notes are decided with the user before this step.

## How each step is built

- UI work uses the design skills (`design:design-system`, `design:ux-copy` for en/ru/uz,
  `design:accessibility-review`, `design:design-critique`); the pull request says which ran.
- Rust checks as for the desktop app: `cargo fmt`, `cargo clippy --all-targets -- -D
  warnings`, `cargo test`. Android checks: `./gradlew lint test assembleDebug` in
  `mobile/android`, and the Rust library built for Android.
- A change computers' users see adds a note in `changelog/unreleased/` (see
  `changelog/README.md`). Changes only the phone shows add none until step K decides how
  the phone's release notes work.
- Checked on the emulator and on a real phone over USB; sync steps with a computer on the
  same Wi‑Fi.
- Secrets reach the UI one at a time, when the user asks, and are never logged.
