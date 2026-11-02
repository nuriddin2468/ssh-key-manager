# sshkm-os

OS integration for SSH Key Manager's password vault: a small, synchronous API
over screen-lock events, biometrics and the system credential store. It does
not depend on Tauri or on `sshkm-core`.

```rust
use sshkm_os::{biometrics, screen_lock, secret_store, SecretString};

let _watcher = screen_lock::watch(|| vault.lock())?;      // stops when dropped
if biometrics::availability().is_available() {
    biometrics::authenticate("unlock the password vault")?; // blocks
}
secret_store::set("dev.sshkeymanager.desktop", "vault", &SecretString::from(key))?;
let key = secret_store::get("dev.sshkeymanager.desktop", "vault")?; // Option<SecretString>
secret_store::delete("dev.sshkeymanager.desktop", "vault")?;        // Ok if missing
```

Calls that can wait for the user (the biometric prompt, a keychain access
dialog, unlocking a Secret Service collection) block, so call them from a
worker thread. Errors are one `Error` enum with a stable `code()`
(`unsupported`, `unavailable`, `cancelled`, `failed`, `store`); messages never
contain secrets.

## Platforms

| | macOS | Windows | Linux |
|---|---|---|---|
| `screen_lock` | `com.apple.screenIsLocked` distributed notification | `WTS_SESSION_LOCK` on a hidden message-only window of its own thread | logind `Lock` signal and `LockedHint`; fallback: `org.freedesktop.ScreenSaver` / `org.gnome.ScreenSaver` `ActiveChanged` |
| `biometrics` | Touch ID only (no password, no Apple Watch) | Windows Hello (face, fingerprint or PIN) | unavailable |
| `secret_store` | regular login keychain (not the data-protection keychain) | Credential Manager, persisted on this computer only | Secret Service (GNOME Keyring, KDE Wallet, KeePassXC, …) |

Notes:

- **macOS screen lock** is delivered through the main thread's run loop,
  whichever thread called `watch`. The app's `NSApplication` runs it; a
  command-line program must run it itself (see `examples/watch_lock.rs`). The
  callback runs on a private serial queue.
- **Linux screen lock** works with desktops that tell logind about the lock
  (GNOME, KDE, Cinnamon, MATE, Xfce, light-locker). Lockers that report
  nothing (swaylock, i3lock) are not noticed. The callback may run twice for
  one lock; make it idempotent.
- **macOS biometrics** need no `Info.plist` key: `NSFaceIDUsageDescription` is
  for Face ID on iOS and iPadOS only. The dialog reads "*App* is trying to
  *reason*."
- **Windows biometrics**: the prompt comes from `robius-authentication`, which
  owns it to the desktop window (not the app's window) and then pulls it to
  the foreground. Availability is checked first, so that crate's
  username/password fallback is never shown.
- **macOS keychain**: items are tied to the code signature of the app that
  created them. Without a Developer ID signature, every update looks like a
  different app, and macOS asks the user once to allow access.
- **Windows Credential Manager**: the item is named `{account}.{service}` and
  holds at most 2560 bytes of UTF-16.
- The credential store uses the `keyring` 4.x ecosystem as its documentation
  advises for applications: `keyring-core` plus the platform stores
  (`apple-native-keyring-store`, `windows-native-keyring-store`,
  `zbus-secret-service-keyring-store`), configured here.

## Unsafe code

The workspace forbids `unsafe_code`; this crate only denies it, and the
platform modules that need FFI opt back in with `#![allow(unsafe_code)]`:
`biometrics/macos.rs` (LocalAuthentication), `screen_lock/macos.rs`
(`NSDistributedNotificationCenter`) and `screen_lock/win.rs` (Win32 window and
WTS calls). Every `unsafe` block has a `// SAFETY:` comment. Everything else,
including all of Linux, uses safe crate APIs.

## Trying it

```sh
cargo test -p sshkm-os
cargo run -p sshkm-os --example watch_lock         # then lock the screen
cargo run -p sshkm-os --example authenticate -- --check   # availability only
cargo run -p sshkm-os --example authenticate       # shows the prompt
cargo run -p sshkm-os --example store_roundtrip    # writes, reads, deletes a test item
```

The ignored tests need the real OS or a person:

```sh
cargo test -p sshkm-os -- --ignored real_store_round_trip   # real credential store
cargo test -p sshkm-os -- --ignored real_prompt --nocapture # biometric prompt
cargo test -p sshkm-os -- --ignored real_watch --nocapture  # lock within 30 s (not macOS)
```
