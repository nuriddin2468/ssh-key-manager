//! OS integration for SSH Key Manager.
//!
//! A small, synchronous API over the operating-system services the password
//! vault needs. It knows nothing about Tauri or the vault itself:
//!
//! - [`screen_lock`]: be told when the user's session or screen is locked, so
//!   the vault can lock itself.
//! - [`biometrics`]: confirm the user with Touch ID (macOS) or Windows Hello
//!   (Windows) before unlocking, and on Windows derive a secret that only
//!   Windows Hello can produce.
//! - [`secret_store`]: keep a secret in the OS credential store (macOS
//!   Keychain, Windows Credential Manager, Linux Secret Service).
//! - `pipe` (Windows): check who serves a named pipe before sending to it.
//! - [`tray`]: whether the system can show a tray icon at all.
//!
//! Every call that can wait for the user (a biometric prompt, a keychain
//! access dialog, a locked Secret Service collection) blocks the calling
//! thread, so call them from a worker thread, never from the UI thread.
//!
//! Secrets are passed as [`SecretString`] and are zeroized when dropped. Error
//! messages never contain secrets.
//!
//! This is the only crate of the workspace allowed to contain `unsafe` code,
//! and only in the platform modules that call OS APIs through FFI. Each
//! `unsafe` block carries a `// SAFETY:` comment.

pub mod biometrics;
mod error;
#[cfg(target_os = "windows")]
pub mod pipe;
pub mod screen_lock;
pub mod secret_store;
pub mod tray;

pub use error::{Error, Result};
pub use secrecy::{self, ExposeSecret, SecretString};
