//! Core library of SSH Key Manager.
//!
//! The application is a front-end over the standard OpenSSH files — private and
//! public keys in `~/.ssh`, `~/.ssh/config`, `~/.ssh/known_hosts` — and the system
//! `ssh-agent`. This crate reads and edits those files in a way that keeps them
//! 100% compatible with `ssh`, `ssh-keygen`, `ssh-add` and every other tool that
//! consumes them. There is no private agent.
//!
//! The one file of the app's own is the optional password vault ([`vault`]): a
//! standard KeePass (KDBX 4) database that KeePassXC and other KeePass apps can
//! open too.
//!
//! Modules:
//!
//! - [`paths`]: where the OpenSSH files live, `~` expansion and display.
//! - [`fsutil`]: atomic writes and rotating backups.
//! - [`keys`]: scanning, inspecting, generating, importing and re-encrypting keys.
//! - [`config`]: a lossless, editable model of `ssh_config`.
//! - [`known_hosts`]: a lossless model of `known_hosts`, including hashed entries.
//! - [`hosts_file`]: a lossless, read-only model of the system hosts file.
//! - [`agent`]: a small synchronous client for the system `ssh-agent`.
//! - [`authorized_keys`]: the keys an `authorized_keys` file lets in, read
//!   from a server's copy.
//! - [`authorized_line`]: one `authorized_keys` line with options, checked.
//! - [`tunnels`]: saved port forwards and the `ssh` that holds each open.
//! - [`perms`]: permission checks and fixes (Unix modes, Windows ACLs).
//! - [`prompt`]: what a server's prompt asks for: the password, a one-time
//!   code or something else.
//! - [`audit`]: security findings computed from all of the above.
//! - [`diagnose`]: why an `ssh` run failed, read from what it printed.
//! - [`vault`]: the encrypted password vault, its key slots and the password
//!   generator.
//! - [`p2p`]: two copies of the app talking over the local network: device
//!   keys, the encrypted session and its pairing code.
//! - [`leaks`]: the leak scanner, which finds the vault's secrets in AI
//!   tools' session history, the shell history and picked folders.
//! - [`shell_history`]: hosts worth adding, found in the user's shell
//!   history with their consent; passwords in it are only counted.
//! - [`sync`]: three-way merges that keep the user's own computers in step.
//! - [`browser`]: what the browser extension may see of the vault: which
//!   logins belong to a page, and the encrypted channel to the extension.
//! - [`net`]: the Tools page's network checks: SSH ping, open ports, DNS
//!   records and TLS certificates.
//!
//! What only computers use (`agent`, `audit`, `leaks`, `shell_history`,
//! `tunnels`, browser import, the trash and the `.env` files on disk) is
//! behind cargo features that are on by default; the phone app builds the
//! crate without them. The crate's README lists them.
//!
//! Every public data type implements [`serde::Serialize`] with camelCase field
//! names so it can be returned from Tauri commands unchanged. With the `ts`
//! feature the types also derive `ts_rs::TS`, and `cargo test --features ts`
//! writes TypeScript declarations into the repository's `src/bindings/`.
//!
//! Private key material never leaves this crate in serialisable form: the only
//! type that holds a decrypted key, [`keys::UnlockedKey`], implements neither
//! `Serialize` nor a revealing `Debug`, and is zeroized on drop. Passphrases are
//! passed as [`SecretString`].

#[cfg(feature = "ssh-agent")]
pub mod agent;
#[cfg(feature = "ssh-audit")]
pub mod audit;
pub mod authorized_keys;
pub mod authorized_line;
pub mod browser;
pub mod chat;
pub mod config;
pub mod diagnose;
mod error;
pub mod fsutil;
pub mod hosts_file;
pub mod keys;
pub mod known_hosts;
#[cfg(feature = "leaks")]
pub mod leaks;
pub mod net;
pub mod p2p;
pub mod paths;
pub mod perms;
pub mod prompt;
mod severity;
#[cfg(feature = "shell-history")]
pub mod shell_history;
pub mod sync;
mod text;
#[cfg(feature = "tunnels")]
pub mod tunnels;
pub mod vault;

pub use error::{Error, ErrorCode, ErrorInfo, Result};
pub use secrecy::{self, ExposeSecret, SecretString};
pub use severity::Severity;

/// The version of this crate: the app's version, the same on every device.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Directory that `ts-rs` writes the TypeScript bindings into: the repository's
/// `src/bindings/`. It is absolute so that neither the working directory of the
/// test run nor `TS_RS_EXPORT_DIR` changes where the files land.
#[cfg(feature = "ts")]
pub(crate) const TS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../src/bindings/");
