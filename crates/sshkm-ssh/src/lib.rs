//! The phone's SSH client.
//!
//! Computers run the system `ssh`; Android doesn't let an app run programs
//! of its own, so the phone speaks SSH itself, through [russh]. It connects
//! by a host's name with the host blocks and `known_hosts` lines computers
//! sync, which the phone carries as text:
//!
//! - [`route`]: the host settings the phone honours (`HostName`, `User`,
//!   `Port`, `ProxyJump` chains, keepalive, `ConnectTimeout`), worked out by
//!   the core with `ssh_config`'s rules; a host that needs `ssh` to run a
//!   program is not available on the phone;
//! - [`host_keys`]: every machine's key against `known_hosts`, with the
//!   rules computers follow; a changed key stops the connection, an unknown
//!   one is the user's call and the new line goes back to the app;
//! - signing in ([`Callbacks`]): the phone's own key, signed by the app
//!   (Android Keystore), then the server's prompts and passwords, answered
//!   by the app from the vault or the user;
//! - [`Shell`]: a terminal (`xterm-256color`): bytes both ways, its size,
//!   keepalive, the end.
//!
//! Algorithms are those of current OpenSSH clients that russh has: no
//! `ssh-rsa` with SHA-1, no DSS, no SHA-1 MACs, no compression. russh's
//! crypto runs on `ring`, which builds for Android with the NDK's compiler
//! alone. Agent forwarding is never asked for. Nothing here logs. The
//! client wipes its own copies of answers once sent; russh wipes the
//! password it sends, not keyboard-interactive answers.
//!
//! Everything is async on tokio; the caller provides the runtime.
//!
//! [russh]: https://github.com/warp-tech/russh

mod auth;
mod callbacks;
mod client;
mod error;
pub mod host_keys;
mod key;
pub mod route;
mod session;

pub use callbacks::{
    AuthMethod, AuthPrompt, CallbackError, Callbacks, PromptItem, SignRequest, UnknownHostKey,
};
pub use client::{ConnectOptions, Connection};
pub use error::{Error, KeyMismatch, NotAvailable};
pub use key::{KeyError, PhoneKey};
pub use route::{Endpoint, Route};
pub use session::{Closed, PtySize, Shell, ShellEvent, TERM};
pub use sshkm_core::prompt::ServerPrompt;
