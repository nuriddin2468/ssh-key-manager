//! The vault's side of browser autofill.
//!
//! The browser extension asks the app, through a native messaging host, for
//! the logins of the page in front of the user, fills the one the user picks,
//! and offers to save what the user typed into a login form. This module
//! holds the parts that do not depend on the app:
//!
//! - [`origin`]: which saved logins belong to a page: same registrable
//!   domain, exactly.
//! - [`channel`]: pairing a browser and sealing every message after that.
//! - [`protocol`]: the JSON messages.
//!
//! Paired browsers are stored in the vault itself
//! ([`crate::vault::PairedBrowser`]).

pub mod channel;
pub mod origin;
pub mod protocol;

pub use origin::{Fit, Origin};
