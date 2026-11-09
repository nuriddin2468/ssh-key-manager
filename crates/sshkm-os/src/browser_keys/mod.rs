//! The keys browsers keep with the system to encrypt their saved logins,
//! for importing those logins into the vault.
//!
//! - **macOS**: [`safe_storage`] reads the Keychain item a Chromium browser
//!   made ("Chrome Safe Storage"). The item belongs to the browser, so macOS
//!   asks the user whether this app may read it, with the login keychain
//!   password; refusing is [`Error::Cancelled`].
//! - **Linux**: [`safe_storage`] looks for the item in the Secret Service
//!   (GNOME Keyring, KeePassXC, …) by its `application` attribute, then in
//!   `KWallet` (folder "`account` Keys"). Either may ask to unlock first.
//! - **Windows**: [`unprotect`] decrypts a DPAPI blob as the signed-in user,
//!   without any prompt (`CRYPTPROTECT_UI_FORBIDDEN`).
//!
//! Each call may block on a system prompt: call it from a worker thread.
//! What is returned is wiped when dropped; copies the OS libraries made
//! inside themselves can't be wiped from here.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use secrecy::zeroize::Zeroizing;

use crate::{Error, Result};

/// The password a Chromium browser keeps in the Keychain (service and
/// account) or the Secret Service (`application`) / `KWallet`. `None` when
/// there is none.
#[cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    allow(unused_variables)
)]
pub fn safe_storage(
    service: &str,
    account: &str,
    application: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    #[cfg(target_os = "macos")]
    {
        let _ = application;
        macos::safe_storage(service, account)
    }
    #[cfg(target_os = "linux")]
    {
        linux::safe_storage(service, account, application)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(Error::Unsupported)
    }
}

/// `blob` decrypted with DPAPI as the signed-in user (Windows only).
#[cfg_attr(not(target_os = "windows"), allow(unused_variables))]
pub fn unprotect(blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "windows")]
    {
        windows::unprotect(blob)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(Error::Unsupported)
    }
}
