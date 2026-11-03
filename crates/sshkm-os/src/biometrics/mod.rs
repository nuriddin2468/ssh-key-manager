//! Confirming the user with biometrics: Touch ID on macOS, Windows Hello on
//! Windows.
//!
//! - **macOS**: Touch ID only, through the Local Authentication framework
//!   (`LAPolicyDeviceOwnerAuthenticationWithBiometrics`). There is no fallback
//!   to the login password and no Apple Watch; if the user clicks the dialog's
//!   password button, [`authenticate`] returns [`Error::Cancelled`] and the app
//!   should ask for its own password instead. The system dialog reads
//!   "*App name* is trying to *reason*.", so phrase `reason` to fit
//!   ("unlock the password vault").
//! - **Windows**: Windows Hello with whatever the user has set up (face,
//!   fingerprint or PIN). `reason` is shown in the Windows Security dialog.
//!   When Windows Hello is not set up, [`authenticate`] returns
//!   [`Error::Unavailable`] rather than falling back to a password dialog.
//! - **Linux**: not supported; [`availability`] reports
//!   [`Availability::Unavailable`].
//!
//! [`authenticate`] is a yes/no answer inside this process: it guards nothing
//! by itself. To bind a secret to the user's confirmation:
//!
//! - **Windows**: a Windows Hello key ([`create_bound_key`],
//!   [`sign_with_bound_key`]) signs a challenge only after the user's PIN,
//!   face or fingerprint, and the signature is the same every time, so a key
//!   derived from it exists nowhere at rest.
//! - **macOS**: there is no equivalent without the data-protection keychain,
//!   which needs a provisioning profile. [`enrollment`] at least tells when
//!   fingerprints were added or removed.
//!
//! Every function blocks (the checks briefly, the prompts until the user
//! answers), so call them from a worker thread.

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod prompt;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as sys;

#[cfg(target_os = "windows")]
mod hello;
#[cfg(target_os = "windows")]
mod win;
#[cfg(target_os = "windows")]
use win as sys;

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
mod unsupported;
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
use unsupported as sys;

use secrecy::zeroize::Zeroizing;

use crate::{Error, Result};

/// Whether this platform has [`create_bound_key`]: Windows only.
pub const BOUND_KEYS: bool = cfg!(target_os = "windows");

/// The biometric method the platform offers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Kind {
    /// Touch ID on a Mac (built in or on a Magic Keyboard).
    TouchId,
    /// Windows Hello: face, fingerprint or PIN.
    WindowsHello,
}

/// Whether [`authenticate`] can show a prompt right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// The prompt can be shown.
    Available(Kind),
    /// It cannot; the text says why, in English, for logs (no hardware,
    /// nothing enrolled, disabled by policy, unsupported platform, …).
    Unavailable(String),
}

impl Availability {
    /// Whether the prompt can be shown.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    /// The available method, if any.
    pub fn kind(&self) -> Option<Kind> {
        match self {
            Self::Available(kind) => Some(*kind),
            Self::Unavailable(_) => None,
        }
    }
}

/// Checks whether biometric confirmation can be used now.
///
/// The answer can change at any time (a fingerprint is added, a Magic
/// Keyboard is unplugged, a Mac's lid is closed), so check again before
/// offering it.
pub fn availability() -> Availability {
    sys::availability()
}

/// Asks the user to confirm with Touch ID or Windows Hello, and blocks until
/// they do, cancel or fail.
///
/// `reason` is shown in the system prompt and must not be empty.
///
/// Errors: [`Error::Cancelled`] when the user dismisses the prompt (or picks
/// the password fallback on macOS), [`Error::Failed`] when they are not
/// recognised or are locked out after too many attempts, and
/// [`Error::Unavailable`] when no biometric method can be used.
pub fn authenticate(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        return Err(Error::Failed("the prompt reason must not be empty".into()));
    }
    sys::authenticate(reason)
}

/// Creates the Windows Hello key `name` for this user, replacing one of that
/// name, and returns its signature of `challenge`. The user confirms with
/// Windows Hello (once for the new key, once for the signature).
///
/// The signature is deterministic: [`sign_with_bound_key`] with the same
/// name and challenge returns the same bytes until the key is replaced or
/// deleted, or Windows Hello is reset. Use it as key material (through a
/// KDF), never store it.
///
/// Errors: [`Error::Cancelled`], [`Error::Failed`], and
/// [`Error::Unsupported`] off Windows.
pub fn create_bound_key(name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "windows")]
    {
        hello::create(name, challenge)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (name, challenge);
        Err(Error::Unsupported)
    }
}

/// Signs `challenge` with the Windows Hello key `name` after the user
/// confirms with Windows Hello. [`Error::NotFound`] when the key is gone.
pub fn sign_with_bound_key(name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    #[cfg(target_os = "windows")]
    {
        hello::sign(name, challenge)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = (name, challenge);
        Err(Error::Unsupported)
    }
}

/// Deletes the Windows Hello key `name`; a missing key, or another platform,
/// is not an error.
pub fn delete_bound_key(name: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        hello::delete(name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = name;
        Ok(())
    }
}

/// macOS: an opaque value that changes whenever fingerprints are added to or
/// removed from Touch ID (Local Authentication's policy domain state). Store a
/// hash of it with whatever Touch ID guards, and compare after each prompt.
/// It may also change with a major macOS update. `None` when Touch ID can't
/// be used now, and on other platforms.
pub fn enrollment() -> Option<Vec<u8>> {
    #[cfg(target_os = "macos")]
    {
        macos::enrollment()
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_helpers() {
        let yes = Availability::Available(Kind::TouchId);
        assert!(yes.is_available());
        assert_eq!(yes.kind(), Some(Kind::TouchId));
        let no = Availability::Unavailable("nothing enrolled".into());
        assert!(!no.is_available());
        assert_eq!(no.kind(), None);
    }

    #[test]
    fn empty_reason_is_rejected_before_any_prompt() {
        assert!(matches!(authenticate(""), Err(Error::Failed(_))));
        assert!(matches!(authenticate("  \n"), Err(Error::Failed(_))));
    }

    /// Only checks that the query returns without panicking; the answer
    /// depends on the machine.
    #[test]
    fn availability_does_not_panic() {
        let _ = availability();
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    #[test]
    fn unsupported_platforms_report_unavailable() {
        assert!(!availability().is_available());
        assert!(matches!(authenticate("unlock"), Err(Error::Unavailable(_))));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn bound_keys_are_windows_only() {
        const { assert!(!BOUND_KEYS) };
        assert_eq!(create_bound_key("x", b"c").unwrap_err(), Error::Unsupported);
        assert_eq!(
            sign_with_bound_key("x", b"c").unwrap_err(),
            Error::Unsupported
        );
        assert!(delete_bound_key("x").is_ok());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn enrollment_is_macos_only() {
        assert!(enrollment().is_none());
    }

    /// Shows the real Touch ID / Windows Hello prompt. Run it at the machine
    /// with `cargo test -p sshkm-os -- --ignored real_prompt --nocapture`, or
    /// use `cargo run -p sshkm-os --example authenticate`.
    #[test]
    #[ignore = "shows a system prompt that a person must answer"]
    fn real_prompt() {
        println!("availability: {:?}", availability());
        println!("result: {:?}", authenticate("test the sshkm-os crate"));
    }
}
