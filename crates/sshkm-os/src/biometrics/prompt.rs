//! The biometric prompt on macOS and Windows, through `robius-authentication`.

use std::sync::mpsc;

use robius_authentication::{
    AndroidText, BiometricStrength, Context, Error as AuthError, PolicyBuilder, Text, WindowsText,
};

use crate::{Error, Result};

/// Caption of the Windows credential dialog. Only its password fallback shows
/// it, which is never reached because Windows Hello's availability is checked
/// first.
const WINDOWS_CAPTION: &str = "SSH Key Manager";

/// Shows the system prompt and blocks until the user answers.
pub(super) fn show(reason: &str) -> Result<()> {
    // macOS: biometrics only (no password, no Apple Watch). Windows: the crate
    // only accepts biometrics plus PIN, which is what Windows Hello is.
    let policy = PolicyBuilder::new()
        .biometrics(Some(BiometricStrength::Strong))
        .password(cfg!(target_os = "windows"))
        .companion(false)
        .build()
        .ok_or_else(|| Error::Failed("the biometric policy is not supported here".into()))?;
    let text = Text {
        android: AndroidText {
            title: reason,
            subtitle: None,
            description: None,
        },
        apple: reason,
        windows: WindowsText::new_truncated(WINDOWS_CAPTION, reason),
    };

    // The callback runs on a framework queue (macOS) or the crate's own thread
    // (Windows), exactly once if `authenticate` returned `Ok`.
    let (tx, rx) = mpsc::channel();
    Context::new(())
        .authenticate(text, &policy, move |result| {
            // The receiver only goes away once `show` has returned.
            let _ = tx.send(result);
        })
        .map_err(|err| map_error(&err))?;
    match rx.recv() {
        Ok(result) => result.map_err(|err| map_error(&err)),
        Err(mpsc::RecvError) => Err(Error::Failed("the prompt ended without a result".into())),
    }
}

fn map_error(err: &AuthError) -> Error {
    match err {
        AuthError::UserCanceled
        | AuthError::AppCanceled
        | AuthError::SystemCanceled
        | AuthError::UserFallback => Error::Cancelled,
        AuthError::Unavailable
        | AuthError::NotEnrolled
        | AuthError::NotPaired
        | AuthError::BiometryDisconnected
        | AuthError::PasscodeNotSet
        | AuthError::NotConfigured
        | AuthError::DisabledByPolicy
        | AuthError::Busy
        | AuthError::NotInteractive
        | AuthError::CompanionNotAvailable => Error::Unavailable(err.to_string()),
        _ => Error::Failed(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_map_to_the_crate_kinds() {
        assert_eq!(map_error(&AuthError::UserCanceled), Error::Cancelled);
        assert_eq!(map_error(&AuthError::UserFallback), Error::Cancelled);
        assert!(matches!(
            map_error(&AuthError::NotEnrolled),
            Error::Unavailable(_)
        ));
        assert!(matches!(
            map_error(&AuthError::Authentication),
            Error::Failed(_)
        ));
        assert!(matches!(map_error(&AuthError::Exhausted), Error::Failed(_)));
    }
}
