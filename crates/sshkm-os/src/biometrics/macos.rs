//! Touch ID through the Local Authentication framework.
//!
//! The prompt itself comes from `robius-authentication`; this module only asks
//! Local Authentication whether Touch ID can be used, which that crate does not
//! expose.

#![allow(unsafe_code)]

use objc2_local_authentication::{LAContext, LAError, LAPolicy};

use super::{Availability, Kind, prompt};
use crate::Result;

pub(super) fn availability() -> Availability {
    // SAFETY: creating a context has no preconditions; it is used on this
    // thread only and released when it goes out of scope.
    let context = unsafe { LAContext::new() };
    // SAFETY: the policy is one of the documented constants and the context is
    // alive. The call only reads state and does not show any UI.
    let result = unsafe {
        context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
    };
    match result {
        Ok(()) => Availability::Available(Kind::TouchId),
        Err(err) => Availability::Unavailable(describe(LAError(err.code()))),
    }
}

pub(super) fn authenticate(reason: &str) -> Result<()> {
    prompt::show(reason)
}

fn describe(err: LAError) -> String {
    let text = match err {
        LAError::BiometryNotAvailable => "Touch ID is not available on this Mac",
        LAError::BiometryNotEnrolled => "no fingerprints are enrolled in Touch ID",
        LAError::BiometryLockout => "Touch ID is locked after too many failed attempts",
        LAError::BiometryNotPaired => "no keyboard with Touch ID is paired",
        LAError::BiometryDisconnected => "the keyboard with Touch ID is not connected",
        LAError::PasscodeNotSet => "the user account has no password",
        _ => return format!("Touch ID cannot be used (LAError {})", err.0),
    };
    text.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_common_errors() {
        assert_eq!(
            describe(LAError::BiometryNotEnrolled),
            "no fingerprints are enrolled in Touch ID"
        );
        assert_eq!(
            describe(LAError(-1000)),
            "Touch ID cannot be used (LAError -1000)"
        );
    }
}
