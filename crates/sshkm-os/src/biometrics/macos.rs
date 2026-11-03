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

/// The policy domain state of a fresh context, which Local Authentication
/// fills in once `canEvaluatePolicy` succeeds for a biometric policy.
pub(super) fn enrollment() -> Option<Vec<u8>> {
    // SAFETY: as in `availability`: a new context, used on this thread only.
    let context = unsafe { LAContext::new() };
    // SAFETY: a documented policy constant on a live context; no UI is shown.
    let usable = unsafe {
        context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthenticationWithBiometrics)
    };
    usable.ok()?;
    // `domainState` replaces it from macOS 15 on, but the app supports older
    // versions, and the old property still works.
    #[allow(deprecated)]
    // SAFETY: a read-only property of the context just evaluated.
    let state = unsafe { context.evaluatedPolicyDomainState() }?;
    Some(state.to_vec())
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
