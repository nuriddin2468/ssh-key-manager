//! Windows Hello.
//!
//! The prompt itself comes from `robius-authentication`; this module asks
//! `UserConsentVerifier` whether Windows Hello is set up, which that crate does
//! not expose. Checking first also stops that crate from falling back to a
//! username/password dialog when Windows Hello is missing. Windows Hello
//! counts as available only if it can also keep keys ([`super::hello`]).

use windows::Security::Credentials::UI::{UserConsentVerifier, UserConsentVerifierAvailability};

use super::{Availability, Kind, hello, prompt};
use crate::{Error, Result};

pub(super) fn availability() -> Availability {
    // Waiting for a WinRT operation must not happen on a UI (single-threaded
    // apartment) thread. A new thread has no apartment, so `windows` puts it
    // in the multithreaded one, where waiting is fine.
    let check = std::thread::Builder::new()
        .name("sshkm-hello-check".into())
        .spawn(check_availability);
    match check {
        Ok(handle) => handle.join().unwrap_or_else(|_| {
            Availability::Unavailable("the Windows Hello check panicked".into())
        }),
        Err(err) => Availability::Unavailable(format!("cannot check Windows Hello: {err}")),
    }
}

pub(super) fn authenticate(reason: &str) -> Result<()> {
    match availability() {
        Availability::Available(_) => prompt::show(reason),
        Availability::Unavailable(why) => Err(Error::Unavailable(why)),
    }
}

fn check_availability() -> Availability {
    match UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.join()) {
        Ok(status) => match from_status(status) {
            Availability::Available(_) if !hello::is_supported() => {
                Availability::Unavailable("Windows Hello can't keep keys on this computer".into())
            }
            availability => availability,
        },
        Err(err) => Availability::Unavailable(format!("cannot check Windows Hello: {err}")),
    }
}

fn from_status(status: UserConsentVerifierAvailability) -> Availability {
    let why = match status {
        UserConsentVerifierAvailability::Available => {
            return Availability::Available(Kind::WindowsHello);
        }
        UserConsentVerifierAvailability::DeviceNotPresent => "no Windows Hello device is present",
        UserConsentVerifierAvailability::NotConfiguredForUser => {
            "Windows Hello is not set up for this user"
        }
        UserConsentVerifierAvailability::DisabledByPolicy => {
            "Windows Hello is disabled by group policy"
        }
        UserConsentVerifierAvailability::DeviceBusy => "the Windows Hello device is busy",
        other => return Availability::Unavailable(format!("Windows Hello status {}", other.0)),
    };
    Availability::Unavailable(why.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_statuses() {
        assert_eq!(
            from_status(UserConsentVerifierAvailability::Available),
            Availability::Available(Kind::WindowsHello)
        );
        assert!(!from_status(UserConsentVerifierAvailability::NotConfiguredForUser).is_available());
        assert_eq!(
            from_status(UserConsentVerifierAvailability(42)),
            Availability::Unavailable("Windows Hello status 42".into())
        );
    }
}
