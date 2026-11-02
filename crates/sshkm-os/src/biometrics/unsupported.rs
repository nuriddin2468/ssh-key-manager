//! Platforms without a supported biometric prompt (Linux and others).
//!
//! On Linux the only candidate, polkit, authenticates with the account
//! password and needs a policy file installed system-wide, so it is not used.

use super::Availability;
use crate::{Error, Result};

const WHY: &str = "biometric unlock is not supported on this platform";

pub(super) fn availability() -> Availability {
    Availability::Unavailable(WHY.to_owned())
}

pub(super) fn authenticate(_reason: &str) -> Result<()> {
    Err(Error::Unavailable(WHY.to_owned()))
}
