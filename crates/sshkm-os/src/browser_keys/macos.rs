use secrecy::zeroize::Zeroizing;
use security_framework::passwords::get_generic_password;

use crate::{Error, Result};

/// `errSecItemNotFound`.
const NOT_FOUND: i32 = -25300;
/// `userCanceledErr`, `errSecAuthFailed`, `errSecInteractionNotAllowed`: the
/// user refused, got the password wrong, or there was no one to ask.
const REFUSED: [i32; 3] = [-128, -25293, -25308];

pub(super) fn safe_storage(service: &str, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match get_generic_password(service, account) {
        Ok(password) => Ok(Some(Zeroizing::new(password))),
        Err(error) if error.code() == NOT_FOUND => Ok(None),
        Err(error) if REFUSED.contains(&error.code()) => Err(Error::Cancelled),
        Err(error) => Err(Error::Store(format!("Keychain error {}", error.code()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "reads the login keychain"]
    fn a_missing_item_is_none() {
        let found = safe_storage("SSH Key Manager test: no such item", "nobody").unwrap();
        assert!(found.is_none());
    }
}
