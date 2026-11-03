//! The OS credential store.
//!
//! - **macOS**: the regular (file-based) login keychain, as a generic password
//!   whose service and account are the ones given here. Not the data-protection
//!   keychain: that needs entitlements, which an app without a Developer ID
//!   signature cannot have. The item gets the default access list of an item
//!   an app creates (`SecKeychainAddGenericPassword` without an access
//!   object): only that app, as identified by its code signature, reads it
//!   silently; any other program — or this app after an update that changed
//!   its signature — makes macOS ask for the login keychain password first.
//! - **Windows**: a generic credential in the Credential Manager named
//!   `{account}.{service}`, persisted on this computer only
//!   (`CRED_PERSIST_LOCAL_MACHINE`), so it never roams with a domain profile.
//!   The secret is stored as UTF-16 and may be at most 2560 bytes in that
//!   encoding (1280 UTF-16 code units). Any program running as the user can
//!   read it without a prompt, so keep nothing here that must need the user's
//!   confirmation (see [`crate::biometrics::create_bound_key`]).
//! - **Linux**: an item in the default collection of the Secret Service
//!   (GNOME Keyring, KDE Wallet, KeePassXC, …) with the attributes `service` and
//!   `username`, over D-Bus. Once the collection is unlocked (usually at
//!   login), any program of the user's session can read it without a prompt.
//!
//! Every call may block on a system prompt: macOS asks before an app other
//! than the one that created an item reads it (an app update with a different
//! code signature counts as another app), and the Secret Service asks to
//! unlock a locked collection. Call these functions from a worker thread.
//!
//! The secret is passed to the platform library as a `&str`; copies made
//! inside the OS libraries cannot be wiped from here. Copies made by this
//! crate are zeroized.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex, PoisonError},
};

use keyring_core::{CredentialStore, Entry};
use secrecy::{ExposeSecret, SecretString, zeroize::Zeroize};

use crate::{Error, Result};

/// Stores `secret` under `service` and `account`, replacing any previous
/// value.
///
/// Use a reverse-DNS `service` (the app identifier) and a short `account`;
/// both must be non-empty.
pub fn set(service: &str, account: &str, secret: &SecretString) -> Result<()> {
    Backend::platform()?.set(service, account, secret)
}

/// Reads the secret stored under `service` and `account`, or `None` if there
/// is none.
pub fn get(service: &str, account: &str) -> Result<Option<SecretString>> {
    Backend::platform()?.get(service, account)
}

/// Deletes the secret stored under `service` and `account`. Deleting a secret
/// that does not exist succeeds.
pub fn delete(service: &str, account: &str) -> Result<()> {
    Backend::platform()?.delete(service, account)
}

/// A credential store plus the entry modifiers used with it.
struct Backend {
    store: Arc<CredentialStore>,
    modifiers: HashMap<&'static str, &'static str>,
}

impl Backend {
    fn platform() -> Result<Self> {
        Ok(Self {
            store: platform_store()?,
            modifiers: platform_modifiers(),
        })
    }

    fn entry(&self, service: &str, account: &str) -> Result<Entry> {
        if service.is_empty() || account.is_empty() {
            return Err(Error::Store(
                "the service and account must not be empty".into(),
            ));
        }
        self.store
            .build(service, account, Some(&self.modifiers))
            .map_err(store_error)
    }

    fn set(&self, service: &str, account: &str, secret: &SecretString) -> Result<()> {
        self.entry(service, account)?
            .set_password(secret.expose_secret())
            .map_err(store_error)
    }

    fn get(&self, service: &str, account: &str) -> Result<Option<SecretString>> {
        match self.entry(service, account)?.get_password() {
            Ok(password) => Ok(Some(into_secret(password))),
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(err) => Err(store_error(err)),
        }
    }

    fn delete(&self, service: &str, account: &str) -> Result<()> {
        match self.entry(service, account)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(err) => Err(store_error(err)),
        }
    }
}

/// The platform store, opened on first use. A failed open is retried on the
/// next call, so a Secret Service started later is picked up.
fn platform_store() -> Result<Arc<CredentialStore>> {
    static STORE: Mutex<Option<Arc<CredentialStore>>> = Mutex::new(None);
    let mut slot = STORE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(store) = slot.as_ref() {
        return Ok(Arc::clone(store));
    }
    let store = open_platform_store()?;
    *slot = Some(Arc::clone(&store));
    Ok(store)
}

#[cfg(target_os = "macos")]
fn open_platform_store() -> Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> =
        apple_native_keyring_store::keychain::Store::new().map_err(|err| unavailable(&err))?;
    Ok(store)
}

#[cfg(target_os = "windows")]
fn open_platform_store() -> Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> =
        windows_native_keyring_store::Store::new().map_err(|err| unavailable(&err))?;
    Ok(store)
}

#[cfg(target_os = "linux")]
fn open_platform_store() -> Result<Arc<CredentialStore>> {
    let store: Arc<CredentialStore> =
        zbus_secret_service_keyring_store::Store::new().map_err(|err| unavailable(&err))?;
    Ok(store)
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn open_platform_store() -> Result<Arc<CredentialStore>> {
    Err(Error::Unsupported)
}

#[cfg(target_os = "windows")]
fn platform_modifiers() -> HashMap<&'static str, &'static str> {
    // The default, `Enterprise`, roams with a domain profile; this secret
    // belongs to this computer.
    HashMap::from([("persistence", "Local")])
}

#[cfg(not(target_os = "windows"))]
fn platform_modifiers() -> HashMap<&'static str, &'static str> {
    HashMap::new()
}

/// The store could not be opened at all.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn unavailable(err: &keyring_core::Error) -> Error {
    Error::Unavailable(format!("cannot open the credential store: {err}"))
}

/// Maps a keyring error, wiping any secret bytes it carries.
fn store_error(err: keyring_core::Error) -> Error {
    use keyring_core::Error as E;
    match err {
        E::NoStorageAccess(source) => {
            Error::Store(format!("the credential store is not accessible: {source}"))
        }
        E::BadEncoding(mut bytes) => {
            bytes.zeroize();
            Error::Store("the stored secret is not valid UTF-8".into())
        }
        E::BadDataFormat(mut bytes, source) => {
            bytes.zeroize();
            Error::Store(format!("the stored secret is malformed: {source}"))
        }
        E::Ambiguous(_) => {
            Error::Store("more than one item matches the service and account".into())
        }
        other => Error::Store(other.to_string()),
    }
}

/// Moves a password into a [`SecretString`] without leaving an unwiped copy:
/// the secret gets an exact-size allocation and the original buffer, spare
/// capacity included, is zeroized.
fn into_secret(mut password: String) -> SecretString {
    let secret = SecretString::from(password.as_str());
    password.zeroize();
    secret
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock() -> Backend {
        Backend {
            store: keyring_core::mock::Store::new().unwrap(),
            modifiers: HashMap::new(),
        }
    }

    #[test]
    fn round_trip() {
        let backend = mock();
        let secret = SecretString::from("correct horse battery staple ✓");
        backend.set("svc", "acct", &secret).unwrap();
        let read = backend.get("svc", "acct").unwrap().unwrap();
        assert_eq!(read.expose_secret(), secret.expose_secret());
    }

    #[test]
    fn set_replaces_the_previous_value() {
        let backend = mock();
        backend.set("svc", "acct", &"one".into()).unwrap();
        backend.set("svc", "acct", &"two".into()).unwrap();
        let read = backend.get("svc", "acct").unwrap().unwrap();
        assert_eq!(read.expose_secret(), "two");
    }

    #[test]
    fn missing_secret_is_none() {
        assert!(mock().get("svc", "nobody").unwrap().is_none());
    }

    #[test]
    fn delete_removes_and_tolerates_missing() {
        let backend = mock();
        backend.set("svc", "acct", &"x".into()).unwrap();
        backend.delete("svc", "acct").unwrap();
        assert!(backend.get("svc", "acct").unwrap().is_none());
        backend.delete("svc", "acct").unwrap();
    }

    #[test]
    fn accounts_and_services_are_separate() {
        let backend = mock();
        backend.set("svc", "a", &"for a".into()).unwrap();
        backend.set("other", "a", &"other a".into()).unwrap();
        assert!(backend.get("svc", "b").unwrap().is_none());
        assert_eq!(
            backend.get("svc", "a").unwrap().unwrap().expose_secret(),
            "for a"
        );
        assert_eq!(
            backend.get("other", "a").unwrap().unwrap().expose_secret(),
            "other a"
        );
    }

    #[test]
    fn empty_names_are_rejected() {
        let backend = mock();
        let err = backend.set("", "acct", &"x".into()).unwrap_err();
        assert_eq!(err.code(), "store");
        assert!(backend.get("svc", "").is_err());
    }

    #[test]
    fn store_errors_do_not_echo_secret_bytes() {
        let err = store_error(keyring_core::Error::BadEncoding(b"hunter2\xff".to_vec()));
        assert_eq!(
            err,
            Error::Store("the stored secret is not valid UTF-8".into())
        );
        let err = store_error(keyring_core::Error::BadDataFormat(
            b"hunter2".to_vec(),
            "bad padding".into(),
        ));
        assert!(!err.to_string().contains("hunter2"));
        let err = store_error(keyring_core::Error::NoStorageAccess("locked".into()));
        assert_eq!(
            err.to_string(),
            "credential store error: the credential store is not accessible: locked"
        );
    }

    #[test]
    fn into_secret_keeps_the_value() {
        let mut password = String::with_capacity(64);
        password.push_str("s3cret");
        assert_eq!(into_secret(password).expose_secret(), "s3cret");
    }

    /// Writes, reads and deletes an item in the real OS credential store (on
    /// macOS the login keychain may ask for permission). Run it with
    /// `cargo test -p sshkm-os -- --ignored real_store_round_trip`.
    #[test]
    #[ignore = "touches the real OS credential store"]
    fn real_store_round_trip() {
        let service = "dev.sshkeymanager.sshkm-os.test";
        let account = format!("round-trip-{}", std::process::id());
        let secret = SecretString::from("test secret ✓");
        set(service, &account, &secret).unwrap();
        let read = get(service, &account)
            .unwrap()
            .expect("the secret was just stored");
        assert_eq!(read.expose_secret(), secret.expose_secret());
        set(service, &account, &"replaced".into()).unwrap();
        assert_eq!(
            get(service, &account).unwrap().unwrap().expose_secret(),
            "replaced"
        );
        delete(service, &account).unwrap();
        assert!(get(service, &account).unwrap().is_none());
        delete(service, &account).unwrap();
    }
}
