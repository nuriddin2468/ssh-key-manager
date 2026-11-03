//! Windows Hello keys (`Windows.Security.Credentials.KeyCredentialManager`).
//!
//! Windows keeps an RSA key pair per user and name — in the TPM when there is
//! one — and signs with it only after the user's PIN, face or fingerprint.
//! The signatures are RSASSA-PKCS1-v1_5 with SHA-256, so signing the same
//! data with the same key always gives the same bytes: a secret that only
//! Windows Hello can produce, unlike a value read from the Credential Manager,
//! which any program of the user can do silently.
//!
//! Every call runs on a new thread, which is in the multithreaded apartment
//! where waiting for Windows Runtime operations is allowed, whatever the caller's
//! thread did with COM before.

#![allow(unsafe_code)]

use std::thread;
use std::time::Duration;

use secrecy::zeroize::{Zeroize, Zeroizing};
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
use windows::core::{Array, HSTRING, PCWSTR, w};

use crate::{Error, Result};

/// Class of the window Windows shows the Hello prompt in.
const PROMPT_CLASS: PCWSTR = w!("Credential Dialog Xaml Host");

/// Whether this Windows can keep Hello keys for the user.
pub(super) fn is_supported() -> bool {
    on_new_thread(|| {
        KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| op.join())
            .map_err(|err| Error::Unavailable(err.message()))
    })
    .unwrap_or(false)
}

/// Creates the key `name`, replacing one of that name, and signs
/// `challenge` with it. The user confirms with Windows Hello.
pub(super) fn create(name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let name = HSTRING::from(name);
    let challenge = challenge.to_vec();
    on_new_thread(move || {
        focus_prompt();
        let created = KeyCredentialManager::RequestCreateAsync(
            &name,
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .and_then(|op| op.join())
        .map_err(|err| failed(&err))?;
        check(created.Status().map_err(|err| failed(&err))?)?;
        sign_with(
            &created.Credential().map_err(|err| failed(&err))?,
            &challenge,
        )
    })
}

/// Signs `challenge` with the existing key `name`; the user confirms with
/// Windows Hello. [`Error::NotFound`] when there is no such key.
pub(super) fn sign(name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let name = HSTRING::from(name);
    let challenge = challenge.to_vec();
    on_new_thread(move || {
        let opened = KeyCredentialManager::OpenAsync(&name)
            .and_then(|op| op.join())
            .map_err(|err| failed(&err))?;
        check(opened.Status().map_err(|err| failed(&err))?)?;
        sign_with(
            &opened.Credential().map_err(|err| failed(&err))?,
            &challenge,
        )
    })
}

/// Deletes the key `name`; deleting one that does not exist succeeds.
pub(super) fn delete(name: &str) -> Result<()> {
    let name = HSTRING::from(name);
    on_new_thread(move || {
        // Deleting a missing key fails with NTE_NO_KEY or NTE_BAD_KEYSET; it
        // is gone either way, so only a key that is still there is an error.
        let deleted = KeyCredentialManager::DeleteAsync(&name).and_then(|op| op.join());
        match deleted {
            Ok(()) => Ok(()),
            Err(err) => match KeyCredentialManager::OpenAsync(&name)
                .and_then(|op| op.join())
                .and_then(|opened| opened.Status())
            {
                Ok(KeyCredentialStatus::NotFound) => Ok(()),
                _ => Err(failed(&err)),
            },
        }
    })
}

fn sign_with(credential: &KeyCredential, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let data = CryptographicBuffer::CreateFromByteArray(challenge).map_err(|err| failed(&err))?;
    focus_prompt();
    let signed = credential
        .RequestSignAsync(&data)
        .and_then(|op| op.join())
        .map_err(|err| failed(&err))?;
    check(signed.Status().map_err(|err| failed(&err))?)?;
    let buffer = signed.Result().map_err(|err| failed(&err))?;
    let mut bytes = Array::<u8>::new();
    CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes).map_err(|err| failed(&err))?;
    let signature = Zeroizing::new(bytes.to_vec());
    bytes.zeroize();
    if signature.is_empty() {
        return Err(Error::Failed(
            "Windows Hello returned an empty signature".into(),
        ));
    }
    Ok(signature)
}

fn check(status: KeyCredentialStatus) -> Result<()> {
    match status {
        KeyCredentialStatus::Success => Ok(()),
        // "Use a password instead" is the user's way out, like Cancel.
        KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
            Err(Error::Cancelled)
        }
        KeyCredentialStatus::NotFound => Err(Error::NotFound(
            "the Windows Hello key is gone (Windows Hello was reset or the key was removed)".into(),
        )),
        KeyCredentialStatus::SecurityDeviceLocked => Err(Error::Failed(
            "the security device is locked after too many attempts".into(),
        )),
        other => Err(Error::Failed(format!("Windows Hello status {}", other.0))),
    }
}

fn failed(err: &windows::core::Error) -> Error {
    Error::Failed(format!("Windows Hello: {}", err.message()))
}

fn on_new_thread<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    thread::Builder::new()
        .name("sshkm-hello-key".into())
        .spawn(work)
        .map_err(|err| Error::Failed(format!("cannot start Windows Hello: {err}")))?
        .join()
        .unwrap_or_else(|_| Err(Error::Failed("the Windows Hello call panicked".into())))
}

/// The Hello prompt of a desktop app may open behind the app's window: bring
/// it to the front once it shows up (what KeePassXC does too).
fn focus_prompt() {
    let _ = thread::Builder::new()
        .name("sshkm-hello-focus".into())
        .spawn(|| {
            for _ in 0..30 {
                thread::sleep(Duration::from_millis(100));
                // SAFETY: the class name is a static NUL-terminated string and
                // no window name is given; the call only reads.
                let Ok(window) = (unsafe { FindWindowW(PROMPT_CLASS, PCWSTR::null()) }) else {
                    continue;
                };
                if !window.is_invalid() {
                    // SAFETY: a window that closed meanwhile only makes the
                    // call fail; it has no memory-safety preconditions.
                    let _ = unsafe { SetForegroundWindow(window) };
                    return;
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_the_crate_kinds() {
        assert!(check(KeyCredentialStatus::Success).is_ok());
        assert_eq!(
            check(KeyCredentialStatus::UserCanceled),
            Err(Error::Cancelled)
        );
        assert_eq!(
            check(KeyCredentialStatus::UserPrefersPassword),
            Err(Error::Cancelled)
        );
        assert!(matches!(
            check(KeyCredentialStatus::NotFound),
            Err(Error::NotFound(_))
        ));
        assert!(matches!(
            check(KeyCredentialStatus(42)),
            Err(Error::Failed(_))
        ));
    }

    /// Creates, uses and deletes a real Windows Hello key; Windows asks for
    /// the PIN or a fingerprint. Run it at the machine with
    /// `cargo test -p sshkm-os -- --ignored real_hello_key --nocapture`.
    #[test]
    #[ignore = "shows Windows Hello prompts that a person must answer"]
    fn real_hello_key() {
        let name = format!("sshkm-os test {}", std::process::id());
        let first = create(&name, b"challenge").unwrap();
        let again = sign(&name, b"challenge").unwrap();
        assert_eq!(*first, *again, "signatures must be deterministic");
        assert_ne!(*sign(&name, b"other").unwrap(), *first);
        delete(&name).unwrap();
        assert!(matches!(sign(&name, b"challenge"), Err(Error::NotFound(_))));
        delete(&name).unwrap();
    }
}
