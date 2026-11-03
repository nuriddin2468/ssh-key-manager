//! Touch ID / Windows Hello for the vault, and locking it with the screen.
//!
//! Turning device unlock on adds a slot to the vault's key slots file whose
//! random key is kept in this computer's credential store (Keychain,
//! Credential Manager). Which slot is this computer's is recorded in
//! `device-unlock.json` in the app's data folder, so the store is only read
//! when the user actually unlocks — reading it may make macOS ask for
//! permission after an update.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString, fsutil};
use sshkm_os::biometrics::{self, Availability};
use tauri::AppHandle;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::types::{BiometricKind, DeviceUnlockStatus};
use crate::vault::{LockReason, VaultRuntime};

/// The credential store item's service name, as Keychain Access shows it.
const SERVICE: &str = "SSH Key Manager vault";
const LINK_FILE: &str = "device-unlock.json";
/// How long an availability answer is reused; asking can take a moment.
const AVAILABILITY_TTL: Duration = Duration::from_secs(30);

/// This computer's device slot in a vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceLink {
    pub vault_id: String,
    pub slot_id: String,
}

impl DeviceLink {
    fn account(&self) -> String {
        format!("{}/{}", self.vault_id, self.slot_id)
    }
}

pub fn load_link(data_dir: &Path) -> Option<DeviceLink> {
    let bytes = std::fs::read(data_dir.join(LINK_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Records this computer's slot, or forgets it with `None`.
pub fn save_link(data_dir: &Path, link: Option<&DeviceLink>) -> AppResult<()> {
    let path = data_dir.join(LINK_FILE);
    match link {
        Some(link) => {
            let json = serde_json::to_vec_pretty(link)
                .map_err(|e| AppError::new(ErrorCode::Io, e.to_string()))?;
            fsutil::atomic_write(&path, &json, 0o600)?;
        }
        None => match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        },
    }
    Ok(())
}

/// Whether device unlock can be used here and is set up for this vault.
pub fn status(
    link: Option<&DeviceLink>,
    vault_id: Option<&str>,
    slots: &[String],
) -> DeviceUnlockStatus {
    let (kind, unavailable_reason) = availability();
    let enabled = link.is_some_and(|link| {
        Some(link.vault_id.as_str()) == vault_id && slots.contains(&link.slot_id)
    });
    DeviceUnlockStatus {
        kind,
        unavailable_reason,
        enabled,
    }
}

/// What the system offers, or why it offers nothing.
type Offer = (Option<BiometricKind>, Option<String>);

fn availability() -> Offer {
    static CACHE: Mutex<Option<(Instant, Offer)>> = Mutex::new(None);
    let mut cache = CACHE.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some((at, offer)) = cache.as_ref()
        && at.elapsed() < AVAILABILITY_TTL
    {
        return offer.clone();
    }
    let (kind, reason) = match biometrics::availability() {
        Availability::Available(biometrics::Kind::TouchId) => (Some(BiometricKind::TouchId), None),
        Availability::Available(biometrics::Kind::WindowsHello) => {
            (Some(BiometricKind::WindowsHello), None)
        }
        Availability::Available(other) => (None, Some(format!("{other:?} is not supported"))),
        Availability::Unavailable(reason) => (None, Some(reason)),
    };
    *cache = Some((Instant::now(), (kind, reason.clone())));
    (kind, reason)
}

/// Shows the system prompt. `reason` completes "<app> is trying to …" on
/// macOS and is the message on Windows; the UI passes it localised.
pub fn authenticate(reason: &str) -> AppResult<()> {
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 200 {
        return Err(AppError::invalid(
            "the prompt text must be 1 to 200 characters",
        ));
    }
    biometrics::authenticate(reason).map_err(os_error)
}

pub fn store_key(link: &DeviceLink, key: &[u8; 32]) -> AppResult<()> {
    let hex = Zeroizing::new(hex_encode(key));
    let secret = SecretString::from(hex.as_str().to_owned());
    sshkm_os::secret_store::set(SERVICE, &link.account(), &secret).map_err(os_error)
}

/// The device key, or `None` if this computer's store has no item for it.
pub fn load_key(link: &DeviceLink) -> AppResult<Option<Zeroizing<[u8; 32]>>> {
    let Some(secret) = sshkm_os::secret_store::get(SERVICE, &link.account()).map_err(os_error)?
    else {
        return Ok(None);
    };
    hex_decode(secret.expose_secret())
        .map(Some)
        .ok_or_else(|| AppError::new(ErrorCode::Parse, "unreadable device key"))
}

pub fn delete_key(link: &DeviceLink) -> AppResult<()> {
    sshkm_os::secret_store::delete(SERVICE, &link.account()).map_err(os_error)
}

/// Locks the vault whenever the screen locks, if the settings say so. On
/// Windows registering can fail early after boot, so it is retried for a while.
pub fn watch_screen_lock(runtime: Arc<VaultRuntime>, app: AppHandle) {
    thread::spawn(move || {
        for attempt in 1..=10 {
            let runtime = Arc::clone(&runtime);
            let app = app.clone();
            let on_lock = move || {
                if runtime.settings().lock_on_screen_lock {
                    runtime.lock(&app, LockReason::ScreenLock);
                }
            };
            match sshkm_os::screen_lock::watch(on_lock) {
                Ok(watcher) => {
                    // Keep the watcher for the life of the app.
                    std::mem::forget(watcher);
                    return;
                }
                Err(sshkm_os::Error::Failed(reason)) => {
                    log::warn!("screen lock watch failed (attempt {attempt}): {reason}");
                    thread::sleep(Duration::from_secs(30));
                }
                Err(error) => {
                    log::info!("screen lock can't be watched here: {error}");
                    return;
                }
            }
        }
    });
}

#[allow(clippy::needless_pass_by_value, reason = "used with map_err")]
fn os_error(error: sshkm_os::Error) -> AppError {
    let code = match error {
        sshkm_os::Error::Cancelled => ErrorCode::Cancelled,
        sshkm_os::Error::Unsupported | sshkm_os::Error::Unavailable(_) => ErrorCode::Unsupported,
        sshkm_os::Error::Failed(_) => ErrorCode::PermissionDenied,
        _ => ErrorCode::Io,
    };
    AppError::new(code, error.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn hex_decode(text: &str) -> Option<Zeroizing<[u8; 32]>> {
    let text = text.trim().as_bytes();
    if text.len() != 64 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    let (pairs, _) = text.as_chunks::<2>();
    for (byte, pair) in out.iter_mut().zip(pairs) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_through_hex() {
        let key: [u8; 32] = std::array::from_fn(|i| u8::try_from(i * 7).unwrap());
        let hex = hex_encode(&key);
        assert_eq!(hex.len(), 64);
        assert_eq!(*hex_decode(&hex).unwrap(), key);
        assert!(hex_decode("zz").is_none());
        assert!(hex_decode(&"g".repeat(64)).is_none());
    }

    #[test]
    fn link_file_round_trips_and_can_be_removed() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_link(dir.path()).is_none());
        let link = DeviceLink {
            vault_id: "v".into(),
            slot_id: "s".into(),
        };
        save_link(dir.path(), Some(&link)).unwrap();
        assert_eq!(load_link(dir.path()), Some(link.clone()));
        assert_eq!(link.account(), "v/s");
        save_link(dir.path(), None).unwrap();
        save_link(dir.path(), None).unwrap();
        assert!(load_link(dir.path()).is_none());
    }

    #[test]
    fn enabled_only_for_the_linked_vault_and_an_existing_slot() {
        let link = DeviceLink {
            vault_id: "v".into(),
            slot_id: "s".into(),
        };
        let slots = vec!["s".to_owned()];
        assert!(status(Some(&link), Some("v"), &slots).enabled);
        assert!(!status(Some(&link), Some("other"), &slots).enabled);
        assert!(!status(Some(&link), Some("v"), &[]).enabled);
        assert!(!status(None, Some("v"), &slots).enabled);
    }
}
