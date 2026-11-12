//! Touch ID / Windows Hello for the vault, and locking it with the screen.
//!
//! Turning device unlock on adds a slot to the vault's key slots file for
//! this computer. Which slot is this computer's is recorded in
//! `device-unlock.json` in the app's data folder. The slot's key is kept
//! differently on each system:
//!
//! - **Windows**: derived from a Windows Hello signature of a fixed per-vault
//!   challenge ([`vault::bound_device_key`]). The key is stored nowhere;
//!   only Windows Hello, after the user's PIN, face or fingerprint, can make
//!   it again. Links from before this scheme ([`Scheme::Store`], a random key
//!   in the Credential Manager) work once more and are then upgraded.
//! - **macOS**: a random key in the login keychain, read after Touch ID says
//!   yes. Only this app reads the item without a password prompt (the default
//!   access list of a keychain item), and device unlock turns itself off when
//!   fingerprints are added or removed. Binding the key to Touch ID itself
//!   would need the data-protection keychain, which needs a provisioning
//!   profile.
//!
//! The store is only read when the user actually unlocks — reading it may
//! make macOS ask for permission after an update. Every prompt text is built
//! here, never taken from the UI.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sshkm_core::vault::{self, Vault, VaultPaths};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString, fsutil};
use sshkm_os::biometrics::{self, Availability};
use tauri::AppHandle;
use zeroize::Zeroizing;

use crate::confirm::Localized;
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
    /// Where the slot's key comes from; links written before there was a
    /// choice have none, which means [`Scheme::Store`].
    #[serde(default)]
    pub scheme: Scheme,
    /// macOS: SHA-256 (hex) of the Touch ID enrolment when device unlock was
    /// turned on. Another value means fingerprints were added or removed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment: Option<String>,
}

/// Where a device slot's key comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Scheme {
    /// A random key in the credential store, read after a yes/no prompt.
    #[default]
    Store,
    /// Windows: derived from a Windows Hello signature, stored nowhere.
    Hello,
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

/// Unlocks the vault at `paths` with this computer's device slot, after the
/// system prompt. Fails with `not_found` (and forgets device unlock here)
/// when the slot or its key is gone, or fingerprints changed.
pub fn unlock(data_dir: &Path, paths: &VaultPaths) -> AppResult<Vault> {
    let files = vault::probe(paths)?;
    let link = load_link(data_dir)
        .filter(|link| files.vault_id.as_deref() == Some(link.vault_id.as_str()))
        .ok_or_else(|| AppError::not_found("device unlock is not set up here"))?;
    match link.scheme {
        Scheme::Hello => unlock_hello(data_dir, paths, &link),
        Scheme::Store if biometrics::BOUND_KEYS => upgrade_to_hello(data_dir, paths, &link),
        Scheme::Store => unlock_store(data_dir, paths, &link),
    }
}

/// Windows: signs the vault's challenge with its Windows Hello key.
fn unlock_hello(data_dir: &Path, paths: &VaultPaths, link: &DeviceLink) -> AppResult<Vault> {
    let challenge = vault::device_challenge(&link.vault_id);
    let signature = match biometrics::sign_with_bound_key(&hello_name(&link.vault_id), &challenge) {
        Ok(signature) => signature,
        Err(sshkm_os::Error::NotFound(_)) => {
            return Err(forget(data_dir, link, "the Windows Hello key is gone"));
        }
        Err(error) => return Err(os_error(error)),
    };
    let key = vault::bound_device_key(&signature, &link.vault_id);
    open_slot(data_dir, paths, link, &key)
}

/// Windows, a link from before device unlock was bound to Windows Hello: a
/// new Windows Hello key confirms the user, the stored key opens the vault
/// this one last time, and a slot bound to the new key replaces the old one.
/// The new slot is added and the link rewritten first; only then is the
/// stored key deleted, which leaves the old slot unusable even if removing
/// it fails. If an earlier step fails, the new slot goes and the old way
/// stays.
fn upgrade_to_hello(data_dir: &Path, paths: &VaultPaths, link: &DeviceLink) -> AppResult<Vault> {
    let name = hello_name(&link.vault_id);
    let signature = biometrics::create_bound_key(&name, &vault::device_challenge(&link.vault_id))
        .map_err(os_error)?;
    let Some(old_key) = load_key(link)? else {
        return Err(forget(data_dir, link, "the device key is gone"));
    };
    let mut vault = open_slot(data_dir, paths, link, &old_key)?;
    let key = vault::bound_device_key(&signature, &link.vault_id);
    let slot_id = match vault.enable_device_unlock_with(&key) {
        Ok(slot_id) => slot_id,
        Err(error) => {
            log::warn!("device unlock not upgraded: {error}");
            return Ok(vault);
        }
    };
    let new = DeviceLink {
        slot_id: slot_id.clone(),
        scheme: Scheme::Hello,
        ..link.clone()
    };
    if let Err(error) = save_link(data_dir, Some(&new)) {
        log::warn!("device unlock not upgraded: {error}");
        let _ = vault.disable_device_unlock(&slot_id);
        return Ok(vault);
    }
    let _ = delete_store_item(link);
    if let Err(error) = vault.disable_device_unlock(&link.slot_id) {
        log::warn!("the old device slot stays, without its key: {error}");
    }
    log::info!("device unlock is now bound to Windows Hello");
    Ok(vault)
}

/// Windows: after the vault was opened another way (master password,
/// recovery key), a link from before device unlock was bound to Windows
/// Hello is retired, since any program of the user can read its stored key.
/// The slot and the key go, and device unlock must be turned on again. It
/// can't be upgraded here, which would show a Windows Hello prompt nobody
/// asked for.
pub fn retire_stored_key(data_dir: &Path, vault: &mut Vault) {
    if !biometrics::BOUND_KEYS {
        return;
    }
    let Some(link) = load_link(data_dir) else {
        return;
    };
    if link.scheme != Scheme::Store || link.vault_id != vault.vault_id() {
        return;
    }
    let _ = delete_store_item(&link);
    if let Err(error) = vault.disable_device_unlock(&link.slot_id) {
        log::warn!("the old device slot stays, without its key: {error}");
    }
    if let Err(error) = save_link(data_dir, None) {
        log::warn!("device unlock not forgotten: {error}");
    }
    log::info!("device unlock from before Windows Hello keys was turned off");
}

/// macOS (and the fallback elsewhere): Touch ID says yes, then the key is
/// read from the keychain. Refused if fingerprints changed since device
/// unlock was turned on; a link from before that was recorded records it.
fn unlock_store(data_dir: &Path, paths: &VaultPaths, link: &DeviceLink) -> AppResult<Vault> {
    authenticate(&Localized::new(
        "unlock the password vault",
        "разблокировать хранилище паролей",
        "parollar omborini ochish",
    ))?;
    let enrollment = enrollment();
    if link
        .enrollment
        .as_ref()
        .is_some_and(|expected| enrollment.as_ref() != Some(expected))
    {
        return Err(forget(
            data_dir,
            link,
            "Touch ID fingerprints were added or removed",
        ));
    }
    let Some(key) = load_key(link)? else {
        return Err(forget(
            data_dir,
            link,
            "the device key is gone from the credential store",
        ));
    };
    let vault = open_slot(data_dir, paths, link, &key)?;
    if link.enrollment.is_none() && enrollment.is_some() {
        let recorded = DeviceLink {
            enrollment,
            ..link.clone()
        };
        if let Err(error) = save_link(data_dir, Some(&recorded)) {
            log::warn!("Touch ID enrolment not recorded: {error}");
        }
    }
    Ok(vault)
}

/// Opens this computer's slot with `key`; when it no longer opens, device
/// unlock is forgotten here.
fn open_slot(
    data_dir: &Path,
    paths: &VaultPaths,
    link: &DeviceLink,
    key: &[u8; 32],
) -> AppResult<Vault> {
    try_slot(paths, link, key)?.ok_or_else(|| {
        forget(
            data_dir,
            link,
            "device unlock was turned off for this vault",
        )
    })
}

/// The vault, or `None` if the slot was removed elsewhere (e.g. a new
/// recovery key) or `key` no longer opens it (a new Windows Hello key).
fn try_slot(paths: &VaultPaths, link: &DeviceLink, key: &[u8; 32]) -> AppResult<Option<Vault>> {
    match Vault::unlock_with_device(paths, &link.slot_id, key) {
        Ok(vault) => Ok(Some(vault)),
        Err(e) if matches!(e.code(), ErrorCode::NotFound | ErrorCode::WrongPassphrase) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Turns on device unlock for `vault` on this computer, after its master
/// password was checked: the system prompt first, then a new slot replaces
/// this computer's earlier one. On Windows that is two prompts, one to make
/// the vault's Windows Hello key and one to sign with it.
pub fn enable(data_dir: &Path, vault: &mut Vault) -> AppResult<()> {
    let vault_id = vault.vault_id().to_owned();
    let bound_key = if biometrics::BOUND_KEYS {
        // Replaces this vault's earlier Windows Hello key, if any.
        let signature = biometrics::create_bound_key(
            &hello_name(&vault_id),
            &vault::device_challenge(&vault_id),
        )
        .map_err(os_error)?;
        Some(vault::bound_device_key(&signature, &vault_id))
    } else {
        authenticate(&Localized::new(
            "turn on Touch ID for the password vault",
            "включить Touch ID для хранилища паролей",
            "parollar ombori uchun Touch IDni yoqish",
        ))?;
        None
    };
    if let Some(old) = load_link(data_dir) {
        if old.vault_id == vault_id {
            vault.disable_device_unlock(&old.slot_id)?;
        }
        let _ = delete_store_item(&old);
        if old.vault_id != vault_id {
            let _ = biometrics::delete_bound_key(&hello_name(&old.vault_id));
        }
        save_link(data_dir, None)?;
    }
    let link = if let Some(key) = bound_key {
        DeviceLink {
            slot_id: vault.enable_device_unlock_with(&key)?,
            vault_id,
            scheme: Scheme::Hello,
            enrollment: None,
        }
    } else {
        let device_key = vault.enable_device_unlock()?;
        let link = DeviceLink {
            vault_id,
            slot_id: device_key.slot_id.clone(),
            scheme: Scheme::Store,
            enrollment: enrollment(),
        };
        if let Err(error) = store_key(&link, &device_key.key) {
            vault.disable_device_unlock(&link.slot_id)?;
            return Err(error);
        }
        link
    };
    if let Err(error) = save_link(data_dir, Some(&link)) {
        delete_key_material(&link);
        vault.disable_device_unlock(&link.slot_id)?;
        return Err(error);
    }
    Ok(())
}

/// Forgets device unlock on this computer: the stored key or Windows Hello
/// key, and the link. The caller removes the slot from the vault.
pub fn disable(data_dir: &Path, link: &DeviceLink) -> AppResult<()> {
    delete_key_material(link);
    save_link(data_dir, None)
}

/// [`disable`] after something went wrong, as the error to report.
fn forget(data_dir: &Path, link: &DeviceLink, message: &str) -> AppError {
    let _ = disable(data_dir, link);
    AppError::not_found(message)
}

fn delete_key_material(link: &DeviceLink) {
    let _ = delete_store_item(link);
    let _ = biometrics::delete_bound_key(&hello_name(&link.vault_id));
}

/// The Windows Hello key of a vault on this computer, as Windows names it.
fn hello_name(vault_id: &str) -> String {
    format!("SSH Key Manager vault {vault_id}")
}

/// macOS: SHA-256 (hex) of the current Touch ID enrolment.
fn enrollment() -> Option<String> {
    biometrics::enrollment().map(|state| hex_encode(&Sha256::digest(&state)))
}

/// Shows the system prompt: macOS puts `reason` after "<app> is trying to".
pub(crate) fn authenticate(reason: &Localized) -> AppResult<()> {
    biometrics::authenticate(reason.pick()).map_err(os_error)
}

fn store_key(link: &DeviceLink, key: &[u8; 32]) -> AppResult<()> {
    let hex = Zeroizing::new(hex_encode(key));
    let secret = SecretString::from(hex.as_str().to_owned());
    sshkm_os::secret_store::set(SERVICE, &link.account(), &secret).map_err(os_error)
}

/// The device key, or `None` if this computer's store has no item for it.
fn load_key(link: &DeviceLink) -> AppResult<Option<Zeroizing<[u8; 32]>>> {
    let Some(secret) = sshkm_os::secret_store::get(SERVICE, &link.account()).map_err(os_error)?
    else {
        return Ok(None);
    };
    hex_decode(secret.expose_secret())
        .map(Some)
        .ok_or_else(|| AppError::new(ErrorCode::Parse, "unreadable device key"))
}

fn delete_store_item(link: &DeviceLink) -> AppResult<()> {
    sshkm_os::secret_store::delete(SERVICE, &link.account()).map_err(os_error)
}

/// Locks the vault whenever the screen locks, if the settings say so, and
/// ends the user's session either way. On Windows registering can fail early
/// after boot, so it is retried for a while.
pub fn watch_screen_lock(runtime: Arc<VaultRuntime>, app: AppHandle) {
    thread::spawn(move || {
        for attempt in 1..=10 {
            let runtime = Arc::clone(&runtime);
            let app = app.clone();
            let on_lock = move || {
                if runtime.settings().lock_on_screen_lock {
                    // On a thread of its own: the lock may first take the
                    // last edits of the files written only while unlocked,
                    // and the OS delivers this where it shouldn't wait.
                    let (runtime, app) = (Arc::clone(&runtime), app.clone());
                    thread::spawn(move || runtime.lock(&app, LockReason::ScreenLock));
                } else {
                    runtime.end_session();
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
        sshkm_os::Error::NotFound(_) => ErrorCode::NotFound,
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

    fn link(vault_id: &str, slot_id: &str) -> DeviceLink {
        DeviceLink {
            vault_id: vault_id.into(),
            slot_id: slot_id.into(),
            scheme: Scheme::Hello,
            enrollment: None,
        }
    }

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
            enrollment: Some("ab".into()),
            ..link("v", "s")
        };
        save_link(dir.path(), Some(&link)).unwrap();
        assert_eq!(load_link(dir.path()), Some(link.clone()));
        assert_eq!(link.account(), "v/s");
        save_link(dir.path(), None).unwrap();
        save_link(dir.path(), None).unwrap();
        assert!(load_link(dir.path()).is_none());
    }

    #[test]
    fn links_from_before_the_schemes_read_as_stored_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(LINK_FILE),
            r#"{"vaultId":"v","slotId":"s"}"#,
        )
        .unwrap();
        let old = load_link(dir.path()).unwrap();
        assert_eq!(old.scheme, Scheme::Store);
        assert_eq!(old.enrollment, None);
    }

    #[test]
    fn enabled_only_for_the_linked_vault_and_an_existing_slot() {
        let link = link("v", "s");
        let slots = vec!["s".to_owned()];
        assert!(status(Some(&link), Some("v"), &slots).enabled);
        assert!(!status(Some(&link), Some("other"), &slots).enabled);
        assert!(!status(Some(&link), Some("v"), &[]).enabled);
        assert!(!status(None, Some("v"), &slots).enabled);
    }

    /// The Windows Hello signature derives the slot's key; the vault opens
    /// with it, with nothing stored on this computer.
    #[test]
    fn a_slot_bound_to_a_signature_opens_with_that_signature_only() {
        let dir = tempfile::tempdir().unwrap();
        let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
        let (mut vault, _) = Vault::create(&paths, &SecretString::from("m")).unwrap();
        let id = vault.vault_id().to_owned();
        let signature = [3u8; 256];
        let link = DeviceLink {
            slot_id: vault
                .enable_device_unlock_with(&vault::bound_device_key(&signature, &id))
                .unwrap(),
            ..link(&id, "")
        };
        let key = vault::bound_device_key(&signature, &id);
        assert!(try_slot(&paths, &link, &key).unwrap().is_some());
        // Another signature (a new Windows Hello key) doesn't open it.
        let other = vault::bound_device_key(&[4u8; 256], &id);
        assert!(try_slot(&paths, &link, &other).unwrap().is_none());
        // Nor does anything once the slot is gone.
        vault.disable_device_unlock(&link.slot_id).unwrap();
        assert!(try_slot(&paths, &link, &key).unwrap().is_none());
    }
}
