//! The vault on the phone: one vault in the app's private folder, opened
//! with this phone's master password or with the fingerprint, and its
//! logins.
//!
//! The phone never makes a vault of its own, so two vaults never have to be
//! merged: it gets the one the user's computers share — the database file
//! and its secret — from a computer (step E of `docs/mobile.md`). What it
//! received waits in memory ([`VaultStatus::Received`]) until the user sets
//! this phone's master password ([`PhoneVault::set_master_password`]), as on
//! a new computer ([`Vault::join`]).
//!
//! Fingerprint unlock is a device key slot, as Touch ID on a Mac: the slot's
//! random key comes out of [`PhoneVault::enable_device_unlock`] once, the app
//! keeps it wrapped by an Android Keystore key that only the fingerprint
//! releases, and hands it back to [`PhoneVault::unlock_with_device`].
//!
//! The unlocked [`Vault`] exists only in this process; [`PhoneVault::lock`]
//! drops it. Logins reach the app as [`Login`] and [`LoginDetail`], which
//! hold no secret: a password crosses the bridge only when the user asks to
//! see or copy it ([`PhoneVault::password`]), and a 2FA secret never does,
//! only its current code ([`PhoneVault::otp_code`]). Every change is saved
//! at once with [`Vault::save`], which keeps a backup of the previous file.

mod logins;
#[cfg(feature = "test-vault")]
mod test_vault;
#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use sshkm_core::vault::{self, Vault, VaultPaths};
use sshkm_core::{ErrorCode, ExposeSecret, SecretString};
use zeroize::Zeroizing;

pub use self::logins::{Login, LoginDetail, LoginInput, OtpCode, ProjectLabel};
use crate::CoreError;

/// The database's file name in the vault's folder; the key slots are
/// `vault.keys` next to it.
const DATABASE_FILE: &str = "vault.kdbx";
/// Backups of the database, one per change, in the vault's folder.
const BACKUPS_DIR: &str = "backups";

/// Where the phone's vault stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum VaultStatus {
    /// No vault yet: it comes from one of the user's computers.
    Missing,
    /// A vault came from a computer and waits for this phone's master
    /// password.
    Received,
    /// The vault is here and locked.
    Locked,
    /// The vault is open.
    Unlocked,
}

/// What can be told about the vault without unlocking it.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct VaultInfo {
    pub status: VaultStatus,
    /// Random id of this phone's key slots file (each device's has its
    /// own); names the Keystore key of fingerprint unlock. `None` until the
    /// vault is here.
    pub vault_id: Option<String>,
    /// Ids of the vault's device slots: on the phone, at most its own.
    pub device_slots: Vec<String>,
}

/// A new fingerprint slot: its id and the random key that opens it. The app
/// wraps the key with Keystore at once and wipes its copy.
#[derive(uniffi::Record)]
pub struct DeviceUnlockKey {
    pub slot_id: String,
    /// 32 bytes.
    pub key: Vec<u8>,
}

impl std::fmt::Debug for DeviceUnlockKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceUnlockKey")
            .field("slot_id", &self.slot_id)
            .finish_non_exhaustive()
    }
}

/// A vault received from a computer, before this phone has a master password
/// for it.
struct Received {
    database: Zeroizing<Vec<u8>>,
    secret: SecretString,
}

/// The phone's vault, in a folder of the app's private storage.
#[derive(uniffi::Object)]
pub struct PhoneVault {
    paths: VaultPaths,
    backups: PathBuf,
    received: Mutex<Option<Received>>,
    open: Mutex<Option<Vault>>,
}

impl std::fmt::Debug for PhoneVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhoneVault")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

#[uniffi::export]
impl PhoneVault {
    /// The vault in `folder`, which the app keeps to itself (no backup).
    /// Nothing is read or written until asked.
    #[uniffi::constructor]
    pub fn new(folder: String) -> Arc<Self> {
        let folder = PathBuf::from(folder);
        Arc::new(Self {
            paths: VaultPaths::new(folder.join(DATABASE_FILE)),
            backups: folder.join(BACKUPS_DIR),
            received: Mutex::new(None),
            open: Mutex::new(None),
        })
    }

    /// Where the vault stands, read from its files without decrypting
    /// anything.
    pub fn info(&self) -> Result<VaultInfo, CoreError> {
        let files = vault::probe(&self.paths)?;
        let status = if lock(&self.open).is_some() {
            VaultStatus::Unlocked
        } else if files.exists {
            VaultStatus::Locked
        } else if lock(&self.received).is_some() {
            VaultStatus::Received
        } else {
            VaultStatus::Missing
        };
        Ok(VaultInfo {
            status,
            vault_id: files.exists.then_some(files.vault_id).flatten(),
            device_slots: if files.exists {
                files.device_slots
            } else {
                Vec::new()
            },
        })
    }

    /// Sets this phone's master password for the vault it received, which
    /// is then written to the folder and opened.
    pub fn set_master_password(&self, master: String) -> Result<(), CoreError> {
        let master = SecretString::from(master);
        let mut received = lock(&self.received);
        let Some(pending) = received.as_ref() else {
            return Err(failed(ErrorCode::NotFound, "no vault was received"));
        };
        sshkm_core::fsutil::ensure_private_dir(self.folder())?;
        let vault = Vault::join(&self.paths, &pending.database, &pending.secret, &master)?;
        received.take();
        *lock(&self.open) = Some(vault);
        Ok(())
    }

    /// Opens the vault with this phone's master password. Wrong passwords in
    /// a row make the next attempt wait (`TooManyAttempts`).
    pub fn unlock(&self, master: String) -> Result<(), CoreError> {
        let master = SecretString::from(master);
        let vault = Vault::unlock(&self.paths, &master)?;
        *lock(&self.open) = Some(vault);
        Ok(())
    }

    /// Opens the vault with the key of its fingerprint slot, which Keystore
    /// released after the fingerprint. The key is wiped here when done.
    pub fn unlock_with_device(&self, slot_id: &str, key: Vec<u8>) -> Result<(), CoreError> {
        let key = Zeroizing::new(key);
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            key.as_slice()
                .try_into()
                .map_err(|_| failed(ErrorCode::InvalidInput, "a device key is 32 bytes"))?,
        );
        let vault = Vault::unlock_with_device(&self.paths, slot_id, &key)?;
        *lock(&self.open) = Some(vault);
        Ok(())
    }

    /// Locks the vault: the open database and its secret are dropped from
    /// memory. Locking a locked vault does nothing.
    pub fn lock(&self) {
        drop(lock(&self.open).take());
    }

    pub fn is_unlocked(&self) -> bool {
        lock(&self.open).is_some()
    }

    /// Checks this phone's master password without changing anything; the
    /// same wait after wrong ones as unlocking.
    pub fn verify_master_password(&self, master: String) -> Result<(), CoreError> {
        let master = SecretString::from(master);
        self.read(|vault| vault.verify_master_password(&master))
    }

    /// Adds a fingerprint slot for this phone. The key comes back once, for
    /// the app to wrap with Keystore.
    pub fn enable_device_unlock(&self) -> Result<DeviceUnlockKey, CoreError> {
        let new = self.write_slots(Vault::enable_device_unlock)?;
        Ok(DeviceUnlockKey {
            slot_id: new.slot_id,
            key: new.key.to_vec(),
        })
    }

    /// Removes a fingerprint slot, e.g. after a new fingerprint was enrolled
    /// and Keystore dropped the key that opened it.
    pub fn disable_device_unlock(&self, slot_id: &str) -> Result<(), CoreError> {
        self.write_slots(|vault| vault.disable_device_unlock(slot_id))
    }
}

impl PhoneVault {
    /// Takes a vault another of the user's devices sent: its database file
    /// and its secret, checked here and kept in memory until this phone's
    /// master password is set ([`Self::set_master_password`]). Fails if the
    /// phone has a vault already: two vaults are never merged.
    pub fn receive(&self, database: Vec<u8>, secret: SecretString) -> Result<(), CoreError> {
        let database = Zeroizing::new(database);
        if self.paths.database.exists() {
            return Err(failed(
                ErrorCode::AlreadyExists,
                "this phone has a vault already",
            ));
        }
        vault::check_shared(&database, &secret)?;
        *lock(&self.received) = Some(Received { database, secret });
        Ok(())
    }

    fn folder(&self) -> &std::path::Path {
        self.paths
            .database
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
    }

    /// Runs `work` on the open vault.
    fn read<T>(&self, work: impl FnOnce(&Vault) -> sshkm_core::Result<T>) -> Result<T, CoreError> {
        let open = lock(&self.open);
        let vault = open.as_ref().ok_or_else(locked)?;
        Ok(work(vault)?)
    }

    /// Runs `work` on the open vault and saves the database, with a backup
    /// of the previous file. If `work` or the save fails, the vault in memory
    /// goes back to what is on disk, so a half-made change never goes out
    /// with the next save.
    fn change<T>(
        &self,
        work: impl FnOnce(&mut Vault) -> sshkm_core::Result<T>,
    ) -> Result<T, CoreError> {
        let mut open = lock(&self.open);
        let vault = open.as_mut().ok_or_else(locked)?;
        let before = vault.snapshot();
        let result = match work(vault) {
            Ok(result) => result,
            Err(error) => {
                vault.restore(before);
                return Err(error.into());
            }
        };
        if let Err(error) = vault.save(&self.backups) {
            vault.restore(before);
            // Reload what is on disk, whatever happened to the write.
            let _ = vault.refresh();
            return Err(error.into());
        }
        Ok(result)
    }

    /// Runs `work`, which changes the key slots file (written by the core
    /// itself), on the open vault.
    fn write_slots<T>(
        &self,
        work: impl FnOnce(&mut Vault) -> sshkm_core::Result<T>,
    ) -> Result<T, CoreError> {
        let mut open = lock(&self.open);
        let vault = open.as_mut().ok_or_else(locked)?;
        Ok(work(vault)?)
    }
}

/// A lock that a panic elsewhere left poisoned still holds a usable value:
/// the vault or nothing.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn failed(code: ErrorCode, detail: &str) -> CoreError {
    CoreError::Failed {
        code,
        detail: detail.to_owned(),
    }
}

fn locked() -> CoreError {
    failed(ErrorCode::VaultLocked, "the vault is locked")
}

/// A secret as the app shows or copies it.
fn exposed(secret: &SecretString) -> String {
    secret.expose_secret().to_owned()
}
