//! The password vault.
//!
//! On disk a vault is two files side by side:
//!
//! - `vault.kdbx`: a standard KeePass database (KDBX 4.1 with Argon2id and
//!   ChaCha20) that holds every entry. Its password is the *vault secret*: for
//!   a vault made here, the recovery key, so KeePassXC opens the file with it.
//! - `vault.keys`: the key slots that open the secret with the master password
//!   or with Touch ID / Windows Hello ([`slots`]).
//!
//! An unlocked [`Vault`] holds the decrypted database and the secret in memory;
//! dropping it is locking it. Entries reach the UI as [`EntrySummary`] and
//! [`EntryDetail`], which never contain a password or a 2FA secret: those are
//! read one at a time with [`Vault::secret`]. A password (or a key's
//! passphrase) is shown to the user when they ask; a 2FA secret never is.
//!
//! Every change is written at once (atomically, after a backup of the previous
//! file). If another program or computer changed the database or the key slots
//! meanwhile — a vault in a synced folder — [`Vault::refresh`] picks the change
//! up, and a write that would overwrite it fails with [`Error::Conflict`]
//! instead.

mod audit;
mod breach;
mod browsers;
mod contacts;
pub mod envs;
mod export;
mod generator;
mod import;
mod kdf;
mod location;
mod own_devices;
pub mod projects;
mod recovery;
mod slots;
#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use keepass::config::{DatabaseConfig, DatabaseVersion, KdfConfig, OuterCipherConfig};
use keepass::db::{EntryId, EntryRef, GroupId, TOTP, Times, Value, fields};
use keepass::{Database, DatabaseKey};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub use self::audit::{VaultAuditInput, VaultFinding, VaultFindingKind};
pub use self::breach::{
    BreachCache, BreachQuery, MAX_RANGE_BYTES, PADDING_HEADER, RANGE_URL, RangePrefix,
};
pub use self::browsers::{BrowserKeys, KeysUsed, PairedBrowser};
pub use self::contacts::Contact;
pub use self::generator::{
    GenerateOptions, Generated, SecretPreset, Strength, TokenEncoding, UuidVersion, generate,
    generate_preset, strength,
};
pub use self::import::{
    BrowserFamily, BrowserKeyStore, BrowserLogins, BrowserProfile, BrowserReadError, CsvFormat,
    ImportComparison, ImportOutcome, ImportPreview, ImportRow, SafeStorage, browser_profiles,
};
pub use self::location::{check_database, copy_files, remove_files};
pub use self::own_devices::{DeviceRecord, MAX_RECORDS, OwnDevice, check_records};
use self::slots::KeySlots;
use crate::{Error, Result, fsutil};

/// Largest database file that is opened, or taken from another computer.
pub const MAX_DATABASE_SIZE: u64 = 256 * 1024 * 1024;
/// Largest value of a single field.
const MAX_FIELD_LEN: usize = 64 * 1024;

/// Custom fields that link an entry to SSH things. KeePassXC shows them as
/// additional attributes.
const KIND_FIELD: &str = "sshkm.kind";
const HOST_FIELD: &str = "sshkm.host";
const KEY_FIELD: &str = "sshkm.fingerprint";
/// A 2FA secret an import could not read (`steam://`, HOTP, …): protected
/// like a password, never shown in the app, and visible in KeePassXC's
/// additional attributes.
const UNREADABLE_OTP_FIELD: &str = "Unrecognized 2FA secret";

/// What Windows Hello signs to unlock the vault `vault_id` on a computer; see
/// [`bound_device_key`].
pub fn device_challenge(vault_id: &str) -> Vec<u8> {
    slots::device_challenge(vault_id)
}

/// The key of a device slot made from a Windows Hello signature of
/// [`device_challenge`]: only that signature, which takes the user's PIN,
/// face or fingerprint, opens the slot.
pub fn bound_device_key(signature: &[u8], vault_id: &str) -> Zeroizing<[u8; 32]> {
    slots::bound_device_key(signature, vault_id)
}

/// The canonical form of a recovery key (as [`Vault::create`] returns it),
/// or `None` if `input` is not one.
pub fn canonical_recovery_key(input: &SecretString) -> Option<SecretString> {
    recovery::normalize(input)
}

/// A field name and its wanted value; `None` removes the field.
type FieldChange = (&'static str, Option<Value<String>>);

/// Where a vault's two files are.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct VaultPaths {
    /// The KeePass database.
    pub database: PathBuf,
    /// The key slots, next to it: `<name>.keys`.
    pub keys: PathBuf,
}

impl VaultPaths {
    /// The paths for a database file; the key slots file sits next to it.
    pub fn new(database: impl Into<PathBuf>) -> Self {
        let database = database.into();
        let keys = database.with_extension("keys");
        Self { database, keys }
    }
}

/// What can be told about a vault without unlocking it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct VaultFiles {
    /// The database file exists.
    pub exists: bool,
    /// The master password opens it. When `false` but the database exists
    /// (a KeePass file brought from elsewhere, or a lost keys file), it opens
    /// with the recovery key / KeePass password, which then sets one.
    pub has_master_password: bool,
    /// Some computer can open it with Touch ID / Windows Hello.
    pub has_device_unlock: bool,
    /// Ids of the device slots, one per computer with device unlock.
    pub device_slots: Vec<String>,
    /// Random id of the vault; names its item in the OS credential store.
    pub vault_id: Option<String>,
}

/// Checks that `database` is a vault `secret` opens, with sane key
/// derivation settings: what a computer does before it takes a vault
/// another one sent.
pub fn check_shared(database: &[u8], secret: &SecretString) -> Result<()> {
    if u64::try_from(database.len()).unwrap_or(u64::MAX) > MAX_DATABASE_SIZE {
        return Err(Error::invalid("the vault is too large"));
    }
    parse_database(database, secret).map(drop)
}

/// Looks at the vault's files without decrypting anything.
pub fn probe(paths: &VaultPaths) -> Result<VaultFiles> {
    let slots = KeySlots::load(&paths.keys)?;
    Ok(VaultFiles {
        exists: paths.database.is_file(),
        has_master_password: slots.as_ref().is_some_and(KeySlots::has_password),
        has_device_unlock: slots.as_ref().is_some_and(|s| !s.device_ids().is_empty()),
        device_slots: slots.as_ref().map(KeySlots::device_ids).unwrap_or_default(),
        vault_id: slots.map(|s| s.vault_id),
    })
}

/// What an entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum EntryKind {
    /// A website, service or anything else.
    #[default]
    Login,
    /// The password of an SSH host from `~/.ssh/config`.
    Host,
    /// The passphrase of an SSH key.
    Key,
}

impl EntryKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Host => "host",
            Self::Key => "key",
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "host" => Self::Host,
            "key" => Self::Key,
            _ => Self::Login,
        }
    }
}

/// An entry as the list shows it. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EntrySummary {
    /// The KeePass entry UUID.
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub kind: EntryKind,
    /// For [`EntryKind::Host`]: the `Host` alias in `~/.ssh/config`.
    pub host: Option<String>,
    /// For [`EntryKind::Key`]: the key's `SHA256:…` fingerprint.
    pub key_fingerprint: Option<String>,
    pub has_password: bool,
    /// A 2FA (TOTP) secret is stored.
    pub has_otp: bool,
    /// Folder path inside the database, e.g. `Work/Servers`; `None` at the top
    /// level. Vaults made here have no folders, KeePass files may.
    pub group: Option<String>,
    /// The entry is in the vault's recycle bin.
    pub in_trash: bool,
    /// RFC 3339, UTC.
    pub created: Option<String>,
    /// RFC 3339, UTC.
    pub modified: Option<String>,
}

/// Everything about an entry except its secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EntryDetail {
    #[serde(flatten)]
    #[cfg_attr(feature = "ts", ts(flatten))]
    pub summary: EntrySummary,
    pub notes: String,
    /// When the current password was set (RFC 3339, UTC), from the history.
    pub password_changed: Option<String>,
    /// Number of earlier versions kept in the history.
    pub history_len: u32,
}

/// A new entry, or the new state of an existing one.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct EntryInput {
    pub title: String,
    #[serde(default)]
    pub username: String,
    /// `None` keeps the current password (an empty one for a new entry).
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub password: Option<SecretString>,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    /// A 2FA secret: an `otpauth://` URI or the base32 key a site shows.
    /// `None` keeps the current one; an empty string removes it.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub otp: Option<SecretString>,
    #[serde(default)]
    pub kind: EntryKind,
    /// The `Host` alias, for [`EntryKind::Host`].
    #[serde(default)]
    pub host: Option<String>,
    /// The key fingerprint, for [`EntryKind::Key`].
    #[serde(default)]
    pub key_fingerprint: Option<String>,
}

/// A secret field of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum SecretField {
    Password,
    /// The `otpauth://` URI.
    Otp,
}

/// A new device slot: its id and the random key that opens it, to be kept in
/// this computer's credential store.
pub struct DeviceKey {
    pub slot_id: String,
    pub key: Zeroizing<[u8; 32]>,
}

/// An unlocked vault. Dropping it locks the vault.
pub struct Vault {
    paths: VaultPaths,
    db: Database,
    secret: SecretString,
    slots: KeySlots,
    /// SHA-256 of the database file as last read or written here.
    disk_hash: [u8; 32],
    /// The same for the key slots file; `None` while there is none.
    keys_hash: Option<[u8; 32]>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("paths", &self.paths)
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates a new, empty vault and returns it unlocked together with its
    /// recovery key, which must be shown to the user once.
    pub fn create(paths: &VaultPaths, master: &SecretString) -> Result<(Self, SecretString)> {
        check_master(master)?;
        if paths.database.exists() {
            return Err(Error::AlreadyExists(paths.database.display().to_string()));
        }
        let secret = recovery::generate();
        let mut db = Database::with_config(new_config());
        db.meta.database_name = Some("SSH Key Manager".into());
        db.meta.generator = Some("SSH Key Manager".into());
        db.meta.recyclebin_enabled = Some(true);
        let bytes = serialize(&db, &secret)?;

        let mut slots = KeySlots::new();
        slots.set_password(&secret, master)?;
        // The keys first: on a crash in between, a stray keys file is harmless.
        let keys_hash = slots.save(&paths.keys)?;
        fsutil::write_new(&paths.database, &bytes, 0o600)?;

        let vault = Self {
            paths: paths.clone(),
            db,
            secret: duplicate(&secret),
            slots,
            disk_hash: sha256(&bytes),
            keys_hash: Some(keys_hash),
        };
        Ok((vault, secret))
    }

    /// Unlocks with the master password.
    pub fn unlock(paths: &VaultPaths, master: &SecretString) -> Result<Self> {
        let (slots, keys_hash) = load_slots(paths)?;
        let secret = slots.open_password(master)?;
        Self::open(paths, secret, slots, keys_hash)
    }

    /// Unlocks with this computer's device key, released by Touch ID or
    /// derived from a Windows Hello signature ([`bound_device_key`]).
    pub fn unlock_with_device(
        paths: &VaultPaths,
        slot_id: &str,
        device_key: &[u8; 32],
    ) -> Result<Self> {
        let (slots, keys_hash) = load_slots(paths)?;
        let secret = slots.open_device(slot_id, device_key)?;
        Self::open(paths, secret, slots, keys_hash)
    }

    /// Unlocks with the recovery key — or, for a KeePass database brought from
    /// elsewhere, its password — and sets a new master password.
    pub fn recover(
        paths: &VaultPaths,
        recovery_key: &SecretString,
        new_master: &SecretString,
    ) -> Result<Self> {
        check_master(new_master)?;
        let bytes = read_database(&paths.database)?;
        kdf::check_kdbx(&bytes)?;
        let candidates = [
            recovery::normalize(recovery_key),
            Some(duplicate(recovery_key)),
        ];
        let mut opened = None;
        for secret in candidates.into_iter().flatten() {
            match Database::parse(&bytes, key(&secret)) {
                Ok(db) => {
                    opened = Some((db, secret));
                    break;
                }
                Err(e) => match open_error(e) {
                    Error::WrongPassphrase => {}
                    other => return Err(other),
                },
            }
        }
        let (db, secret) = opened.ok_or(Error::WrongPassphrase)?;
        let (slots, keys_hash) = match KeySlots::read(&paths.keys)? {
            Some((slots, hash)) => (slots, Some(hash)),
            None => (KeySlots::new(), None),
        };
        let mut vault = Self {
            paths: paths.clone(),
            db,
            secret,
            slots,
            disk_hash: sha256(&bytes),
            keys_hash,
        };
        let mut slots = vault.slots.clone();
        slots.set_password(&vault.secret, new_master)?;
        vault.write_slots(slots)?;
        Ok(vault)
    }

    /// Sets up the vault another of the user's computers sent — its
    /// database file and its secret — with this computer's own master
    /// password. Fails if a database is there already.
    pub fn join(
        paths: &VaultPaths,
        database: &[u8],
        secret: &SecretString,
        master: &SecretString,
    ) -> Result<Self> {
        check_master(master)?;
        if paths.database.exists() {
            return Err(Error::AlreadyExists(paths.database.display().to_string()));
        }
        let db = parse_database(database, secret)?;
        let mut slots = KeySlots::new();
        slots.set_password(secret, master)?;
        // The keys first, as in `create`; a stray keys file without its
        // database opens nothing and is replaced.
        let keys_hash = slots.save(&paths.keys)?;
        fsutil::write_new(&paths.database, database, 0o600)?;
        Ok(Self {
            paths: paths.clone(),
            db,
            secret: duplicate(secret),
            slots,
            disk_hash: sha256(database),
            keys_hash: Some(keys_hash),
        })
    }

    fn open(
        paths: &VaultPaths,
        secret: SecretString,
        slots: KeySlots,
        keys_hash: [u8; 32],
    ) -> Result<Self> {
        let bytes = read_database(&paths.database)?;
        let db = parse_database(&bytes, &secret).map_err(|e| match e {
            // The slot opened, so the keys file belongs to another database.
            Error::WrongPassphrase => Error::Parse(format!(
                "{} does not belong to {}; unlock with the recovery key",
                paths.keys.display(),
                paths.database.display()
            )),
            other => other,
        })?;
        Ok(Self {
            paths: paths.clone(),
            db,
            secret,
            slots,
            disk_hash: sha256(&bytes),
            keys_hash: Some(keys_hash),
        })
    }

    pub fn paths(&self) -> &VaultPaths {
        &self.paths
    }

    /// Random id of the vault; names its item in the OS credential store.
    pub fn vault_id(&self) -> &str {
        &self.slots.vault_id
    }

    /// Ids of the device slots, one per computer with device unlock.
    pub fn device_slots(&self) -> Vec<String> {
        self.slots.device_ids()
    }

    /// The vault secret, to give a new own device along with the database
    /// file; for nothing else.
    pub fn share_secret(&self) -> SecretString {
        duplicate(&self.secret)
    }

    /// The database file as saved, for a new own device. Fails with
    /// [`Error::Conflict`] if it changed on disk since it was read here.
    pub fn saved_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = Zeroizing::new(read_database(&self.paths.database)?);
        if sha256(&bytes) != self.disk_hash {
            return Err(Error::Conflict(self.paths.database.display().to_string()));
        }
        Ok(bytes)
    }

    /// Re-reads the files that another program or computer changed. Returns
    /// whether anything was reloaded.
    pub fn refresh(&mut self) -> Result<bool> {
        // An unreadable keys file is not a reason to refuse reading entries:
        // the slots in memory stay, and the next write of the slots fails.
        let slots_changed = self.reload_slots().unwrap_or(false);
        let bytes = read_database(&self.paths.database)?;
        let hash = sha256(&bytes);
        if hash == self.disk_hash {
            return Ok(slots_changed);
        }
        self.db = parse_database(&bytes, &self.secret)?;
        self.disk_hash = hash;
        Ok(true)
    }

    /// Re-reads the key slots file if it changed on disk. When it is gone,
    /// the slots in memory stay and the next write puts it back.
    fn reload_slots(&mut self) -> Result<bool> {
        if slots::file_hash(&self.paths.keys)? == self.keys_hash {
            return Ok(false);
        }
        match KeySlots::read(&self.paths.keys)? {
            Some((slots, hash)) => {
                self.slots = slots;
                self.keys_hash = Some(hash);
            }
            None => self.keys_hash = None,
        }
        Ok(true)
    }

    /// Writes the key slots file, unless it changed on disk since it was last
    /// read or written here: then that version is loaded instead and the
    /// write fails with [`Error::Conflict`], so a slot added or a master
    /// password changed on another computer is never overwritten.
    fn write_slots(&mut self, slots: KeySlots) -> Result<()> {
        if slots::file_hash(&self.paths.keys)? != self.keys_hash {
            self.reload_slots()?;
            return Err(Error::Conflict(self.paths.keys.display().to_string()));
        }
        self.keys_hash = Some(slots.save(&self.paths.keys)?);
        self.slots = slots;
        Ok(())
    }

    /// Writes the database, keeping a backup of the previous file.
    ///
    /// Fails with [`Error::Conflict`] if the file changed on disk since it was
    /// read; this version is then saved next to the backups instead, as
    /// `<name>-conflict-<time>.kdbx`, which KeePassXC can open to compare.
    pub fn save(&mut self, backup_dir: &Path) -> Result<()> {
        if !matches!(self.db.config.version, DatabaseVersion::KDB4(_)) {
            // The writer only does KDBX 4: an old KDBX 3 file is upgraded.
            self.db.config = new_config();
        }
        let bytes = serialize(&self.db, &self.secret)?;
        self.write_database(&bytes, backup_dir, true)
    }

    /// Like [`Self::save`], without a backup of the previous file: for a
    /// change to nothing but a paired browser's keys. Such a backup would
    /// hold nothing worth going back to, and keys change about once a day,
    /// so they would push out the backups taken before real changes.
    pub fn save_without_backup(&mut self, backup_dir: &Path) -> Result<()> {
        if !matches!(self.db.config.version, DatabaseVersion::KDB4(_)) {
            return self.save(backup_dir);
        }
        let bytes = serialize(&self.db, &self.secret)?;
        self.write_database(&bytes, backup_dir, false)
    }

    fn write_database(&mut self, bytes: &[u8], backup_dir: &Path, backup: bool) -> Result<()> {
        let on_disk = match std::fs::read(&self.paths.database) {
            Ok(current) => Some(sha256(&current)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(Error::io(e, &self.paths.database)),
        };
        if on_disk.is_some_and(|hash| hash != self.disk_hash) {
            let copy = self.write_conflict_copy(bytes, backup_dir)?;
            return Err(Error::Conflict(copy.display().to_string()));
        }
        if backup {
            fsutil::backup(&self.paths.database, backup_dir)?;
        }
        fsutil::atomic_write(&self.paths.database, bytes, 0o600)?;
        self.disk_hash = sha256(bytes);
        Ok(())
    }

    fn write_conflict_copy(&self, bytes: &[u8], backup_dir: &Path) -> Result<PathBuf> {
        fsutil::ensure_private_dir(backup_dir)?;
        let stem = self
            .paths
            .database
            .file_stem()
            .map_or_else(|| "vault".into(), |s| s.to_string_lossy().into_owned());
        let stamp = time::OffsetDateTime::now_utc().unix_timestamp();
        let mut path = backup_dir.join(format!("{stem}-conflict-{stamp}.kdbx"));
        let mut n = 1;
        while path.exists() {
            path = backup_dir.join(format!("{stem}-conflict-{stamp}-{n}.kdbx"));
            n += 1;
        }
        fsutil::write_new(&path, bytes, 0o600)?;
        Ok(path)
    }

    /// Checks the master password without changing anything.
    pub fn verify_master_password(&self, master: &SecretString) -> Result<()> {
        self.slots.open_password(master).map(drop)
    }

    /// Replaces the master password.
    ///
    /// The vault secret (the recovery key) stays the same, so an old copy of
    /// the key slots file — a cloud version, a Time Machine backup — still
    /// opens the database with the old password. If that password may have
    /// leaked, make a new recovery key as well ([`Self::new_recovery_key`]).
    pub fn change_master_password(
        &mut self,
        current: &SecretString,
        new: &SecretString,
    ) -> Result<()> {
        check_master(new)?;
        self.verify_master_password(current)?;
        let mut slots = self.slots.clone();
        slots.set_password(&self.secret, new)?;
        self.write_slots(slots)
    }

    /// Replaces the recovery key and re-encrypts the database with it, and
    /// with it the backups and conflict copies in `backup_dir`, so the old key
    /// opens none of the files this app keeps. Copies made elsewhere (exports,
    /// cloud versions, Time Machine) are out of reach and still open with it.
    ///
    /// Device unlock is switched off on every computer, because those slots
    /// hold the old key: turn it on again and delete the old credential store
    /// items. The key the user's own devices share is replaced as well, so a
    /// computer that is gone fails their check.
    pub fn new_recovery_key(
        &mut self,
        master: &SecretString,
        backup_dir: &Path,
    ) -> Result<SecretString> {
        self.refresh()?;
        self.verify_master_password(master)?;
        let secret = recovery::generate();
        let mut db = self.db.clone();
        own_devices::renew_own_key(&mut db);
        let bytes = serialize(&db, &secret)?;
        let mut slots = self.slots.clone();
        slots.set_password(&secret, master)?;
        slots.remove_all_devices();
        // The keys first: on a crash in between, the old recovery key still
        // opens the database and sets the master password again.
        self.write_slots(slots)?;
        self.write_database(&bytes, backup_dir, true)?;
        self.db = db;
        let old = std::mem::replace(&mut self.secret, duplicate(&secret));
        reencrypt_copies(&self.paths, backup_dir, &old, &secret);
        Ok(secret)
    }

    /// Adds Touch ID unlock for this computer, with a random key to be kept
    /// in its credential store.
    pub fn enable_device_unlock(&mut self) -> Result<DeviceKey> {
        let mut slots = self.slots.clone();
        let (slot_id, key) = slots.add_device(&self.secret)?;
        self.write_slots(slots)?;
        Ok(DeviceKey { slot_id, key })
    }

    /// Adds device unlock for this computer with a key that is never stored,
    /// e.g. [`bound_device_key`] for Windows Hello. Returns the slot's id.
    pub fn enable_device_unlock_with(&mut self, key: &[u8; 32]) -> Result<String> {
        let mut slots = self.slots.clone();
        let slot_id = slots.add_device_key(&self.secret, key)?;
        self.write_slots(slots)?;
        Ok(slot_id)
    }

    /// Removes one computer's device slot.
    pub fn disable_device_unlock(&mut self, slot_id: &str) -> Result<()> {
        if !self.slots.device_ids().iter().any(|id| id == slot_id) {
            return Ok(());
        }
        let mut slots = self.slots.clone();
        slots.remove_device(slot_id);
        self.write_slots(slots)
    }

    /// All entries, sorted by title. Environments ([`envs`]) aren't
    /// entries here.
    pub fn entries(&self) -> Vec<EntrySummary> {
        let mut entries: Vec<EntrySummary> = self
            .db
            .iter_all_entries()
            .filter(|entry| !envs::is_environment(entry))
            .map(|entry| self.summary(&entry))
            .collect();
        entries.sort_by_cached_key(|e| (e.title.to_lowercase(), e.username.to_lowercase()));
        entries
    }

    pub fn entry(&self, id: &str) -> Result<EntryDetail> {
        let entry = self.find(id)?;
        let history = entry.history.as_ref().map(|h| h.get_entries().as_slice());
        Ok(EntryDetail {
            summary: self.summary(&entry),
            notes: text(entry.get(fields::NOTES)),
            password_changed: password_changed(&entry, history.unwrap_or_default()).map(rfc3339),
            history_len: history.map_or(0, |h| u32::try_from(h.len()).unwrap_or(u32::MAX)),
        })
    }

    /// One secret of an entry; empty when it has none.
    pub fn secret(&self, id: &str, field: SecretField) -> Result<SecretString> {
        let entry = self.find(id)?;
        let name = match field {
            SecretField::Password => fields::PASSWORD,
            SecretField::Otp => fields::OTP,
        };
        Ok(SecretString::from(text(entry.get(name))))
    }

    /// The current 2FA code of an entry and the seconds it stays valid. A
    /// stored secret this app can't make codes for (from a KeePass file made
    /// elsewhere) is an error, never a crash.
    pub fn otp_code(&self, id: &str) -> Result<(String, u64)> {
        let entry = self.find(id)?;
        let uri = entry
            .get(fields::OTP)
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| Error::NotFound("2FA secret".into()))?;
        let totp = parse_totp(uri).ok_or_else(|| Error::Parse("unreadable 2FA secret".into()))?;
        let code = totp
            .value_now()
            .map_err(|_| Error::invalid("the system clock is before 1970"))?;
        Ok((code.code, code.valid_for.as_secs()))
    }

    /// Adds an entry at the top level and returns its id.
    pub fn add_entry(&mut self, input: &EntryInput) -> Result<String> {
        let wanted = wanted_fields(input, None)?;
        let mut root = self.db.root_mut();
        let mut entry = root.add_entry();
        for (name, value) in wanted {
            if let Some(value) = value {
                entry.set(name, value);
            }
        }
        if !entry.fields.contains_key(fields::PASSWORD) {
            entry.set_protected(fields::PASSWORD, "");
        }
        Ok(entry.id().uuid().to_string())
    }

    /// Updates an entry, keeping its previous version in the history.
    pub fn update_entry(&mut self, id: &str, input: &EntryInput) -> Result<()> {
        let entry_id = parse_id(id)?;
        let current = self.find(id)?;
        let changes: Vec<FieldChange> = wanted_fields(input, Some(&current))?
            .into_iter()
            .filter(|(name, value)| current.get(name) != value.as_ref().map(|v| v.get().as_str()))
            .collect();
        if changes.is_empty() {
            return Ok(());
        }
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::NotFound(format!("entry {id}")))?;
        let mut tracked = entry.track_changes();
        for (name, value) in changes {
            match value {
                Some(value) => tracked.set(name, value),
                None => {
                    tracked.fields.remove(name);
                }
            }
        }
        tracked.times.last_modification = Some(Times::now());
        Ok(())
    }

    /// Moves an entry to the recycle bin.
    pub fn trash_entry(&mut self, id: &str) -> Result<()> {
        let entry_id = parse_id(id)?;
        if self.summary(&self.find(id)?).in_trash {
            return Ok(());
        }
        let bin = self.recycle_bin();
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::NotFound(format!("entry {id}")))?;
        entry
            .move_to(bin)
            .map_err(|_| Error::NotFound("recycle bin".into()))?;
        entry.times.location_changed = Some(Times::now());
        Ok(())
    }

    /// Moves an entry out of the recycle bin, back to its folder if that still
    /// exists.
    pub fn restore_entry(&mut self, id: &str) -> Result<()> {
        let entry_id = parse_id(id)?;
        let entry = self.find(id)?;
        if !self.summary(&entry).in_trash {
            return Ok(());
        }
        let bin = self.db.meta.recyclebin_uuid;
        let target = entry
            .previous_parent()
            .filter(|group| !in_group(group.id(), bin, &self.db))
            .map_or_else(|| self.db.root().id(), |group| group.id());
        let mut entry = self
            .db
            .entry_mut(entry_id)
            .ok_or_else(|| Error::NotFound(format!("entry {id}")))?;
        entry
            .move_to(target)
            .map_err(|_| Error::NotFound("folder".into()))?;
        entry.times.location_changed = Some(Times::now());
        Ok(())
    }

    /// Deletes an entry from the recycle bin for good.
    pub fn delete_entry(&mut self, id: &str) -> Result<()> {
        let entry_id = parse_id(id)?;
        if !self.summary(&self.find(id)?).in_trash {
            return Err(Error::invalid(
                "only entries in the recycle bin can be deleted",
            ));
        }
        self.db
            .deleted_objects
            .insert(entry_id.uuid(), Some(Times::now()));
        if let Some(entry) = self.db.entry_mut(entry_id) {
            entry.remove();
        }
        Ok(())
    }

    /// Deletes everything in the recycle bin. Returns how many entries went.
    pub fn empty_trash(&mut self) -> Result<usize> {
        let ids: Vec<String> = self
            .entries()
            .into_iter()
            .filter(|e| e.in_trash)
            .map(|e| e.id)
            .collect();
        for id in &ids {
            self.delete_entry(id)?;
        }
        Ok(ids.len())
    }

    /// The recycle bin group, created on first use the way KeePass does.
    fn recycle_bin(&mut self) -> GroupId {
        if let Some(bin) = self.db.recycle_bin() {
            return bin.id();
        }
        let mut root = self.db.root_mut();
        let mut bin = root.add_group();
        bin.name = "Recycle Bin".into();
        bin.set_icon_builtin(43);
        bin.enable_autotype = Some(false);
        bin.enable_searching = Some(false);
        let id = bin.id();
        self.db.meta.recyclebin_enabled = Some(true);
        self.db.meta.recyclebin_uuid = Some(id.uuid());
        self.db.meta.recyclebin_changed = Some(Times::now());
        id
    }

    fn find(&self, id: &str) -> Result<EntryRef<'_>> {
        self.db
            .entry(parse_id(id)?)
            .ok_or_else(|| Error::NotFound(format!("entry {id}")))
    }

    fn summary(&self, entry: &EntryRef<'_>) -> EntrySummary {
        let bin = self.db.meta.recyclebin_uuid;
        let mut path = Vec::new();
        let mut in_trash = false;
        let mut group = Some(entry.parent().id());
        while let Some(current) = group.and_then(|id| self.db.group(id)) {
            if bin == Some(current.id().uuid()) {
                in_trash = true;
            }
            group = current.parent().map(|parent| parent.id());
            if group.is_some() {
                path.push(current.name.clone());
            }
        }
        path.reverse();
        let kind = EntryKind::parse(entry.get(KIND_FIELD).unwrap_or_default());
        EntrySummary {
            id: entry.id().uuid().to_string(),
            title: text(entry.get(fields::TITLE)),
            username: text(entry.get(fields::USERNAME)),
            url: text(entry.get(fields::URL)),
            kind,
            host: non_empty(entry.get(HOST_FIELD)),
            key_fingerprint: non_empty(entry.get(KEY_FIELD)),
            has_password: entry.get(fields::PASSWORD).is_some_and(|p| !p.is_empty()),
            has_otp: entry.get(fields::OTP).is_some_and(|p| !p.is_empty()),
            group: (!path.is_empty()).then(|| path.join("/")),
            in_trash,
            created: entry.times.creation.map(rfc3339),
            modified: entry.times.last_modification.map(rfc3339),
        }
    }
}

/// The fields an entry should have, with `None` for fields to remove. For an
/// update, `current` decides what "keep" means.
fn wanted_fields(input: &EntryInput, current: Option<&EntryRef<'_>>) -> Result<Vec<FieldChange>> {
    let title = input.title.trim();
    if title.is_empty() {
        return Err(Error::invalid("an entry needs a title"));
    }
    for value in [title, &input.username, &input.url, &input.notes] {
        check_field(value)?;
    }
    let mut wanted = vec![
        (fields::TITLE, Some(Value::unprotected(title))),
        (
            fields::USERNAME,
            Some(Value::unprotected(input.username.trim())),
        ),
        (fields::URL, Some(Value::unprotected(input.url.trim()))),
        (fields::NOTES, non_empty_value(&input.notes)),
    ];
    if let Some(password) = &input.password {
        check_field(password.expose_secret())?;
        wanted.push((
            fields::PASSWORD,
            Some(Value::protected(password.expose_secret())),
        ));
    }
    match &input.otp {
        Some(otp) if otp.expose_secret().trim().is_empty() => wanted.push((fields::OTP, None)),
        Some(otp) => {
            let uri = otp_uri(otp.expose_secret(), title)?;
            wanted.push((fields::OTP, Some(Value::protected(uri.as_str()))));
        }
        None => {}
    }
    let link = |value: &Option<String>, what: &str| -> Result<Option<Value<String>>> {
        let value = value.as_deref().map(str::trim).unwrap_or_default();
        if value.is_empty() {
            return Err(Error::invalid(format!("{what} is missing")));
        }
        check_field(value)?;
        Ok(Some(Value::unprotected(value)))
    };
    let (kind, host, key) = match input.kind {
        EntryKind::Login => (None, None, None),
        EntryKind::Host => (
            Some(Value::unprotected(EntryKind::Host.as_str())),
            link(&input.host, "host alias")?,
            None,
        ),
        EntryKind::Key => (
            Some(Value::unprotected(EntryKind::Key.as_str())),
            None,
            link(&input.key_fingerprint, "key fingerprint")?,
        ),
    };
    wanted.extend([(KIND_FIELD, kind), (HOST_FIELD, host), (KEY_FIELD, key)]);
    // On an update, fields that are absent and should stay absent are no change.
    if let Some(current) = current {
        wanted.retain(|(name, value)| value.is_some() || current.fields.contains_key(*name));
    }
    Ok(wanted)
}

/// Turns what a site shows for 2FA — an `otpauth://` URI, or a base32 key
/// with optional spaces — into the `otpauth://` URI KeePassXC stores.
fn otp_uri(input: &str, title: &str) -> Result<String> {
    let input = input.trim();
    let uri = if input.starts_with("otpauth://") {
        input.to_owned()
    } else {
        let secret: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let secret = secret.trim_end_matches('=');
        if secret.len() < 16 || !secret.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7')) {
            return Err(Error::invalid("not a 2FA secret"));
        }
        let label: String = title
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        format!("otpauth://totp/{label}?secret={secret}&period=30&digits=6&algorithm=SHA1")
    };
    if parse_totp(&uri).is_none() {
        return Err(Error::invalid("not a 2FA secret"));
    }
    Ok(uri)
}

/// Seconds a 2FA code lasts: 30 almost everywhere, 60 at a few sites.
const OTP_PERIODS: std::ops::RangeInclusive<u64> = 1..=300;
/// Digits of a 2FA code: 6 almost everywhere, 8 at a few sites.
const OTP_DIGITS: std::ops::RangeInclusive<u32> = 6..=10;

/// An `otpauth://` URI this app can make codes for: TOTP with a secret, a
/// known algorithm (the parser knows no other), and a period and number of
/// digits within [`OTP_PERIODS`] and [`OTP_DIGITS`]. The KeePass crate takes
/// any numbers, and computing a code then panics — which aborts the app —
/// on a period of 0 or 64 digits and more. So anything else is refused
/// when entered, kept as an unreadable secret on import, and an error when
/// a code is asked for.
fn parse_totp(uri: &str) -> Option<TOTP> {
    // The KeePass crate reads `otpauth://hotp/…` as TOTP too.
    let parsed = url::Url::parse(uri).ok()?;
    if !parsed
        .host_str()
        .is_some_and(|kind| kind.eq_ignore_ascii_case("totp"))
    {
        return None;
    }
    let totp: TOTP = uri.parse().ok()?;
    let usable = OTP_PERIODS.contains(&totp.period)
        && OTP_DIGITS.contains(&totp.digits)
        && !Zeroizing::new(totp.get_secret()).is_empty();
    usable.then_some(totp)
}

/// When the current password was set: the oldest version in the unbroken run
/// of versions, newest first, that have it.
fn password_changed(
    entry: &EntryRef<'_>,
    history: &[keepass::db::Entry],
) -> Option<chrono::NaiveDateTime> {
    let password = entry.get(fields::PASSWORD);
    let mut changed = entry.times.last_modification;
    for version in history.iter().rev() {
        if version.get(fields::PASSWORD) != password {
            break;
        }
        changed = version.times.last_modification.or(changed);
    }
    changed
}

fn in_group(group: GroupId, ancestor: Option<uuid::Uuid>, db: &Database) -> bool {
    let Some(ancestor) = ancestor else {
        return false;
    };
    let mut current = Some(group);
    while let Some(g) = current.and_then(|id| db.group(id)) {
        if g.id().uuid() == ancestor {
            return true;
        }
        current = g.parent().map(|parent| parent.id());
    }
    false
}

/// Settings for databases made here. The password is a random 256-bit key, so
/// a moderate Argon2id cost is plenty and KeePassXC opens it quickly too.
fn new_config() -> DatabaseConfig {
    let mut config = DatabaseConfig::default();
    config.outer_cipher_config = OuterCipherConfig::ChaCha20;
    config.kdf_config = KdfConfig::Argon2id {
        iterations: 2,
        memory: 32 * 1024 * 1024,
        parallelism: 2,
        version: argon2::Version::Version13,
    };
    config
}

fn key(secret: &SecretString) -> DatabaseKey {
    DatabaseKey::new().with_password(secret.expose_secret())
}

fn serialize(db: &Database, secret: &SecretString) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    db.save(&mut bytes, key(secret))
        .map_err(|e| Error::Parse(format!("writing the vault: {e}")))?;
    Ok(bytes)
}

fn read_database(path: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(path).map_err(|e| Error::io(e, path))?;
    if meta.len() > MAX_DATABASE_SIZE {
        return Err(Error::Parse(format!("{} is too large", path.display())));
    }
    std::fs::read(path).map_err(|e| Error::io(e, path))
}

/// Decrypts a KeePass file, after checking that its key derivation settings
/// ask for a sane amount of memory and time.
fn parse_database(bytes: &[u8], secret: &SecretString) -> Result<Database> {
    kdf::check_kdbx(bytes)?;
    Database::parse(bytes, key(secret)).map_err(open_error)
}

fn load_slots(paths: &VaultPaths) -> Result<(KeySlots, [u8; 32])> {
    KeySlots::read(&paths.keys)?.ok_or_else(|| Error::NotFound(paths.keys.display().to_string()))
}

/// Re-encrypts with `new` the database's backups and conflict copies in
/// `backup_dir` that `old` opens. A backup that can't be rewritten is
/// deleted; a conflict copy is kept, since it may hold the only copy of
/// changes made elsewhere. Files the old secret doesn't open (another
/// vault's with the same name) stay as they are. Returns how many files were
/// rewritten or deleted.
fn reencrypt_copies(
    paths: &VaultPaths,
    backup_dir: &Path,
    old: &SecretString,
    new: &SecretString,
) -> usize {
    let Some(name) = paths.database.file_name().and_then(|n| n.to_str()) else {
        return 0;
    };
    let stem = paths
        .database
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("vault");
    let conflict_prefix = format!("{stem}-conflict-");
    let mut copies: Vec<(PathBuf, bool)> = fsutil::list_backups(backup_dir, name)
        .into_iter()
        .map(|path| (path, false))
        .collect();
    if let Ok(entries) = std::fs::read_dir(backup_dir) {
        // Named by `write_conflict_copy`.
        copies.extend(entries.filter_map(std::result::Result::ok).filter_map(|e| {
            let path = e.path();
            let file = path.file_name()?.to_str()?;
            let kdbx = path.extension().is_some_and(|ext| ext == "kdbx");
            (kdbx && file.starts_with(&conflict_prefix)).then_some((path, true))
        }));
    }
    let mut done = 0;
    for (copy, conflict) in copies {
        let Ok(bytes) = read_database(&copy) else {
            continue;
        };
        let Ok(mut db) = parse_database(&bytes, old) else {
            continue;
        };
        if !matches!(db.config.version, DatabaseVersion::KDB4(_)) {
            db.config = new_config();
        }
        let written =
            serialize(&db, new).and_then(|bytes| fsutil::atomic_write(&copy, &bytes, 0o600));
        if written.is_err() {
            if conflict {
                continue;
            }
            // It must not stay readable with the old key.
            let _ = std::fs::remove_file(&copy);
        }
        done += 1;
    }
    done
}

fn open_error(error: keepass::db::DatabaseOpenError) -> Error {
    use keepass::db::DatabaseOpenError as E;
    match error {
        E::Key(keepass::error::DatabaseKeyError::IncorrectKey) => Error::WrongPassphrase,
        E::UnsupportedVersion => Error::Unsupported("this KeePass file version".into()),
        other => Error::Parse(format!("reading the vault: {other}")),
    }
}

fn check_master(master: &SecretString) -> Result<()> {
    if master.expose_secret().is_empty() {
        return Err(Error::invalid("the master password is empty"));
    }
    check_field(master.expose_secret())
}

fn check_field(value: &str) -> Result<()> {
    if value.len() > MAX_FIELD_LEN {
        return Err(Error::invalid("a value is too long"));
    }
    if value.contains('\0') {
        return Err(Error::invalid("a value contains a NUL character"));
    }
    Ok(())
}

fn parse_id(id: &str) -> Result<EntryId> {
    uuid::Uuid::parse_str(id)
        .map(EntryId::from)
        .map_err(|_| Error::invalid(format!("not an entry id: {id}")))
}

fn text(value: Option<&str>) -> String {
    value.unwrap_or_default().to_owned()
}

fn non_empty(value: Option<&str>) -> Option<String> {
    value.filter(|v| !v.is_empty()).map(str::to_owned)
}

fn non_empty_value(value: &str) -> Option<Value<String>> {
    (!value.is_empty()).then(|| Value::unprotected(value))
}

fn rfc3339(time: chrono::NaiveDateTime) -> String {
    time.and_utc().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn duplicate(secret: &SecretString) -> SecretString {
    SecretString::from(secret.expose_secret().to_owned())
}
