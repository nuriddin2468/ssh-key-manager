//! The key slots file (`vault.keys`) next to the database.
//!
//! The database's KeePass password — the *vault secret* — is never typed in
//! day-to-day use. Each slot holds a copy of it encrypted with
//! XChaCha20-Poly1305 under a different key:
//!
//! - `password`: a key derived from the master password with Argon2id;
//! - `device`: a random key kept in the operating system's credential store,
//!   released after Touch ID or Windows Hello.
//!
//! Losing this file loses no data: the recovery key opens the database alone.

use std::path::Path;

use base64ct::{Base64, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result, fsutil};

const FORMAT: &str = "sshkm-vault-keys";
const VERSION: u32 = 1;
const MAX_SIZE: u64 = 64 * 1024;

/// Argon2id cost for the master password: 128 MiB, 3 passes, 4 lanes —
/// a fraction of a second on a current laptop.
#[cfg(not(test))]
const KDF_COST: (u32, u32, u32) = (128 * 1024, 3, 4);
#[cfg(test)]
const KDF_COST: (u32, u32, u32) = (1024, 1, 1);

/// Contents of the key slots file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeySlots {
    format: String,
    version: u32,
    /// Random id of this vault; names its item in the OS credential store.
    pub(crate) vault_id: String,
    slots: Vec<Slot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
enum Slot {
    Password { kdf: Kdf, sealed: Sealed },
    Device { sealed: Sealed },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Kdf {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Sealed {
    nonce: String,
    ciphertext: String,
}

impl KeySlots {
    pub(crate) fn new() -> Self {
        Self {
            format: FORMAT.into(),
            version: VERSION,
            vault_id: uuid::Uuid::new_v4().to_string(),
            slots: Vec::new(),
        }
    }

    /// Reads the file; `Ok(None)` when it does not exist.
    pub(crate) fn load(path: &Path) -> Result<Option<Self>> {
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::io(e, path)),
        };
        if meta.len() > MAX_SIZE {
            return Err(Error::Parse(format!("{} is too large", path.display())));
        }
        let bytes = std::fs::read(path).map_err(|e| Error::io(e, path))?;
        let slots: Self = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Parse(format!("{}: {e}", path.display())))?;
        if slots.format != FORMAT || slots.version != VERSION {
            return Err(Error::Unsupported(format!(
                "{}: format {} version {}",
                path.display(),
                slots.format,
                slots.version
            )));
        }
        Ok(Some(slots))
    }

    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        let mut json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Parse(format!("serialising key slots: {e}")))?;
        json.push(b'\n');
        fsutil::atomic_write(path, &json, 0o600)
    }

    pub(crate) fn has_password(&self) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s, Slot::Password { .. }))
    }

    pub(crate) fn has_device(&self) -> bool {
        self.slots.iter().any(|s| matches!(s, Slot::Device { .. }))
    }

    /// Replaces the password slot with one for `master`.
    pub(crate) fn set_password(
        &mut self,
        secret: &SecretString,
        master: &SecretString,
    ) -> Result<()> {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let (memory_kib, iterations, parallelism) = KDF_COST;
        let kdf = Kdf {
            algorithm: "argon2id".into(),
            memory_kib,
            iterations,
            parallelism,
            salt: Base64::encode_string(&salt),
        };
        let key = derive(master, &kdf)?;
        let sealed = seal(&key, secret, b"password")?;
        self.slots.retain(|s| !matches!(s, Slot::Password { .. }));
        self.slots.push(Slot::Password { kdf, sealed });
        Ok(())
    }

    /// The vault secret, or [`Error::WrongPassphrase`].
    pub(crate) fn open_password(&self, master: &SecretString) -> Result<SecretString> {
        let (kdf, sealed) = self
            .slots
            .iter()
            .find_map(|s| match s {
                Slot::Password { kdf, sealed } => Some((kdf, sealed)),
                Slot::Device { .. } => None,
            })
            .ok_or_else(|| Error::NotFound("master password slot".into()))?;
        let key = derive(master, kdf)?;
        open(&key, sealed, b"password")
    }

    /// Adds (or replaces) the device slot and returns its new random key, to
    /// be kept in the OS credential store.
    pub(crate) fn set_device(&mut self, secret: &SecretString) -> Result<Zeroizing<[u8; 32]>> {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        let sealed = seal(&key, secret, b"device")?;
        self.remove_device();
        self.slots.push(Slot::Device { sealed });
        Ok(key)
    }

    pub(crate) fn open_device(&self, key: &[u8; 32]) -> Result<SecretString> {
        let sealed = self
            .slots
            .iter()
            .find_map(|s| match s {
                Slot::Device { sealed } => Some(sealed),
                Slot::Password { .. } => None,
            })
            .ok_or_else(|| Error::NotFound("device unlock slot".into()))?;
        open(key, sealed, b"device")
    }

    pub(crate) fn remove_device(&mut self) {
        self.slots.retain(|s| !matches!(s, Slot::Device { .. }));
    }
}

fn derive(master: &SecretString, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>> {
    if kdf.algorithm != "argon2id" {
        return Err(Error::Unsupported(format!(
            "key derivation {}",
            kdf.algorithm
        )));
    }
    let salt = decode(&kdf.salt)?;
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: kdf.memory_kib,
        time_cost: kdf.iterations,
        lanes: kdf.parallelism,
        thread_mode: argon2::ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };
    let hash = Zeroizing::new(
        argon2::hash_raw(master.expose_secret().as_bytes(), &salt, &config)
            .map_err(|e| Error::invalid(format!("key derivation: {e}")))?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&hash);
    Ok(key)
}

fn seal(key: &[u8; 32], secret: &SecretString, purpose: &[u8]) -> Result<Sealed> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: secret.expose_secret().as_bytes(),
                aad: &aad(purpose),
            },
        )
        .map_err(|_| Error::invalid("encryption failed"))?;
    Ok(Sealed {
        nonce: Base64::encode_string(&nonce),
        ciphertext: Base64::encode_string(&ciphertext),
    })
}

fn open(key: &[u8; 32], sealed: &Sealed, purpose: &[u8]) -> Result<SecretString> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce: [u8; 24] = decode(&sealed.nonce)?
        .try_into()
        .map_err(|_| Error::Parse("bad nonce in key slots".into()))?;
    let ciphertext = decode(&sealed.ciphertext)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad(purpose),
                },
            )
            .map_err(|_| Error::WrongPassphrase)?,
    );
    let text = std::str::from_utf8(&plain).map_err(|_| Error::Parse("bad key slot".into()))?;
    Ok(SecretString::from(text.to_owned()))
}

/// Binds a ciphertext to its slot type, so one can't be swapped for another.
fn aad(purpose: &[u8]) -> Vec<u8> {
    [FORMAT.as_bytes(), b"/", purpose].concat()
}

fn decode(text: &str) -> Result<Vec<u8>> {
    Base64::decode_vec(text).map_err(|_| Error::Parse("bad base64 in key slots".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> SecretString {
        SecretString::from("ABCD-EFGH")
    }

    #[test]
    fn password_slot_round_trips_and_rejects_wrong_passwords() {
        let mut slots = KeySlots::new();
        slots
            .set_password(&secret(), &SecretString::from("hunter2"))
            .unwrap();
        let opened = slots.open_password(&SecretString::from("hunter2")).unwrap();
        assert_eq!(opened.expose_secret(), "ABCD-EFGH");
        let wrong = slots
            .open_password(&SecretString::from("hunter3"))
            .unwrap_err();
        assert!(matches!(wrong, Error::WrongPassphrase));
    }

    #[test]
    fn device_slot_round_trips_and_can_be_removed() {
        let mut slots = KeySlots::new();
        let key = slots.set_device(&secret()).unwrap();
        assert_eq!(
            slots.open_device(&key).unwrap().expose_secret(),
            "ABCD-EFGH"
        );
        assert!(matches!(
            slots.open_device(&[7; 32]),
            Err(Error::WrongPassphrase)
        ));
        slots.remove_device();
        assert!(!slots.has_device());
    }

    #[test]
    fn a_slot_cannot_be_moved_to_another_type() {
        let mut slots = KeySlots::new();
        let key = slots.set_device(&secret()).unwrap();
        let Some(Slot::Device { sealed }) = slots.slots.first().cloned() else {
            panic!("no device slot");
        };
        assert!(open(&key, &sealed, b"password").is_err());
    }

    #[test]
    fn file_round_trips_and_keeps_one_password_slot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.keys");
        assert!(KeySlots::load(&path).unwrap().is_none());
        let mut slots = KeySlots::new();
        slots
            .set_password(&secret(), &SecretString::from("a"))
            .unwrap();
        slots
            .set_password(&secret(), &SecretString::from("b"))
            .unwrap();
        slots.save(&path).unwrap();
        let loaded = KeySlots::load(&path).unwrap().unwrap();
        assert_eq!(loaded.vault_id, slots.vault_id);
        assert!(loaded.has_password() && !loaded.has_device());
        assert!(loaded.open_password(&SecretString::from("a")).is_err());
        assert!(loaded.open_password(&SecretString::from("b")).is_ok());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("ABCD"));
    }
}
