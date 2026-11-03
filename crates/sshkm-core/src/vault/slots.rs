//! The key slots file (`vault.keys`) next to the database.
//!
//! The database's KeePass password — the *vault secret* — is never typed in
//! day-to-day use. Each slot holds a copy of it encrypted with
//! XChaCha20-Poly1305 under a different key:
//!
//! - `password`: a key derived from the master password with Argon2id;
//! - `device`: one per computer that turned on Touch ID or Windows Hello. Its
//!   key is random and kept in that computer's credential store (macOS), or
//!   derived from a Windows Hello signature that only the user's PIN, face or
//!   fingerprint can produce ([`bound_device_key`]). A vault in a synced folder
//!   can have several.
//!
//! Losing this file loses no data: the recovery key opens the database alone.

use std::path::Path;

use base64ct::{Base64, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::kdf;
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
    Device { id: String, sealed: Sealed },
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
        Ok(Self::read(path)?.map(|(slots, _)| slots))
    }

    /// Reads the file together with its SHA-256, which a later write checks
    /// against ([`file_hash`]); `Ok(None)` when it does not exist.
    pub(crate) fn read(path: &Path) -> Result<Option<(Self, [u8; 32])>> {
        let Some(bytes) = read_file(path)? else {
            return Ok(None);
        };
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
        Ok(Some((slots, Sha256::digest(&bytes).into())))
    }

    /// Writes the file and returns the SHA-256 of what was written.
    pub(crate) fn save(&self, path: &Path) -> Result<[u8; 32]> {
        let mut json = serde_json::to_vec_pretty(self)
            .map_err(|e| Error::Parse(format!("serialising key slots: {e}")))?;
        json.push(b'\n');
        fsutil::atomic_write(path, &json, 0o600)?;
        Ok(Sha256::digest(&json).into())
    }

    pub(crate) fn has_password(&self) -> bool {
        self.slots
            .iter()
            .any(|s| matches!(s, Slot::Password { .. }))
    }

    /// Ids of the device slots, one per computer with device unlock.
    pub(crate) fn device_ids(&self) -> Vec<String> {
        self.slots
            .iter()
            .filter_map(|s| match s {
                Slot::Device { id, .. } => Some(id.clone()),
                Slot::Password { .. } => None,
            })
            .collect()
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

    /// Adds a device slot and returns its id and new random key, to be kept
    /// in this computer's credential store.
    pub(crate) fn add_device(
        &mut self,
        secret: &SecretString,
    ) -> Result<(String, Zeroizing<[u8; 32]>)> {
        let mut key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(key.as_mut());
        let id = self.add_device_key(secret, &key)?;
        Ok((id, key))
    }

    /// Adds a device slot that `key` opens, e.g. one from
    /// [`bound_device_key`], and returns its id.
    pub(crate) fn add_device_key(
        &mut self,
        secret: &SecretString,
        key: &[u8; 32],
    ) -> Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let sealed = seal(key, secret, &device_purpose(&id))?;
        self.slots.push(Slot::Device {
            id: id.clone(),
            sealed,
        });
        Ok(id)
    }

    pub(crate) fn open_device(&self, id: &str, key: &[u8; 32]) -> Result<SecretString> {
        let sealed = self
            .slots
            .iter()
            .find_map(|s| match s {
                Slot::Device { id: slot, sealed } if slot == id => Some(sealed),
                _ => None,
            })
            .ok_or_else(|| Error::NotFound("device unlock slot".into()))?;
        open(key, sealed, &device_purpose(id))
    }

    pub(crate) fn remove_device(&mut self, id: &str) {
        self.slots
            .retain(|s| !matches!(s, Slot::Device { id: slot, .. } if slot == id));
    }

    pub(crate) fn remove_all_devices(&mut self) {
        self.slots.retain(|s| !matches!(s, Slot::Device { .. }));
    }
}

/// SHA-256 of the key slots file as it is on disk now; `None` when there is
/// none. Compared with what was last read or written before every write, so a
/// change made elsewhere is never overwritten.
pub(crate) fn file_hash(path: &Path) -> Result<Option<[u8; 32]>> {
    Ok(read_file(path)?.map(|bytes| Sha256::digest(&bytes).into()))
}

fn read_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::io(e, path)),
    };
    if meta.len() > MAX_SIZE {
        return Err(Error::Parse(format!("{} is too large", path.display())));
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|e| Error::io(e, path))
}

/// What Windows Hello signs to unlock a vault on this computer: fixed for a
/// vault, so the same key gives the same signature every time (RSA PKCS #1
/// v1.5 signatures are deterministic).
pub(crate) fn device_challenge(vault_id: &str) -> Vec<u8> {
    [
        b"SSH Key Manager vault device unlock v2\0".as_slice(),
        vault_id.as_bytes(),
    ]
    .concat()
}

/// The key of a device slot, derived from a Windows Hello signature of
/// [`device_challenge`]. Nothing that opens the slot is stored anywhere: it
/// takes the private key in Windows Hello, which signs only after the user's
/// PIN, face or fingerprint.
pub(crate) fn bound_device_key(signature: &[u8], vault_id: &str) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(FORMAT.as_bytes()), signature);
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&device_challenge(vault_id), key.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

fn derive(master: &SecretString, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>> {
    if kdf.algorithm != "argon2id" {
        return Err(Error::Unsupported(format!(
            "key derivation {}",
            kdf.algorithm
        )));
    }
    // The file may come from anywhere (a synced folder): refuse a cost that
    // would exhaust memory or never finish before deriving anything.
    kdf::check_argon2(
        kdf.memory_kib.into(),
        kdf.iterations.into(),
        kdf.parallelism.into(),
    )?;
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

fn device_purpose(id: &str) -> Vec<u8> {
    format!("device/{id}").into_bytes()
}

/// Binds a ciphertext to its slot, so one can't be swapped for another.
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
    fn device_slots_are_per_computer() {
        let mut slots = KeySlots::new();
        let (laptop, laptop_key) = slots.add_device(&secret()).unwrap();
        let (desktop, desktop_key) = slots.add_device(&secret()).unwrap();
        assert_eq!(slots.device_ids(), [laptop.clone(), desktop.clone()]);
        let opened = slots.open_device(&laptop, &laptop_key).unwrap();
        assert_eq!(opened.expose_secret(), "ABCD-EFGH");
        assert!(slots.open_device(&desktop, &desktop_key).is_ok());
        // One computer's key does not open another's slot.
        assert!(matches!(
            slots.open_device(&laptop, &desktop_key),
            Err(Error::WrongPassphrase)
        ));
        slots.remove_device(&laptop);
        assert_eq!(slots.device_ids(), std::slice::from_ref(&desktop));
        assert!(matches!(
            slots.open_device(&laptop, &laptop_key),
            Err(Error::NotFound(_))
        ));
        slots.remove_all_devices();
        assert_eq!(slots.device_ids(), Vec::<String>::new());
    }

    #[test]
    fn a_slot_cannot_be_moved_to_another_slot() {
        let mut slots = KeySlots::new();
        let (id, key) = slots.add_device(&secret()).unwrap();
        let Some(Slot::Device { sealed, .. }) = slots.slots.first().cloned() else {
            panic!("no device slot");
        };
        assert!(open(&key, &sealed, b"password").is_err());
        assert!(open(&key, &sealed, &device_purpose("other")).is_err());
        assert!(open(&key, &sealed, &device_purpose(&id)).is_ok());
    }

    #[test]
    fn a_planted_slot_with_a_huge_kdf_cost_is_refused() {
        let mut slots = KeySlots::new();
        slots
            .set_password(&secret(), &SecretString::from("pw"))
            .unwrap();
        for slot in &mut slots.slots {
            if let Slot::Password { kdf, .. } = slot {
                kdf.memory_kib = u32::MAX;
            }
        }
        assert!(matches!(
            slots.open_password(&SecretString::from("pw")),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn bound_device_keys_are_stable_per_signature_and_vault() {
        let signature = [7u8; 256];
        let key = bound_device_key(&signature, "vault-a");
        assert_eq!(*key, *bound_device_key(&signature, "vault-a"));
        assert_ne!(*key, *bound_device_key(&signature, "vault-b"));
        assert_ne!(*key, *bound_device_key(&[8u8; 256], "vault-a"));
        assert!(device_challenge("vault-a").ends_with(b"vault-a"));

        let mut slots = KeySlots::new();
        let id = slots.add_device_key(&secret(), &key).unwrap();
        let opened = slots.open_device(&id, &key).unwrap();
        assert_eq!(opened.expose_secret(), "ABCD-EFGH");
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
        let written = slots.save(&path).unwrap();
        assert_eq!(file_hash(&path).unwrap(), Some(written));
        let (loaded, read) = KeySlots::read(&path).unwrap().unwrap();
        assert_eq!(read, written);
        assert_eq!(loaded.vault_id, slots.vault_id);
        assert!(loaded.has_password());
        assert_eq!(loaded.device_ids(), Vec::<String>::new());
        assert!(loaded.open_password(&SecretString::from("a")).is_err());
        assert!(loaded.open_password(&SecretString::from("b")).is_ok());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("ABCD"));
    }
}
