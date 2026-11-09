//! Firefox's saved logins: `logins.json`, with user names and passwords
//! encrypted by the key in `key4.db` (NSS's key database).
//!
//! `key4.db` holds:
//!
//! - in `metaData`, row `password`: a global salt (`item1`) and the text
//!   `password-check` encrypted with the primary password (`item2`), which
//!   tells whether a primary password opens the profile;
//! - in `nssPrivate`: the logins' key (`a11`), encrypted the same way, with
//!   its id (`a102`).
//!
//! Both are PKCS #5 structures: PBES2 with PBKDF2-HMAC-SHA256 and
//! AES-256-CBC (Firefox 72 and later), or the older PKCS #12
//! pbeWithSHA1AndTripleDES-CBC. The password they are made with is
//! `SHA-1(global salt ‖ primary password)`; without a primary password, that
//! is the empty string. Each login value is then `{ key id, cipher + IV,
//! ciphertext }`, with AES-256-CBC or Triple DES.

use std::path::Path;

use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use secrecy::{ExposeSecret, SecretString};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::crypto::{Cbc, text};
use super::der::{Reader, oid};
use super::{
    BrowserLogins, BrowserReadError, Login, copy_database, open_database, private_temp_dir,
    sqlite_error, to_logins,
};
use crate::vault::import::CsvFormat;
use crate::{Error, Result, fsutil};

/// Largest `logins.json` read.
const MAX_LOGINS_JSON: u64 = 64 * 1024 * 1024;
/// What `password-check` decrypts to when the primary password is right.
const PASSWORD_CHECK: &[u8] = b"password-check";
/// Most PBKDF2 rounds accepted; Firefox uses 10 000.
const MAX_ROUNDS: u32 = 10_000_000;

/// Reads the Firefox profile at `dir`.
pub(super) fn read(
    dir: &Path,
    primary_password: Option<&SecretString>,
) -> Result<BrowserLogins, BrowserReadError> {
    let logins_path = dir.join("logins.json");
    if !logins_path.is_file() {
        return to_logins(CsvFormat::Firefox, Vec::new(), 0, 0);
    }
    let json = Zeroizing::new(fsutil::read_limited(&logins_path, MAX_LOGINS_JSON)?);
    let entries = parse_logins(&json)?;
    if entries.is_empty() {
        return to_logins(CsvFormat::Firefox, Vec::new(), 0, 0);
    }

    let key_db = dir.join("key4.db");
    if !key_db.is_file() {
        return Err(if dir.join("key3.db").is_file() {
            BrowserReadError::Unsupported("the profile uses the old key3.db".into())
        } else {
            Error::NotFound("the profile's key4.db".into()).into()
        });
    }
    let temp = private_temp_dir()?;
    let copy = copy_database(&key_db, temp.path())?;
    let stored = read_key_db(&copy)?;
    drop(temp);

    let primary = primary_password.map_or("", |p| p.expose_secret());
    let wanted = entries.iter().find_map(|e| encrypted_key_id(&e.password));
    let key = stored.logins_key(primary, wanted.as_deref(), primary_password.is_some())?;

    let mut logins = Vec::with_capacity(entries.len());
    let mut unreadable = 0u32;
    for entry in entries {
        let username = decrypt_value(&key, &entry.username);
        let password = decrypt_value(&key, &entry.password);
        match (username, password) {
            (Some(username), Some(password)) => logins.push(Login {
                url: entry.url,
                username: username.to_string(),
                password,
            }),
            _ => unreadable += 1,
        }
    }
    if logins.is_empty() && unreadable > 0 {
        return Err(BrowserReadError::Unsupported(
            "no saved password could be decrypted".into(),
        ));
    }
    to_logins(CsvFormat::Firefox, logins, unreadable, 0)
}

/// A login of `logins.json`, its user name and password still encrypted.
struct Entry {
    url: String,
    username: String,
    password: String,
}

fn parse_logins(json: &[u8]) -> Result<Vec<Entry>> {
    let value: serde_json::Value = serde_json::from_slice(json)
        .map_err(|_| Error::Parse("the profile's logins.json is not valid JSON".into()))?;
    let Some(logins) = value["logins"].as_array() else {
        return Ok(Vec::new());
    };
    let field =
        |login: &serde_json::Value, name: &str| login[name].as_str().unwrap_or_default().to_owned();
    Ok(logins
        .iter()
        .map(|login| Entry {
            url: field(login, "hostname"),
            username: field(login, "encryptedUsername"),
            password: field(login, "encryptedPassword"),
        })
        .collect())
}

/// What `key4.db` holds.
struct KeyDb {
    global_salt: Vec<u8>,
    password_check: Vec<u8>,
    /// Encrypted keys and their ids.
    keys: Vec<(Vec<u8>, Vec<u8>)>,
}

fn read_key_db(path: &Path) -> Result<KeyDb> {
    let db = open_database(path)?;
    let (global_salt, password_check) = db
        .query_row(
            "SELECT item1, item2 FROM metaData WHERE id = 'password'",
            [],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .map_err(|e| sqlite_error(&e))?;
    let mut statement = db
        .prepare("SELECT a11, a102 FROM nssPrivate")
        .map_err(|e| sqlite_error(&e))?;
    let keys = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Option<Vec<u8>>>(0)?.unwrap_or_default(),
                row.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default(),
            ))
        })
        .map_err(|e| sqlite_error(&e))?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|e| sqlite_error(&e))?;
    Ok(KeyDb {
        global_salt,
        password_check,
        keys,
    })
}

impl KeyDb {
    /// The logins' key, after checking `primary` opens the profile. Prefers
    /// the key with id `wanted`.
    fn logins_key(
        &self,
        primary: &str,
        wanted: Option<&[u8]>,
        primary_given: bool,
    ) -> Result<Zeroizing<Vec<u8>>, BrowserReadError> {
        let check = match pbe_decrypt(&self.password_check, &self.global_salt, primary.as_bytes()) {
            Pbe::Plain(plain) => plain,
            Pbe::Unsupported => {
                return Err(BrowserReadError::Unsupported(
                    "unknown key4.db encryption".into(),
                ));
            }
            Pbe::Failed => Zeroizing::default(),
        };
        if check.as_slice() != PASSWORD_CHECK {
            return Err(if primary_given {
                BrowserReadError::WrongPrimaryPassword
            } else {
                BrowserReadError::PrimaryPasswordRequired
            });
        }
        let mut keys: Vec<&(Vec<u8>, Vec<u8>)> = self.keys.iter().collect();
        // The key the logins name first; the others after it.
        keys.sort_by_key(|(_, id)| Some(id.as_slice()) != wanted);
        keys.into_iter()
            .find_map(|(encrypted, _)| {
                match pbe_decrypt(encrypted, &self.global_salt, primary.as_bytes()) {
                    Pbe::Plain(key) if key.len() >= Cbc::Tdes.key_len() => Some(key),
                    _ => None,
                }
            })
            .ok_or_else(|| BrowserReadError::Unsupported("no usable key in key4.db".into()))
    }
}

enum Pbe {
    Plain(Zeroizing<Vec<u8>>),
    /// A scheme this code doesn't know.
    Unsupported,
    /// The scheme is known; the password is wrong or the data damaged.
    Failed,
}

/// Decrypts a PKCS #5 / PKCS #12 encrypted item of `key4.db`.
fn pbe_decrypt(der: &[u8], global_salt: &[u8], primary: &[u8]) -> Pbe {
    let parse = || -> Option<(&[u8], Reader<'_>, &[u8])> {
        let mut outer = Reader::new(der).sequence()?;
        let mut algorithm = outer.sequence()?;
        let id = algorithm.oid()?;
        let ciphertext = outer.octets()?;
        Some((id, algorithm, ciphertext))
    };
    let Some((id, params, ciphertext)) = parse() else {
        return Pbe::Unsupported;
    };
    let mut digest = Sha1::new();
    digest.update(global_salt);
    digest.update(primary);
    let hashed = Zeroizing::new(digest.finalize().to_vec());

    let plain = if id == oid::PBES2 {
        let Some((key, iv)) = pbes2_key(params, hashed.as_slice()) else {
            return Pbe::Unsupported;
        };
        Cbc::Aes256.decrypt(&key, &iv, ciphertext)
    } else if id == oid::PBE_SHA1_3DES {
        let Some((key, iv)) = pkcs12_3des_key(params, hashed.as_slice()) else {
            return Pbe::Unsupported;
        };
        Cbc::Tdes.decrypt(&key, &iv, ciphertext)
    } else {
        return Pbe::Unsupported;
    };
    plain.map_or(Pbe::Failed, Pbe::Plain)
}

/// PBES2: `SEQUENCE { SEQUENCE { pbkdf2, SEQUENCE { salt, rounds,
/// [key length], [prf] } }, SEQUENCE { aes256-CBC, iv } }`. NSS stores
/// only 14 bytes of the IV; the 16-byte IV is them after `04 0E` (the DER
/// header they had).
fn pbes2_key(mut params: Reader<'_>, password: &[u8]) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let mut params = params.sequence()?;
    let mut kdf = params.sequence()?;
    if kdf.oid()? != oid::PBKDF2 {
        return None;
    }
    let mut kdf_params = kdf.sequence()?;
    let salt = kdf_params.octets()?;
    let rounds = kdf_params.small_int()?;
    if rounds == 0 || rounds > MAX_ROUNDS {
        return None;
    }
    let mut key_len = 32;
    if kdf_params.peek_tag() == Some(super::der::INTEGER) {
        key_len = kdf_params.small_int()?;
    }
    let sha256 = if kdf_params.is_empty() {
        false
    } else {
        let mut prf = kdf_params.sequence()?;
        match prf.oid()? {
            id if id == oid::HMAC_SHA256 => true,
            id if id == oid::HMAC_SHA1 => false,
            _ => return None,
        }
    };
    if key_len != 32 {
        return None;
    }
    let mut cipher = params.sequence()?;
    if cipher.oid()? != oid::AES256_CBC {
        return None;
    }
    let iv = cipher.octets()?;
    let iv = match iv.len() {
        14 => [&[0x04, 0x0E], iv].concat(),
        16 => iv.to_vec(),
        _ => return None,
    };
    let mut key = Zeroizing::new(vec![0u8; 32]);
    if sha256 {
        pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut key);
    } else {
        pbkdf2_hmac::<Sha1>(password, salt, rounds, &mut key);
    }
    Some((key, iv))
}

/// NSS's pbeWithSHA1AndTripleDES-CBC: `SEQUENCE { entry salt, rounds }`,
/// with the key and IV NSS derives from the hashed password (one round, as
/// NSS always writes it).
fn pkcs12_3des_key(
    mut params: Reader<'_>,
    hashed_password: &[u8],
) -> Option<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    let mut params = params.sequence()?;
    let entry_salt = params.octets()?;
    if params.small_int()? != 1 {
        return None;
    }
    Some(nss_3des_key(hashed_password, entry_salt))
}

/// The key and IV of NSS's legacy PBE.
pub(super) fn nss_3des_key(
    hashed_password: &[u8],
    entry_salt: &[u8],
) -> (Zeroizing<Vec<u8>>, Vec<u8>) {
    type HmacSha1 = Hmac<Sha1>;
    let mut padded_salt = entry_salt.to_vec();
    padded_salt.resize(entry_salt.len().max(20), 0);
    let mut chp = Sha1::new();
    chp.update(hashed_password);
    chp.update(entry_salt);
    let chp = Zeroizing::new(chp.finalize().to_vec());
    let hmac = |parts: &[&[u8]]| -> Zeroizing<Vec<u8>> {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&chp).expect("HMAC takes any key length");
        for part in parts {
            mac.update(part);
        }
        Zeroizing::new(mac.finalize().into_bytes().to_vec())
    };
    let k1 = hmac(&[&padded_salt, entry_salt]);
    let tk = hmac(&[&padded_salt]);
    let k2 = hmac(&[&tk, entry_salt]);
    let mut k = Zeroizing::new(Vec::with_capacity(40));
    k.extend_from_slice(&k1);
    k.extend_from_slice(&k2);
    let key = Zeroizing::new(k[..24].to_vec());
    let iv = k[32..40].to_vec();
    (key, iv)
}

/// The key id an encrypted login value names.
fn encrypted_key_id(value: &str) -> Option<Vec<u8>> {
    let der = Base64::decode_vec(value).ok()?;
    let mut outer = Reader::new(&der).sequence()?;
    outer.octets().map(<[u8]>::to_vec)
}

/// Decrypts a login value of `logins.json`: base64 of `SEQUENCE { key id,
/// SEQUENCE { cipher, iv }, ciphertext }`.
fn decrypt_value(key: &[u8], value: &str) -> Option<Zeroizing<String>> {
    let der = Base64::decode_vec(value).ok()?;
    let mut outer = Reader::new(&der).sequence()?;
    let _key_id = outer.octets()?;
    let mut cipher = outer.sequence()?;
    let id = cipher.oid()?;
    let iv = cipher.octets()?;
    let ciphertext = outer.octets()?;
    let algorithm = if id == oid::AES256_CBC {
        Cbc::Aes256
    } else if id == oid::DES_EDE3_CBC {
        Cbc::Tdes
    } else {
        return None;
    };
    let plain = algorithm.decrypt(key, iv, ciphertext)?;
    text(&plain)
}
