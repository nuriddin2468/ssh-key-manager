//! Chromium's saved logins: the `logins` table of `Login Data` and of
//! `Login Data For Account` (the passwords of the signed-in Google account,
//! Chrome 114 and later).
//!
//! A password starts with the version of its encryption:
//!
//! - `v10` on macOS: AES-128-CBC with a key made by PBKDF2-HMAC-SHA1 (1003
//!   rounds, salt `saltysalt`) from the password in the Keychain item
//!   "<Browser> Safe Storage", and an IV of 16 spaces.
//! - `v10` / `v11` on Linux: the same with 1 round, from the fixed password
//!   `peanuts` (v10) or the one in the Secret Service / `KWallet` (v11).
//! - `v10` on Windows: AES-256-GCM with the key in `Local State`, which DPAPI
//!   wraps for the user. `v20` (Chrome 127+): the same key wrapped again by
//!   a service only Chrome may call, so no other program can read it. No
//!   prefix: the password itself, wrapped by DPAPI (before Chrome 80).

use std::path::Path;

use base64ct::{Base64, Encoding};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use zeroize::Zeroizing;

use super::crypto::{Cbc, aes256_gcm_decrypt, text};
use super::{
    BrowserKeyStore, BrowserLogins, BrowserReadError, Login, copy_database, open_database,
    private_temp_dir, sqlite_error, to_logins,
};
use crate::vault::import::CsvFormat;
use crate::{Error, Result, fsutil};

/// The login databases of a profile, in the order they are read.
pub(super) const LOGIN_FILES: [&str; 2] = ["Login Data", "Login Data For Account"];
/// Largest `Local State` file read.
const MAX_LOCAL_STATE: u64 = 16 * 1024 * 1024;
const SALT: &[u8] = b"saltysalt";
const IV: [u8; 16] = [b' '; 16];
/// How every DPAPI blob starts: version 1, then the DPAPI provider's GUID.
pub(super) const DPAPI_BLOB: [u8; 20] = [
    1, 0, 0, 0, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11, 0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2,
    0x97, 0xEB,
];

/// Where a Chromium browser keeps the password its logins' key is made of:
/// the Keychain item (macOS) with this service and account, the Secret
/// Service item with this `application` attribute (Linux), or the `KWallet`
/// entry `service` in the folder "`account` Keys".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeStorage {
    /// "Chrome Safe Storage".
    pub service: &'static str,
    /// "Chrome".
    pub account: &'static str,
    /// "chrome".
    pub application: &'static str,
}

/// How the profile's passwords are encrypted, which depends on the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Platform {
    Mac,
    Linux,
    Windows,
}

impl Platform {
    pub(super) const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Mac
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }
}

/// A login as the database has it, its password still encrypted.
struct Row {
    url: String,
    username: String,
    password: Vec<u8>,
}

/// Reads the profile at `dir` of the browser whose data folder is
/// `user_data`.
pub(super) fn read(
    dir: &Path,
    user_data: &Path,
    storage: &SafeStorage,
    os: &dyn BrowserKeyStore,
    platform: Platform,
) -> Result<BrowserLogins, BrowserReadError> {
    let temp = private_temp_dir()?;
    let mut rows = Vec::new();
    for (n, name) in LOGIN_FILES.iter().enumerate() {
        let source = dir.join(name);
        if !source.is_file() {
            continue;
        }
        // Each database in a folder of its own: both have `-wal` files.
        let into = temp.path().join(n.to_string());
        std::fs::create_dir(&into).map_err(|e| Error::io(e, &into))?;
        let copy = copy_database(&source, &into)?;
        rows.extend(read_rows(&copy)?);
    }
    drop(temp);

    let mut keys = Keys {
        platform,
        storage,
        os,
        user_data,
        v10: Key::Unasked,
        v11: Key::Unasked,
    };
    let mut logins = Vec::with_capacity(rows.len());
    let (mut unreadable, mut app_bound) = (0u32, 0u32);
    for row in rows {
        match keys.decrypt(&row.password)? {
            Plain::Text(password) => logins.push(Login {
                url: row.url,
                username: row.username,
                password,
            }),
            Plain::AppBound => app_bound += 1,
            Plain::Unreadable => unreadable += 1,
        }
    }
    if logins.is_empty() && app_bound > 0 {
        return Err(BrowserReadError::AppBound);
    }
    if logins.is_empty() && unreadable > 0 {
        return Err(match keys.missing_key() {
            Some(why) => BrowserReadError::KeyUnavailable(why.into()),
            None => BrowserReadError::Unsupported("no saved password could be decrypted".into()),
        });
    }
    to_logins(CsvFormat::Chrome, logins, unreadable, app_bound)
}

/// The logins of one database, leaving out the sites the user chose never
/// to save a password for.
fn read_rows(path: &Path) -> Result<Vec<Row>> {
    let db = open_database(path)?;
    let mut statement = db
        .prepare("SELECT * FROM logins")
        .map_err(|e| sqlite_error(&e))?;
    let column = |name: &str| statement.column_index(name).ok();
    let (Some(origin), Some(username), Some(password)) = (
        column("origin_url"),
        column("username_value"),
        column("password_value"),
    ) else {
        return Err(Error::Unsupported(
            "the browser's login database has an unknown layout".into(),
        ));
    };
    let realm = column("signon_realm");
    let blocked = column("blacklisted_by_user");
    let mut rows = statement.query([]).map_err(|e| sqlite_error(&e))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(|e| sqlite_error(&e))? {
        let is_blocked = blocked
            .and_then(|i| row.get::<_, Option<i64>>(i).ok().flatten())
            .is_some_and(|b| b != 0);
        if is_blocked {
            continue;
        }
        let text = |i: Option<usize>| -> String {
            i.and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
                .unwrap_or_default()
        };
        let mut url = text(Some(origin));
        if url.is_empty() {
            url = text(realm);
        }
        let password: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(password)
            .ok()
            .flatten()
            .unwrap_or_default();
        out.push(Row {
            url,
            username: text(Some(username)),
            password,
        });
    }
    Ok(out)
}

enum Plain {
    Text(Zeroizing<String>),
    /// Chrome's app-bound encryption (`v20`).
    AppBound,
    Unreadable,
}

/// The keys of a profile, fetched the first time a password needs them, so
/// the system is asked at most once, and only when there is something to
/// decrypt.
struct Keys<'a> {
    platform: Platform,
    storage: &'a SafeStorage,
    os: &'a dyn BrowserKeyStore,
    user_data: &'a Path,
    /// The key of `v10` passwords.
    v10: Key,
    /// Linux: the key of `v11` passwords.
    v11: Key,
}

/// A key, once it was looked for.
enum Key {
    Unasked,
    Missing,
    Found(Zeroizing<Vec<u8>>),
}

impl Key {
    fn from(key: Option<Zeroizing<Vec<u8>>>) -> Self {
        key.map_or(Self::Missing, Self::Found)
    }

    fn get(&self) -> Option<&[u8]> {
        match self {
            Self::Found(key) => Some(key),
            Self::Unasked | Self::Missing => None,
        }
    }
}

impl Keys<'_> {
    fn decrypt(&mut self, value: &[u8]) -> Result<Plain, BrowserReadError> {
        if value.is_empty() {
            return Ok(Plain::Text(Zeroizing::default()));
        }
        let (version, data) = value.split_at(value.len().min(3));
        let plain = match (self.platform, version) {
            (Platform::Mac | Platform::Linux, b"v10") => {
                let Some(key) = self.v10()? else {
                    return Ok(Plain::Unreadable);
                };
                Cbc::Aes128.decrypt(key, &IV, data)
            }
            (Platform::Linux, b"v11") => {
                let Some(key) = self.v11()? else {
                    return Ok(Plain::Unreadable);
                };
                Cbc::Aes128.decrypt(key, &IV, data)
            }
            (Platform::Windows, b"v10" | b"v11") => {
                let Some(key) = self.v10()? else {
                    return Ok(Plain::Unreadable);
                };
                aes256_gcm_decrypt(key, data)
            }
            (Platform::Windows, b"v20") => return Ok(Plain::AppBound),
            // Only what is a DPAPI blob goes to DPAPI.
            (Platform::Windows, _) if value.starts_with(&DPAPI_BLOB) => {
                match self.os.unprotect(value) {
                    Ok(plain) => Some(plain),
                    Err(BrowserReadError::Denied) => return Err(BrowserReadError::Denied),
                    Err(_) => None,
                }
            }
            _ => None,
        };
        Ok(plain
            .as_ref()
            .and_then(text)
            .map_or(Plain::Unreadable, Plain::Text))
    }

    fn v10(&mut self) -> Result<Option<&[u8]>, BrowserReadError> {
        if matches!(self.v10, Key::Unasked) {
            let key = match self.platform {
                Platform::Mac => self
                    .os
                    .safe_storage(self.storage)?
                    .map(|password| derive(&password, 1003)),
                Platform::Linux => Some(derive(b"peanuts", 1)),
                Platform::Windows => self.windows_key()?,
            };
            self.v10 = Key::from(key);
        }
        Ok(self.v10.get())
    }

    fn v11(&mut self) -> Result<Option<&[u8]>, BrowserReadError> {
        if matches!(self.v11, Key::Unasked) {
            // Without a key store, Chromium encrypts v11 with an empty password.
            let password = self.os.safe_storage(self.storage)?.unwrap_or_default();
            self.v11 = Key::Found(derive(&password, 1));
        }
        Ok(self.v11.get())
    }

    /// Windows: the AES key in `Local State`, unwrapped with DPAPI.
    fn windows_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, BrowserReadError> {
        let path = self.user_data.join("Local State");
        let Ok(bytes) = fsutil::read_limited(&path, MAX_LOCAL_STATE) else {
            return Ok(None);
        };
        let Ok(state) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            return Ok(None);
        };
        let Some(encoded) = state["os_crypt"]["encrypted_key"].as_str() else {
            return Ok(None);
        };
        let Ok(wrapped) = Base64::decode_vec(encoded) else {
            return Ok(None);
        };
        let Some(blob) = wrapped.strip_prefix(b"DPAPI") else {
            return Ok(None);
        };
        match self.os.unprotect(blob) {
            Ok(key) if key.len() == 32 => Ok(Some(key)),
            Ok(_) | Err(BrowserReadError::KeyUnavailable(_) | BrowserReadError::Other(_)) => {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    /// Why passwords couldn't be decrypted, when it was for want of a key.
    fn missing_key(&self) -> Option<&'static str> {
        match (self.platform, &self.v10) {
            (Platform::Mac, Key::Missing) => Some("the Keychain has no key for this browser"),
            (Platform::Windows, Key::Missing) => Some("the browser's key could not be unwrapped"),
            _ => None,
        }
    }
}

/// The AES-128 key Chromium makes of its password on macOS and Linux.
pub(super) fn derive(password: &[u8], rounds: u32) -> Zeroizing<Vec<u8>> {
    let mut key = Zeroizing::new(vec![0u8; 16]);
    pbkdf2_hmac::<Sha1>(password, SALT, rounds, &mut key);
    key
}
