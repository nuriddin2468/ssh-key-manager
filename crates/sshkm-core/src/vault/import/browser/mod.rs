//! Importing the logins a browser keeps, straight from its profile, instead
//! of through a CSV export.
//!
//! - **Chromium** (Chrome, Edge, Brave, Vivaldi, Chromium) keeps them in the
//!   SQLite files `Login Data` and `Login Data For Account`, each password
//!   encrypted with a key the system holds for the browser: a password in the
//!   macOS Keychain or the Linux Secret Service / `KWallet` ("Chrome Safe
//!   Storage"), or on Windows an AES key in `Local State` that DPAPI wraps.
//!   Asking for that key is what makes the system ask the user for
//!   permission. Chrome 127 and later on Windows encrypts new passwords with
//!   an app-bound key (`v20`) that only Chrome itself can unwrap; those can't
//!   be read and are counted, so the UI can send the user to a CSV export.
//! - **Firefox** keeps them in `logins.json`, encrypted with a key in
//!   `key4.db` (NSS), which a primary password may protect.
//! - **Safari** keeps them in the Keychain, out of reach: its CSV export is
//!   the only way.
//!
//! The databases are copied to a private temporary folder first (the browser
//! may hold them open, and nothing is ever written to its profile), read
//! there, and deleted. Decrypted values stay in [`Zeroizing`] buffers and end
//! up in the same records a CSV import makes, so the preview, the duplicate
//! check and the import itself work as they do for a file.

mod chromium;
mod crypto;
mod der;
mod firefox;
mod profiles;

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use zeroize::Zeroizing;

use super::{CsvFormat, ImportPreview, MAX_RECORDS, Parsed, Record, UNTITLED, host};
use crate::vault::{Vault, check_field};
use crate::{Error, Result};

pub use chromium::SafeStorage;
pub use profiles::{BrowserFamily, BrowserProfile, browser_profiles};

/// Largest browser database copied: far above any real profile.
const MAX_DB_SIZE: u64 = 512 * 1024 * 1024;

/// What the operating system does for a browser import: hand out the key a
/// browser keeps with it. Each call may show a system prompt and block until
/// the user answers it.
pub trait BrowserKeyStore {
    /// macOS and Linux: the password a Chromium browser keeps in the Keychain
    /// or the Secret Service / `KWallet`. `None` when there is none.
    /// [`BrowserReadError::Denied`] when the user refused to share it.
    fn safe_storage(
        &self,
        storage: &SafeStorage,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, BrowserReadError>;

    /// Windows: `blob` decrypted with DPAPI, as the signed-in user.
    fn unprotect(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, BrowserReadError>;
}

/// Why a browser's logins could not be read. None of these carries a secret.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BrowserReadError {
    /// The user refused the system's request for the browser's key.
    #[error("access to the browser's key was refused")]
    Denied,
    /// The system has no key for the browser, or no way to ask for it.
    #[error("the browser's key is not available: {0}")]
    KeyUnavailable(String),
    /// Every login is encrypted with Chrome's app-bound key (Windows).
    #[error("the browser encrypts its logins so that only it can read them")]
    AppBound,
    /// The Firefox profile has a primary password and none was given.
    #[error("the profile has a primary password")]
    PrimaryPasswordRequired,
    /// The primary password given doesn't open the profile.
    #[error("wrong primary password")]
    WrongPrimaryPassword,
    /// The profile is encrypted in a way this app can't read.
    #[error("unsupported encryption: {0}")]
    Unsupported(String),
    /// Reading the profile failed.
    #[error(transparent)]
    Other(#[from] Error),
}

/// The logins read from a browser profile, decrypted. What
/// [`Vault::browser_import_preview`] lists and [`Vault::import_browser`]
/// adds. Its secrets are wiped when it is dropped.
#[derive(Debug)]
pub struct BrowserLogins {
    parsed: Parsed,
    unreadable: u32,
    app_bound: u32,
}

impl BrowserLogins {
    /// Logins that could not be decrypted, app-bound ones included.
    pub fn unreadable(&self) -> u32 {
        self.unreadable + self.app_bound
    }

    /// Logins encrypted with Chrome's app-bound key, which only Chrome can
    /// read (part of [`Self::unreadable`]).
    pub fn app_bound(&self) -> u32 {
        self.app_bound
    }

    /// Logins read.
    pub fn len(&self) -> usize {
        self.parsed.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parsed.records.is_empty()
    }
}

impl BrowserProfile {
    /// Reads and decrypts the profile's saved logins. May ask the system for
    /// the browser's key through `keys`, which can show a prompt; Firefox
    /// profiles with a primary password need `primary_password`.
    pub fn read(
        &self,
        keys: &dyn BrowserKeyStore,
        primary_password: Option<&SecretString>,
    ) -> Result<BrowserLogins, BrowserReadError> {
        match self.family {
            BrowserFamily::Chromium => {
                let storage = self.storage.as_ref().ok_or_else(|| {
                    BrowserReadError::Unsupported("no key store for this browser".into())
                })?;
                chromium::read(
                    &self.dir,
                    &self.user_data,
                    storage,
                    keys,
                    chromium::Platform::current(),
                )
            }
            BrowserFamily::Firefox => firefox::read(&self.dir, primary_password),
        }
    }
}

impl Vault {
    /// Lists the logins read from a browser like [`Vault::import_preview`]
    /// lists a file's rows: without secrets, marking duplicates.
    pub fn browser_import_preview(&self, logins: &BrowserLogins) -> ImportPreview {
        self.preview_parsed(&logins.parsed)
    }

    /// Adds the logins at `indices` (from the preview) as entries, like
    /// [`Vault::import_csv`]. The caller saves the vault.
    pub fn import_browser(&mut self, logins: &BrowserLogins, indices: &[u32]) -> Result<usize> {
        self.apply_parsed(&logins.parsed, indices)
    }
}

/// A login as a browser keeps it, decrypted.
struct Login {
    url: String,
    username: String,
    password: Zeroizing<String>,
}

/// The logins as import records: one per site, user name and password (a
/// login saved in both of Chrome's stores is listed once), leaving out the
/// ones that can't be stored.
fn to_logins(
    format: CsvFormat,
    logins: Vec<Login>,
    unreadable: u32,
    app_bound: u32,
) -> Result<BrowserLogins, BrowserReadError> {
    if logins.len() > MAX_RECORDS {
        return Err(
            Error::invalid(format!("the profile has more than {MAX_RECORDS} logins")).into(),
        );
    }
    let mut records: Vec<Record> = Vec::with_capacity(logins.len());
    let mut seen: HashMap<(String, String), Vec<usize>> = HashMap::new();
    let mut skipped = 0;
    for (index, login) in (0u32..).zip(logins) {
        let key = (login.url.clone(), login.username.clone());
        let same = seen.get(&key).is_some_and(|at| {
            at.iter()
                .any(|&i| records[i].password.as_str() == login.password.as_str())
        });
        if same {
            continue;
        }
        match record(index, login) {
            Some(record) => {
                seen.entry(key).or_default().push(records.len());
                records.push(record);
            }
            None => skipped += 1,
        }
    }
    Ok(BrowserLogins {
        parsed: Parsed {
            format,
            records,
            skipped,
        },
        unreadable,
        app_bound,
    })
}

fn record(index: u32, login: Login) -> Option<Record> {
    let Login {
        url,
        username,
        password,
    } = login;
    let url = url.trim().to_owned();
    let username = username.trim().to_owned();
    if url.is_empty() && username.is_empty() && password.is_empty() {
        return None;
    }
    let title = [host(&url), url.clone(), username.clone()]
        .into_iter()
        .find(|t| !t.is_empty())
        .unwrap_or_else(|| UNTITLED.to_owned());
    if [&title, &username, &url, password.as_str()]
        .iter()
        .any(|v| check_field(v).is_err())
    {
        return None;
    }
    Some(Record {
        index,
        title,
        username,
        url,
        notes: String::new(),
        group: None,
        password,
        otp: None,
        unreadable_otp: None,
    })
}

/// A private temporary folder for copies of a browser's databases, deleted
/// with everything in it when dropped. Only the user can open it.
fn private_temp_dir() -> Result<tempfile::TempDir> {
    // Mode 0700 on Unix, set as the folder is made. On Windows it is in the
    // user's own temporary folder, whose access list only lets them in.
    let mut builder = tempfile::Builder::new();
    builder.prefix("sshkm-browser-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    builder
        .tempdir()
        .map_err(|e| Error::io(e, &std::env::temp_dir()))
}

/// Copies the SQLite database at `source` (with its write-ahead log, if
/// there is one) into `dir`, readable by the user only, and returns the
/// copy's path. The browser may be running and writing it: the copy is what
/// SQLite reads, so the browser's file is never locked or changed.
fn copy_database(source: &Path, dir: &Path) -> Result<PathBuf> {
    let name = source
        .file_name()
        .ok_or_else(|| Error::invalid("not a database file"))?;
    let target = dir.join(name);
    copy_private(source, &target)?;
    let mut wal = source.as_os_str().to_owned();
    wal.push("-wal");
    let wal = PathBuf::from(wal);
    if wal.is_file() {
        let mut target_wal = target.as_os_str().to_owned();
        target_wal.push("-wal");
        copy_private(&wal, Path::new(&target_wal))?;
    }
    Ok(target)
}

fn copy_private(source: &Path, target: &Path) -> Result<()> {
    let file = fs::File::open(source).map_err(|e| Error::io(e, source))?;
    let len = file.metadata().map_err(|e| Error::io(e, source))?.len();
    if len > MAX_DB_SIZE {
        return Err(Error::invalid(format!(
            "{} is larger than {MAX_DB_SIZE} bytes",
            source.display()
        )));
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut out = options.open(target).map_err(|e| Error::io(e, target))?;
    let copied = io::copy(&mut file.take(MAX_DB_SIZE + 1), &mut out)
        .and_then(|copied| out.flush().map(|()| copied))
        .map_err(|e| Error::io(e, target))?;
    if copied > MAX_DB_SIZE {
        return Err(Error::invalid(format!(
            "{} is larger than {MAX_DB_SIZE} bytes",
            source.display()
        )));
    }
    Ok(())
}

/// Opens a database copied with [`copy_database`]. Read-write, since SQLite
/// may have to replay the copied write-ahead log, but only ever read.
fn open_database(path: &Path) -> Result<rusqlite::Connection> {
    use rusqlite::OpenFlags;
    rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| sqlite_error(&e))
}

fn sqlite_error(error: &rusqlite::Error) -> Error {
    // SQLite's messages name tables and columns, never values.
    Error::Parse(format!("reading the browser's database: {error}"))
}

#[cfg(test)]
mod tests;
