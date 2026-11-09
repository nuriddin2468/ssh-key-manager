//! Browser import. The fixtures are databases made here, laid out as the
//! browsers lay theirs out, with values encrypted the way each browser and
//! system encrypts them; no real profile is read.

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use rusqlite::{Connection, params};
use secrecy::{ExposeSecret, SecretString};
use sha1::{Digest, Sha1};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::chromium::{self, Platform, SafeStorage};
use super::crypto::{Cbc, encrypt};
use super::der::{OBJECT_ID, OCTET_STRING, oid, write};
use super::firefox::nss_3des_key;
use super::profiles::{CHROMIUM, chromium_profiles, firefox_profiles, parse_profiles_ini};
use super::*;
use crate::vault::{SecretField, VaultPaths};

const STORAGE: SafeStorage = SafeStorage {
    service: "Chrome Safe Storage",
    account: "Chrome",
    application: "chrome",
};
const IV: [u8; 16] = [b' '; 16];

/// The system's side, as a test sets it up: a stored password, a refusal,
/// and DPAPI as XOR with a fixed byte. Counts how often it is asked.
#[derive(Default)]
struct FakeKeys {
    password: Option<&'static [u8]>,
    denied: bool,
    asked: Cell<u32>,
}

const DPAPI_XOR: u8 = 0x5A;

impl BrowserKeyStore for FakeKeys {
    fn safe_storage(
        &self,
        storage: &SafeStorage,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, BrowserReadError> {
        assert_eq!(storage, &STORAGE);
        self.asked.set(self.asked.get() + 1);
        if self.denied {
            return Err(BrowserReadError::Denied);
        }
        Ok(self.password.map(|p| Zeroizing::new(p.to_vec())))
    }

    fn unprotect(&self, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, BrowserReadError> {
        self.asked.set(self.asked.get() + 1);
        Ok(Zeroizing::new(dpapi(blob)))
    }
}

fn dpapi(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(|b| b ^ DPAPI_XOR).collect()
}

struct ChromeRow {
    url: &'static str,
    user: &'static str,
    password: Vec<u8>,
    blocked: bool,
}

fn row(url: &'static str, user: &'static str, password: Vec<u8>) -> ChromeRow {
    ChromeRow {
        url,
        user,
        password,
        blocked: false,
    }
}

/// A `Login Data` database with Chromium's columns (the ones read, and some
/// others).
fn login_db(path: &Path, rows: &[ChromeRow]) {
    let db = Connection::open(path).unwrap();
    db.execute_batch(
        "CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR,
            username_element VARCHAR, username_value VARCHAR, password_element VARCHAR,
            password_value BLOB, signon_realm VARCHAR NOT NULL,
            date_created INTEGER NOT NULL DEFAULT 0, blacklisted_by_user INTEGER NOT NULL DEFAULT 0,
            id INTEGER PRIMARY KEY AUTOINCREMENT);",
    )
    .unwrap();
    for r in rows {
        db.execute(
            "INSERT INTO logins (origin_url, action_url, username_value, password_value,
                signon_realm, blacklisted_by_user) VALUES (?1, ?1, ?2, ?3, ?1, ?4)",
            params![r.url, r.user, r.password, i64::from(r.blocked)],
        )
        .unwrap();
    }
}

fn mac_v10(password: &[u8], plain: &str) -> Vec<u8> {
    let key = chromium::derive(password, 1003);
    [
        b"v10".as_slice(),
        &encrypt::cbc(Cbc::Aes128, &key, &IV, plain.as_bytes()),
    ]
    .concat()
}

fn linux(version: [u8; 3], password: &[u8], plain: &str) -> Vec<u8> {
    let key = chromium::derive(password, 1);
    [
        version.as_slice(),
        &encrypt::cbc(Cbc::Aes128, &key, &IV, plain.as_bytes()),
    ]
    .concat()
}

const WINDOWS_KEY: [u8; 32] = [7; 32];

fn windows(version: [u8; 3], plain: &str) -> Vec<u8> {
    [
        version.as_slice(),
        &encrypt::gcm(&WINDOWS_KEY, &[9; 12], plain.as_bytes()),
    ]
    .concat()
}

/// A Chromium data folder with one profile, `Default`.
struct Chrome {
    root: TempDir,
}

impl Chrome {
    fn new(rows: &[ChromeRow]) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir(root.path().join("Default")).unwrap();
        login_db(&root.path().join("Default/Login Data"), rows);
        let wrapped = [b"DPAPI".as_slice(), &dpapi(&WINDOWS_KEY)].concat();
        let state = serde_json::json!({
            "os_crypt": { "encrypted_key": Base64::encode_string(&wrapped) },
            "profile": { "info_cache": { "Default": { "name": "Person 1" } } }
        });
        fs::write(root.path().join("Local State"), state.to_string()).unwrap();
        Self { root }
    }

    fn profile(&self) -> PathBuf {
        self.root.path().join("Default")
    }

    fn read(&self, keys: &FakeKeys, platform: Platform) -> Result<BrowserLogins, BrowserReadError> {
        chromium::read(&self.profile(), self.root.path(), &STORAGE, keys, platform)
    }
}

fn passwords(logins: &BrowserLogins) -> Vec<(&str, &str, &str)> {
    logins
        .parsed
        .records
        .iter()
        .map(|r| (r.url.as_str(), r.username.as_str(), r.password.as_str()))
        .collect()
}

#[test]
fn macos_passwords_decrypt_with_the_keychain_password() {
    let chrome = Chrome::new(&[
        row(
            "https://github.com/login",
            "octocat",
            mac_v10(b"keychain", "hunter2"),
        ),
        row(
            "https://example.com/",
            "me@example.com",
            mac_v10(b"keychain", "пароль ✓"),
        ),
        // Saved without a password (e.g. a federated sign-in).
        row("https://sso.example.com/", "me", Vec::new()),
    ]);
    let keys = FakeKeys {
        password: Some(b"keychain"),
        ..FakeKeys::default()
    };
    let logins = chrome.read(&keys, Platform::Mac).unwrap();
    assert_eq!(
        passwords(&logins),
        [
            ("https://github.com/login", "octocat", "hunter2"),
            ("https://example.com/", "me@example.com", "пароль ✓"),
            ("https://sso.example.com/", "me", ""),
        ]
    );
    assert_eq!(logins.unreadable(), 0);
    // Asked once, for all of them.
    assert_eq!(keys.asked.get(), 1);
}

#[test]
fn the_keychain_is_not_asked_when_nothing_is_encrypted() {
    let chrome = Chrome::new(&[row("https://a.example/", "me", Vec::new())]);
    let keys = FakeKeys::default();
    let logins = chrome.read(&keys, Platform::Mac).unwrap();
    assert_eq!(logins.len(), 1);
    assert_eq!(keys.asked.get(), 0);
}

#[test]
fn a_refused_keychain_prompt_stops_the_import() {
    let chrome = Chrome::new(&[row("https://a.example/", "me", mac_v10(b"k", "x"))]);
    let keys = FakeKeys {
        denied: true,
        ..FakeKeys::default()
    };
    let error = chrome.read(&keys, Platform::Mac).unwrap_err();
    assert!(matches!(error, BrowserReadError::Denied), "{error:?}");
}

#[test]
fn no_keychain_item_means_no_key() {
    let chrome = Chrome::new(&[row("https://a.example/", "me", mac_v10(b"k", "x"))]);
    let error = chrome
        .read(&FakeKeys::default(), Platform::Mac)
        .unwrap_err();
    assert!(
        matches!(error, BrowserReadError::KeyUnavailable(_)),
        "{error:?}"
    );
}

#[test]
fn a_wrong_key_reads_nothing() {
    let chrome = Chrome::new(&[row("https://a.example/", "me", mac_v10(b"right", "secret"))]);
    let keys = FakeKeys {
        password: Some(b"wrong"),
        ..FakeKeys::default()
    };
    let error = chrome.read(&keys, Platform::Mac).unwrap_err();
    assert!(
        matches!(error, BrowserReadError::Unsupported(_)),
        "{error:?}"
    );
}

#[test]
fn never_saved_sites_and_repeats_are_left_out() {
    let mut blocked = row("https://never.example/", "", Vec::new());
    blocked.blocked = true;
    let chrome = Chrome::new(&[
        blocked,
        row("https://a.example/", "me", mac_v10(b"k", "one")),
        row("https://a.example/", "me", mac_v10(b"k", "two")),
    ]);
    // The account store repeats one login and adds another.
    login_db(
        &chrome.profile().join("Login Data For Account"),
        &[
            row("https://a.example/", "me", mac_v10(b"k", "one")),
            row("https://b.example/", "you", mac_v10(b"k", "three")),
        ],
    );
    let keys = FakeKeys {
        password: Some(b"k"),
        ..FakeKeys::default()
    };
    let logins = chrome.read(&keys, Platform::Mac).unwrap();
    assert_eq!(
        passwords(&logins),
        [
            ("https://a.example/", "me", "one"),
            ("https://a.example/", "me", "two"),
            ("https://b.example/", "you", "three"),
        ]
    );
}

#[test]
fn linux_v10_uses_the_fixed_password_and_v11_the_keyring() {
    let chrome = Chrome::new(&[
        row(
            "https://a.example/",
            "a",
            linux(*b"v10", b"peanuts", "first"),
        ),
        row(
            "https://b.example/",
            "b",
            linux(*b"v11", b"from-keyring", "second"),
        ),
    ]);
    let keys = FakeKeys {
        password: Some(b"from-keyring"),
        ..FakeKeys::default()
    };
    let logins = chrome.read(&keys, Platform::Linux).unwrap();
    assert_eq!(
        passwords(&logins),
        [
            ("https://a.example/", "a", "first"),
            ("https://b.example/", "b", "second"),
        ]
    );
    assert_eq!(keys.asked.get(), 1);
}

#[test]
fn linux_v11_without_a_keyring_uses_an_empty_password() {
    let chrome = Chrome::new(&[row("https://a.example/", "a", linux(*b"v11", b"", "x"))]);
    let logins = chrome.read(&FakeKeys::default(), Platform::Linux).unwrap();
    assert_eq!(passwords(&logins), [("https://a.example/", "a", "x")]);
}

#[test]
fn windows_passwords_decrypt_with_the_dpapi_wrapped_key() {
    let chrome = Chrome::new(&[
        row("https://a.example/", "a", windows(*b"v10", "gcm")),
        // Before Chrome 80: the password wrapped by DPAPI itself.
        row("https://b.example/", "b", dpapi(b"legacy")),
    ]);
    let logins = chrome
        .read(&FakeKeys::default(), Platform::Windows)
        .unwrap();
    assert_eq!(
        passwords(&logins),
        [
            ("https://a.example/", "a", "gcm"),
            ("https://b.example/", "b", "legacy"),
        ]
    );
    assert_eq!(logins.unreadable(), 0);
}

#[test]
fn windows_app_bound_passwords_are_counted() {
    let chrome = Chrome::new(&[
        row("https://a.example/", "a", windows(*b"v10", "old")),
        row("https://b.example/", "b", windows(*b"v20", "new")),
    ]);
    let logins = chrome
        .read(&FakeKeys::default(), Platform::Windows)
        .unwrap();
    assert_eq!(passwords(&logins), [("https://a.example/", "a", "old")]);
    assert_eq!((logins.unreadable(), logins.app_bound()), (1, 1));

    let only_new = Chrome::new(&[row("https://b.example/", "b", windows(*b"v20", "new"))]);
    let error = only_new
        .read(&FakeKeys::default(), Platform::Windows)
        .unwrap_err();
    assert!(matches!(error, BrowserReadError::AppBound), "{error:?}");
}

#[test]
fn the_browsers_database_is_left_as_it_was() {
    let chrome = Chrome::new(&[row("https://a.example/", "me", mac_v10(b"k", "x"))]);
    let path = chrome.profile().join("Login Data");
    let before = fs::read(&path).unwrap();
    let keys = FakeKeys {
        password: Some(b"k"),
        ..FakeKeys::default()
    };
    chrome.read(&keys, Platform::Mac).unwrap();
    assert_eq!(fs::read(&path).unwrap(), before);
    let names: Vec<_> = fs::read_dir(chrome.profile())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["Login Data"]);
}

#[test]
fn private_copies_are_owner_only_and_deleted() {
    let chrome = Chrome::new(&[row("https://a.example/", "me", Vec::new())]);
    let temp = private_temp_dir().unwrap();
    let copy = copy_database(&chrome.profile().join("Login Data"), temp.path()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(temp.path()), 0o700);
        assert_eq!(mode(&copy), 0o600);
    }
    let dir = temp.path().to_owned();
    drop(temp);
    assert!(!dir.exists());
}

#[test]
fn chromium_profiles_are_named_and_kept_inside_the_data_folder() {
    let chrome = Chrome::new(&[row("https://a.example/", "me", Vec::new())]);
    let root = chrome.root.path();
    fs::create_dir(root.join("Profile 2")).unwrap();
    login_db(&root.join("Profile 2/Login Data"), &[]);
    // A profile without logins, and a name that leaves the folder.
    fs::create_dir(root.join("Profile 3")).unwrap();
    let state = serde_json::json!({
        "profile": { "info_cache": {
            "Default": { "name": "Person 1" },
            "Profile 2": { "name": "Work" },
            "Profile 3": { "name": "Empty" },
            "../Default": { "name": "Escape" },
        } }
    });
    fs::write(root.join("Local State"), state.to_string()).unwrap();
    let profiles = chromium_profiles(&CHROMIUM[0], root);
    let names: Vec<_> = profiles
        .iter()
        .map(|p| (p.id.as_str(), p.name.as_str(), p.browser.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("chrome:Default", "Person 1", "Google Chrome"),
            ("chrome:Profile 2", "Work", "Google Chrome"),
        ]
    );
}

// --- Firefox ---------------------------------------------------------------

const KEY_ID: &[u8] = &[0xF8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn hashed(global_salt: &[u8], primary: &str) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(global_salt);
    h.update(primary.as_bytes());
    h.finalize().to_vec()
}

/// PBES2 as NSS writes it: PBKDF2-HMAC-SHA256, AES-256-CBC with a 14-byte IV.
fn pbes2(global_salt: &[u8], primary: &str, plain: &[u8]) -> Vec<u8> {
    let salt = [3u8; 32];
    let iv14 = [4u8; 14];
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&hashed(global_salt, primary), &salt, 1000, &mut key);
    let iv = [&[0x04, 0x0E], iv14.as_slice()].concat();
    let ciphertext = encrypt::cbc(Cbc::Aes256, &key, &iv, plain);
    write::seq(&[
        write::seq(&[
            write::tlv(OBJECT_ID, oid::PBES2),
            write::seq(&[
                write::seq(&[
                    write::tlv(OBJECT_ID, oid::PBKDF2),
                    write::seq(&[
                        write::tlv(OCTET_STRING, &salt),
                        write::int(1000),
                        write::int(32),
                        write::seq(&[write::tlv(OBJECT_ID, oid::HMAC_SHA256)]),
                    ]),
                ]),
                write::seq(&[
                    write::tlv(OBJECT_ID, oid::AES256_CBC),
                    write::tlv(OCTET_STRING, &iv14),
                ]),
            ]),
        ]),
        write::tlv(OCTET_STRING, &ciphertext),
    ])
}

/// The legacy PKCS #12 3DES PBE of older profiles.
fn pbe_3des(global_salt: &[u8], primary: &str, plain: &[u8]) -> Vec<u8> {
    let entry_salt = [5u8; 20];
    let (key, iv) = nss_3des_key(&hashed(global_salt, primary), &entry_salt);
    let ciphertext = encrypt::cbc(Cbc::Tdes, &key, &iv, plain);
    write::seq(&[
        write::seq(&[
            write::tlv(OBJECT_ID, oid::PBE_SHA1_3DES),
            write::seq(&[write::tlv(OCTET_STRING, &entry_salt), write::int(1)]),
        ]),
        write::tlv(OCTET_STRING, &ciphertext),
    ])
}

/// A `logins.json` value.
fn login_value(cipher: Cbc, key: &[u8], plain: &str) -> String {
    let (id, iv) = match cipher {
        Cbc::Aes256 => (oid::AES256_CBC, vec![6u8; 16]),
        _ => (oid::DES_EDE3_CBC, vec![6u8; 8]),
    };
    let ciphertext = encrypt::cbc(cipher, key, &iv, plain.as_bytes());
    Base64::encode_string(&write::seq(&[
        write::tlv(OCTET_STRING, KEY_ID),
        write::seq(&[write::tlv(OBJECT_ID, id), write::tlv(OCTET_STRING, &iv)]),
        write::tlv(OCTET_STRING, &ciphertext),
    ]))
}

#[derive(Clone, Copy)]
enum Nss {
    /// Firefox 72 and later: PBES2, AES-256 logins.
    Aes,
    /// Older profiles: 3DES throughout.
    Tdes,
}

type Pbe = fn(&[u8], &str, &[u8]) -> Vec<u8>;

/// A Firefox profile with a `key4.db` locked by `primary` ("" for none).
fn firefox(nss: Nss, primary: &str, logins: &[(&str, &str, &str)]) -> TempDir {
    let dir = tempfile::tempdir().unwrap();
    let global_salt = [1u8; 20];
    let (cipher, key, pbe): (Cbc, Vec<u8>, Pbe) = match nss {
        Nss::Aes => (Cbc::Aes256, vec![8u8; 32], pbes2),
        Nss::Tdes => (Cbc::Tdes, vec![8u8; 24], pbe_3des),
    };
    let db = Connection::open(dir.path().join("key4.db")).unwrap();
    db.execute_batch(
        "CREATE TABLE metaData (id PRIMARY KEY UNIQUE ON CONFLICT REPLACE, item1, item2);
         CREATE TABLE nssPrivate (id PRIMARY KEY UNIQUE ON CONFLICT ABORT, a11, a102);",
    )
    .unwrap();
    db.execute(
        "INSERT INTO metaData VALUES ('password', ?1, ?2)",
        params![
            global_salt.to_vec(),
            pbe(&global_salt, primary, b"password-check")
        ],
    )
    .unwrap();
    // A key of something else first, then the logins' key.
    db.execute(
        "INSERT INTO nssPrivate VALUES (1, ?1, ?2)",
        params![pbe(&global_salt, primary, &[9u8; 32]), vec![1u8; 16]],
    )
    .unwrap();
    db.execute(
        "INSERT INTO nssPrivate VALUES (2, ?1, ?2)",
        params![pbe(&global_salt, primary, &key), KEY_ID.to_vec()],
    )
    .unwrap();
    drop(db);
    let logins: Vec<_> = logins
        .iter()
        .map(|(url, user, password)| {
            serde_json::json!({
                "hostname": url,
                "formSubmitURL": url,
                "encryptedUsername": login_value(cipher, &key, user),
                "encryptedPassword": login_value(cipher, &key, password),
                "encType": 1,
            })
        })
        .collect();
    fs::write(
        dir.path().join("logins.json"),
        serde_json::json!({ "nextId": 3, "logins": logins }).to_string(),
    )
    .unwrap();
    dir
}

fn s(text: &str) -> SecretString {
    SecretString::from(text.to_owned())
}

const FIREFOX_LOGINS: &[(&str, &str, &str)] = &[
    ("https://github.com", "octocat", "hunter2"),
    ("https://example.com", "", "пароль"),
];

#[test]
fn firefox_logins_decrypt_without_a_primary_password() {
    for nss in [Nss::Aes, Nss::Tdes] {
        let profile = firefox(nss, "", FIREFOX_LOGINS);
        let logins = firefox::read(profile.path(), None).unwrap();
        assert_eq!(passwords(&logins), FIREFOX_LOGINS);
    }
}

#[test]
fn firefox_primary_password_is_asked_for_and_checked() {
    for nss in [Nss::Aes, Nss::Tdes] {
        let profile = firefox(nss, "correct horse", FIREFOX_LOGINS);
        let error = firefox::read(profile.path(), None).unwrap_err();
        assert!(
            matches!(error, BrowserReadError::PrimaryPasswordRequired),
            "{error:?}"
        );
        let error = firefox::read(profile.path(), Some(&s("wrong"))).unwrap_err();
        assert!(
            matches!(error, BrowserReadError::WrongPrimaryPassword),
            "{error:?}"
        );
        let logins = firefox::read(profile.path(), Some(&s("correct horse"))).unwrap();
        assert_eq!(passwords(&logins), FIREFOX_LOGINS);
    }
}

#[test]
fn firefox_without_logins_reads_nothing() {
    let dir = tempfile::tempdir().unwrap();
    assert!(firefox::read(dir.path(), None).unwrap().is_empty());
    let profile = firefox(Nss::Aes, "", &[]);
    assert!(firefox::read(profile.path(), None).unwrap().is_empty());
}

#[test]
fn firefox_old_or_unknown_key_databases_are_unsupported() {
    let profile = firefox(Nss::Aes, "", FIREFOX_LOGINS);
    fs::remove_file(profile.path().join("key4.db")).unwrap();
    fs::write(profile.path().join("key3.db"), b"old").unwrap();
    let error = firefox::read(profile.path(), None).unwrap_err();
    assert!(
        matches!(error, BrowserReadError::Unsupported(_)),
        "{error:?}"
    );

    let profile = firefox(Nss::Aes, "", FIREFOX_LOGINS);
    let db = Connection::open(profile.path().join("key4.db")).unwrap();
    let unknown = write::seq(&[
        write::seq(&[write::tlv(OBJECT_ID, &[0x2A, 0x03])]),
        write::tlv(OCTET_STRING, &[0; 16]),
    ]);
    db.execute("UPDATE metaData SET item2 = ?1", params![unknown])
        .unwrap();
    drop(db);
    let error = firefox::read(profile.path(), None).unwrap_err();
    assert!(
        matches!(error, BrowserReadError::Unsupported(_)),
        "{error:?}"
    );
}

#[test]
fn profiles_ini_lists_profiles_default_first() {
    let root = tempfile::tempdir().unwrap();
    let ini = "[Install4F96D1932A9F858E]\nDefault=Profiles/b.default-release\n\n\
        [Profile1]\nName=default\nIsRelative=1\nPath=Profiles/a.default\n\n\
        [Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/b.default-release\nDefault=1\n\n\
        [Profile2]\nName=escape\nIsRelative=1\nPath=../../elsewhere\n\n\
        [General]\nStartWithLastProfile=1\n";
    fs::write(root.path().join("profiles.ini"), ini).unwrap();
    assert_eq!(parse_profiles_ini(ini).len(), 3);
    for name in ["a.default", "b.default-release"] {
        let dir = root.path().join("Profiles").join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("logins.json"), "{}").unwrap();
    }
    let profiles = firefox_profiles(0, root.path());
    let names: Vec<_> = profiles
        .iter()
        .map(|p| (p.id.as_str(), p.name.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("firefox:0:Profiles/b.default-release", "default-release"),
            ("firefox:0:Profiles/a.default", "default"),
        ]
    );
}

// --- Through the vault -----------------------------------------------------

#[test]
fn browser_logins_preview_and_import_like_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let paths = VaultPaths::new(dir.path().join("vault.kdbx"));
    let (mut vault, _recovery) = Vault::create(&paths, &s("master")).unwrap();
    vault
        .add_entry(&crate::vault::EntryInput {
            title: "GitHub".into(),
            username: "octocat".into(),
            url: "https://github.com/".into(),
            password: Some(s("old")),
            ..crate::vault::EntryInput::default()
        })
        .unwrap();

    let profile = firefox(Nss::Aes, "", FIREFOX_LOGINS);
    let logins = firefox::read(profile.path(), None).unwrap();
    let preview = vault.browser_import_preview(&logins);
    assert_eq!(preview.format, CsvFormat::Firefox);
    let rows: Vec<_> = preview
        .rows
        .iter()
        .map(|r| (r.title.as_str(), r.duplicate_of.is_some(), r.has_password))
        .collect();
    assert_eq!(
        rows,
        [("github.com", true), ("example.com", false)].map(|(t, d)| (t, d, true))
    );

    let count = vault
        .import_browser(&logins, &[preview.rows[1].index])
        .unwrap();
    assert_eq!(count, 1);
    let added = vault
        .entries()
        .into_iter()
        .find(|e| e.title == "example.com")
        .unwrap();
    let password = vault.secret(&added.id, SecretField::Password).unwrap();
    assert_eq!(password.expose_secret(), "пароль");
}
