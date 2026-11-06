//! SSH key files: scanning `~/.ssh`, inspecting single files, generating,
//! importing, re-encrypting and trashing keys.
//!
//! Keys are detected by content, not by name. Supported private key formats are
//! the OpenSSH format (what `ssh-keygen` writes since 7.8), legacy PEM
//! (`BEGIN RSA/EC/DSA PRIVATE KEY`) and PKCS#8. Public keys are one-line OpenSSH
//! public keys (`ssh-ed25519 AAAA… comment`).
//!
//! The public half of an OpenSSH private key is stored unencrypted, so
//! encrypted keys get a fingerprint and public key without a passphrase.

pub mod convert;
mod legacy;
mod ops;
mod ppk;
mod randomart;
#[cfg(test)]
pub(crate) mod testdata;

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};

use serde::{Deserialize, Serialize};
use ssh_key::{
    Algorithm, EcdsaCurve as SshCurve, HashAlg, Mpint, PrivateKey, PublicKey, public::KeyData,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use zeroize::Zeroizing;

pub use ops::{
    EcdsaCurve, GenerateAlgorithm, GenerateRequest, UnlockedKey, add_public, change_passphrase,
    generate, import, load_private, move_to_trash, regenerate_public, validate_file_name,
};

use crate::{
    Error, Result, fsutil,
    paths::path_string,
    perms::{self, PermKind, PermissionProblem, PermissionReport},
};

/// Files larger than this are never keys and are not read.
pub const MAX_KEY_FILE_SIZE: u64 = 64 * 1024;

/// Key algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum KeyAlgorithm {
    /// `ssh-ed25519`
    Ed25519,
    /// `ssh-rsa`
    Rsa,
    /// `ecdsa-sha2-nistp256`
    EcdsaP256,
    /// `ecdsa-sha2-nistp384`
    EcdsaP384,
    /// `ecdsa-sha2-nistp521`
    EcdsaP521,
    /// `sk-ssh-ed25519@openssh.com` (FIDO/U2F security key)
    SkEd25519,
    /// `sk-ecdsa-sha2-nistp256@openssh.com` (FIDO/U2F security key)
    SkEcdsaP256,
    /// `ssh-dss` (deprecated, disabled in OpenSSH since 7.0)
    Dsa,
    /// Anything else (see [`KeyInfo::key_type`]).
    Other,
}

impl KeyAlgorithm {
    /// True for keys backed by a hardware security key (`sk-*`).
    pub const fn is_hardware(self) -> bool {
        matches!(self, Self::SkEd25519 | Self::SkEcdsaP256)
    }

    /// The OpenSSH key type name (`""` for [`KeyAlgorithm::Other`]).
    pub const fn key_type(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::Rsa => "ssh-rsa",
            Self::EcdsaP256 => "ecdsa-sha2-nistp256",
            Self::EcdsaP384 => "ecdsa-sha2-nistp384",
            Self::EcdsaP521 => "ecdsa-sha2-nistp521",
            Self::SkEd25519 => "sk-ssh-ed25519@openssh.com",
            Self::SkEcdsaP256 => "sk-ecdsa-sha2-nistp256@openssh.com",
            Self::Dsa => "ssh-dss",
            Self::Other => "",
        }
    }

    pub(crate) fn from_ssh(alg: &Algorithm) -> Self {
        match alg {
            Algorithm::Ed25519 => Self::Ed25519,
            Algorithm::Rsa { .. } => Self::Rsa,
            Algorithm::Ecdsa { curve } => match curve {
                SshCurve::NistP256 => Self::EcdsaP256,
                SshCurve::NistP384 => Self::EcdsaP384,
                SshCurve::NistP521 => Self::EcdsaP521,
            },
            Algorithm::SkEd25519 => Self::SkEd25519,
            Algorithm::SkEcdsaSha2NistP256 => Self::SkEcdsaP256,
            Algorithm::Dsa => Self::Dsa,
            _ => Self::Other,
        }
    }
}

/// On-disk format of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum KeyFormat {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----`
    Openssh,
    /// Legacy PEM: `-----BEGIN RSA/EC/DSA PRIVATE KEY-----`
    Pem,
    /// PKCS#8: `-----BEGIN (ENCRYPTED) PRIVATE KEY-----`
    Pkcs8,
    /// Only a public key file exists.
    PublicOnly,
}

/// Metadata of one key (a private key and/or its `.pub` file). Never contains
/// private key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct KeyInfo {
    /// Stable identifier: `<fingerprint>#<file name>` (`unknown#…` when the
    /// fingerprint cannot be determined). The file name makes copies of the same
    /// key distinct.
    pub id: String,
    /// Display name: the private key's file name, or the public key's without
    /// `.pub`.
    pub name: String,
    /// Absolute path of the private key file.
    pub private_path: Option<String>,
    /// Absolute path of the public key file.
    pub public_path: Option<String>,
    /// Algorithm.
    pub algorithm: KeyAlgorithm,
    /// OpenSSH key type, e.g. `ssh-ed25519` (empty if unknown).
    pub key_type: String,
    /// Key size in bits (RSA modulus, DSA `p`, curve size).
    pub bits: Option<u32>,
    /// `SHA256:…` fingerprint as printed by `ssh-keygen -l`. `None` only for
    /// encrypted legacy PEM/PKCS#8 keys without a `.pub` file.
    pub fingerprint: Option<String>,
    /// Comment (from the `.pub` file, else from an unencrypted private key).
    pub comment: String,
    /// Whether the private key is passphrase-protected (`None` without a
    /// private key).
    pub encrypted: Option<bool>,
    /// Hardware security key (`sk-*`).
    pub hardware: bool,
    /// File format of the private key, or `publicOnly`.
    pub format: KeyFormat,
    /// One-line OpenSSH public key with comment. When the private key and its
    /// `.pub` disagree this is the private key's real public key.
    pub public_key: Option<String>,
    /// Modification time of the private (else public) file, RFC 3339 UTC.
    pub modified: Option<String>,
    /// The `.pub` file holds a different key than the private key.
    pub pair_mismatch: bool,
    /// Permissions of the private key file (or of the public file for
    /// public-only keys).
    pub permissions: PermissionReport,
}

/// Why a file in the scanned directory is not listed as a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum SkipReason {
    /// `PuTTY` `.ppk` key (convert with `puttygen`).
    Putty,
    /// An OpenSSH certificate (`*-cert.pub`).
    Certificate,
    /// Larger than [`MAX_KEY_FILE_SIZE`].
    TooLarge,
    /// Could not be read.
    Unreadable,
    /// Looks like a key but cannot be parsed (truncated, corrupt).
    Malformed,
    /// A key format that is not supported (e.g. RFC 4716 / ssh.com).
    UnsupportedFormat,
    /// Not a key.
    NotAKey,
    /// The file name is not valid UTF-8.
    NonUtf8Name,
}

/// A file that was looked at but not listed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct SkippedFile {
    /// Absolute path.
    pub path: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// Result of [`scan`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct ScanResult {
    /// Keys, sorted by name.
    pub keys: Vec<KeyInfo>,
    /// Files that were not recognised, sorted by path. Well-known non-key files
    /// (`config`, `known_hosts*`, `authorized_keys*`, backups, hidden files,
    /// directories, sockets) are ignored silently.
    pub skipped: Vec<SkippedFile>,
}

/// Lists the keys in `dir` (top level only). A missing directory gives an
/// empty result.
pub fn scan(dir: &Path) -> Result<ScanResult> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ScanResult::default()),
        Err(e) => return Err(Error::io(e, dir)),
    };
    let mut privates: BTreeMap<String, Found<PrivateContent>> = BTreeMap::new();
    let mut publics: BTreeMap<String, Found<PublicKey>> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut skip = |path: &Path, reason| {
        skipped.push(SkippedFile {
            path: path_string(path),
            reason,
        });
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            skip(&path, SkipReason::NonUtf8Name);
            continue;
        };
        if is_ignored_name(&name) {
            continue;
        }
        let Ok(meta) = fs::metadata(&path) else {
            skip(&path, SkipReason::Unreadable);
            continue;
        };
        if !meta.is_file() {
            continue;
        }
        if Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ppk"))
        {
            skip(&path, SkipReason::Putty);
            continue;
        }
        if meta.len() > MAX_KEY_FILE_SIZE {
            skip(&path, SkipReason::TooLarge);
            continue;
        }
        let Ok(bytes) = fsutil::read_limited(&path, MAX_KEY_FILE_SIZE).map(Zeroizing::new) else {
            skip(&path, SkipReason::Unreadable);
            continue;
        };
        let modified = meta.modified().ok();
        match classify(&bytes) {
            Content::Private(content) => {
                privates.insert(
                    name,
                    Found {
                        path,
                        content,
                        modified,
                    },
                );
            }
            Content::Public(content) => {
                publics.insert(
                    name,
                    Found {
                        path,
                        content,
                        modified,
                    },
                );
            }
            Content::Skip(reason) => skip(&path, reason),
        }
    }

    let mut keys = Vec::with_capacity(privates.len() + publics.len());
    for (name, private) in &privates {
        let public = publics.remove(&format!("{name}.pub"));
        keys.push(build_info(name, Some(private), public.as_ref()));
    }
    for (name, public) in &publics {
        let base = name.strip_suffix(".pub").unwrap_or(name);
        keys.push(build_info(base, None, Some(public)));
    }
    attach_permissions(&mut keys);
    keys.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
    skipped.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(ScanResult { keys, skipped })
}

/// Describes one key file anywhere on disk (e.g. an `IdentityFile` outside
/// `~/.ssh`). `path` may be the private key or the `.pub`; the other half of
/// the pair is picked up when it exists next to it.
pub fn inspect(path: &Path) -> Result<KeyInfo> {
    let found = read_found(path)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut info = match found.content {
        Content::Private(content) => {
            let private = Found {
                path: found.path,
                content,
                modified: found.modified,
            };
            let public = read_found(&sibling_pub(path))
                .ok()
                .and_then(Found::into_public);
            build_info(&file_name, Some(&private), public.as_ref())
        }
        Content::Public(content) => {
            let public = Found {
                path: found.path,
                content,
                modified: found.modified,
            };
            let base = file_name.strip_suffix(".pub");
            let private = base
                .map(|b| path.with_file_name(b))
                .and_then(|p| read_found(&p).ok())
                .and_then(Found::into_private);
            build_info(base.unwrap_or(&file_name), private.as_ref(), Some(&public))
        }
        Content::Skip(reason) => return Err(skip_error(reason, path)),
    };
    attach_permissions(std::slice::from_mut(&mut info));
    Ok(info)
}

// ---------------------------------------------------------------------------
// Classification

/// What a file contains.
pub(crate) enum Content {
    Private(PrivateContent),
    Public(PublicKey),
    Skip(SkipReason),
}

/// What could be learned from a private key file without a passphrase.
pub(crate) struct PrivateContent {
    pub(crate) format: KeyFormat,
    pub(crate) encrypted: bool,
    pub(crate) algorithm_hint: Option<KeyAlgorithm>,
    /// Public half, with the private key's comment when it is readable.
    pub(crate) public: Option<PublicKey>,
}

/// A classified file.
pub(crate) struct Found<T> {
    pub(crate) path: PathBuf,
    pub(crate) content: T,
    pub(crate) modified: Option<SystemTime>,
}

impl Found<Content> {
    fn into_public(self) -> Option<Found<PublicKey>> {
        match self.content {
            Content::Public(content) => Some(Found {
                path: self.path,
                content,
                modified: self.modified,
            }),
            _ => None,
        }
    }

    fn into_private(self) -> Option<Found<PrivateContent>> {
        match self.content {
            Content::Private(content) => Some(Found {
                path: self.path,
                content,
                modified: self.modified,
            }),
            _ => None,
        }
    }
}

/// Classifies file contents. Total: any input gives a result.
pub(crate) fn classify(bytes: &[u8]) -> Content {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Content::Skip(SkipReason::NotAKey);
    };
    let text = text.trim_start_matches('\u{feff}').trim();
    if text.starts_with("PuTTY-User-Key-File-") {
        return Content::Skip(SkipReason::Putty);
    }
    if text.starts_with("---- BEGIN SSH2") {
        return Content::Skip(SkipReason::UnsupportedFormat);
    }
    if let Some(kind) = legacy::pem_kind(text) {
        return classify_private(text, kind);
    }
    if text.starts_with("-----BEGIN ") {
        return Content::Skip(SkipReason::NotAKey);
    }
    let Some(line) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
    else {
        return Content::Skip(SkipReason::NotAKey);
    };
    let key_type = line.split_ascii_whitespace().next().unwrap_or_default();
    if key_type.ends_with("-cert-v01@openssh.com") {
        return Content::Skip(SkipReason::Certificate);
    }
    match PublicKey::from_openssh(line) {
        Ok(key) => Content::Public(key),
        Err(_) if looks_like_key_type(key_type) => Content::Skip(SkipReason::Malformed),
        Err(_) => Content::Skip(SkipReason::NotAKey),
    }
}

fn classify_private(text: &str, kind: legacy::PemKind) -> Content {
    if kind == legacy::PemKind::OpenSsh {
        return match PrivateKey::from_openssh(text) {
            Ok(key) => Content::Private(PrivateContent {
                format: KeyFormat::Openssh,
                encrypted: key.is_encrypted(),
                algorithm_hint: Some(KeyAlgorithm::from_ssh(&key.algorithm())),
                public: Some(key.public_key().clone()),
            }),
            Err(_) => Content::Skip(SkipReason::Malformed),
        };
    }
    match legacy::parse(text, kind) {
        Some(key) => Content::Private(PrivateContent {
            format: key.format,
            encrypted: key.encrypted,
            algorithm_hint: key.algorithm,
            public: key
                .keypair
                .as_ref()
                .and_then(|kp| KeyData::try_from(kp).ok())
                .map(|kd| PublicKey::new(kd, "")),
        }),
        None => Content::Skip(SkipReason::Malformed),
    }
}

fn looks_like_key_type(word: &str) -> bool {
    ["ssh-", "ecdsa-", "sk-"]
        .iter()
        .any(|prefix| word.starts_with(prefix))
}

/// Names that are never keys and are skipped without being reported.
fn is_ignored_name(name: &str) -> bool {
    const EXACT: &[&str] = &["config", "environment", "rc", "allowed_signers"];
    const PREFIXES: &[&str] = &["known_hosts", "authorized_keys"];
    const SUFFIXES: &[&str] = &[
        "~",
        ".bak",
        ".old",
        ".orig",
        ".backup",
        ".swp",
        ".tmp",
        ".sock",
        ".sshkm-tmp",
    ];
    name.starts_with('.')
        || EXACT.contains(&name)
        || PREFIXES.iter().any(|p| name.starts_with(p))
        || SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Reads and classifies one file for [`inspect`] and the key operations.
pub(crate) fn read_found(path: &Path) -> Result<Found<Content>> {
    let meta = fs::metadata(path).map_err(|e| Error::io(e, path))?;
    if !meta.is_file() {
        return Err(Error::invalid(format!("not a file: {}", path.display())));
    }
    let bytes = Zeroizing::new(fsutil::read_limited(path, MAX_KEY_FILE_SIZE)?);
    Ok(Found {
        path: path.to_path_buf(),
        content: classify(&bytes),
        modified: meta.modified().ok(),
    })
}

pub(crate) fn skip_error(reason: SkipReason, path: &Path) -> Error {
    let p = path.display();
    match reason {
        SkipReason::Putty => {
            Error::Unsupported(format!("PuTTY key, convert it with puttygen: {p}"))
        }
        SkipReason::Certificate => Error::Unsupported(format!("certificate, not a key: {p}")),
        SkipReason::UnsupportedFormat => Error::Unsupported(format!("unsupported key format: {p}")),
        SkipReason::TooLarge => Error::invalid(format!("file too large to be a key: {p}")),
        SkipReason::Malformed => Error::Parse(format!("malformed key: {p}")),
        SkipReason::NotAKey | SkipReason::Unreadable | SkipReason::NonUtf8Name => {
            Error::Parse(format!("not an SSH key: {p}"))
        }
    }
}

/// `<path>.pub`
pub(crate) fn sibling_pub(path: &Path) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

// ---------------------------------------------------------------------------
// KeyInfo assembly

fn build_info(
    name: &str,
    private: Option<&Found<PrivateContent>>,
    public: Option<&Found<PublicKey>>,
) -> KeyInfo {
    let derived = private.and_then(|p| p.content.public.as_ref());
    let file_pub = public.map(|p| &p.content);
    let pair_mismatch =
        matches!((derived, file_pub), (Some(a), Some(b)) if a.key_data() != b.key_data());
    let comment = file_pub
        .map(PublicKey::comment)
        .filter(|c| !c.is_empty())
        .or_else(|| derived.map(PublicKey::comment))
        .unwrap_or_default()
        .to_owned();

    let (algorithm, key_type, bits, fingerprint, public_key) =
        if let Some(pk) = derived.or(file_pub) {
            let kd = pk.key_data();
            let algorithm = kd.algorithm();
            (
                KeyAlgorithm::from_ssh(&algorithm),
                algorithm.to_string(),
                key_bits(kd),
                Some(fingerprint(kd)),
                PublicKey::new(kd.clone(), comment.clone())
                    .to_openssh()
                    .ok(),
            )
        } else {
            let alg = private
                .and_then(|p| p.content.algorithm_hint)
                .unwrap_or(KeyAlgorithm::Other);
            (alg, alg.key_type().to_owned(), None, None, None)
        };

    let primary_path = private.map_or_else(|| public.map(|p| &p.path), |p| Some(&p.path));
    let primary_file = primary_path
        .and_then(|p| p.file_name())
        .map_or_else(|| name.to_owned(), |n| n.to_string_lossy().into_owned());
    let id = format!(
        "{}#{primary_file}",
        fingerprint.as_deref().unwrap_or("unknown")
    );

    KeyInfo {
        id,
        name: name.to_owned(),
        private_path: private.map(|p| path_string(&p.path)),
        public_path: public.map(|p| path_string(&p.path)),
        algorithm,
        key_type,
        bits,
        fingerprint,
        comment,
        encrypted: private.map(|p| p.content.encrypted),
        hardware: algorithm.is_hardware(),
        format: private.map_or(KeyFormat::PublicOnly, |p| p.content.format),
        public_key,
        modified: private
            .and_then(|p| p.modified)
            .or_else(|| public.and_then(|p| p.modified))
            .and_then(rfc3339),
        pair_mismatch,
        permissions: PermissionReport {
            ok: false,
            mode: None,
            problem: Some(PermissionProblem::CheckFailed),
        },
    }
}

/// Fills in [`KeyInfo::permissions`] with one batched check.
fn attach_permissions(keys: &mut [KeyInfo]) {
    let items: Vec<(PathBuf, PermKind)> = keys
        .iter()
        .map(|k| match (&k.private_path, &k.public_path) {
            (Some(p), _) => (PathBuf::from(p), PermKind::PrivateKey),
            (None, Some(p)) => (PathBuf::from(p), PermKind::PublicKey),
            (None, None) => (PathBuf::new(), PermKind::PublicKey),
        })
        .collect();
    for (key, report) in keys.iter_mut().zip(perms::check_many(&items)) {
        key.permissions = report;
    }
}

/// `SHA256:…` fingerprint of public key data.
pub(crate) fn fingerprint(kd: &KeyData) -> String {
    kd.fingerprint(HashAlg::Sha256).to_string()
}

/// Key size in bits as `ssh-keygen -l` reports it.
pub(crate) fn key_bits(kd: &KeyData) -> Option<u32> {
    match kd {
        KeyData::Rsa(k) => mpint_bits(&k.n),
        KeyData::Dsa(k) => mpint_bits(&k.p),
        KeyData::Ecdsa(k) => Some(match k.curve() {
            SshCurve::NistP256 => 256,
            SshCurve::NistP384 => 384,
            SshCurve::NistP521 => 521,
        }),
        KeyData::Ed25519(_) | KeyData::SkEd25519(_) | KeyData::SkEcdsaSha2NistP256(_) => Some(256),
        _ => None,
    }
}

fn mpint_bits(m: &Mpint) -> Option<u32> {
    let bytes = m.as_positive_bytes()?;
    let first = bytes.iter().position(|b| *b != 0)?;
    let len = u32::try_from(bytes.len() - first).ok()?;
    Some((len - 1) * 8 + (8 - bytes[first].leading_zeros()))
}

fn rfc3339(t: SystemTime) -> Option<String> {
    OffsetDateTime::from(t)
        .replace_nanosecond(0)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use testdata as td;

    fn write(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let is_pub = Path::new(name).extension().is_some_and(|e| e == "pub");
            let mode = if is_pub { 0o644 } else { 0o600 };
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        }
        path
    }

    fn by_name<'a>(scan: &'a ScanResult, name: &str) -> &'a KeyInfo {
        scan.keys.iter().find(|k| k.name == name).unwrap()
    }

    #[test]
    fn classify_is_total() {
        for input in [
            &b""[..],
            b"\xff\xfe\x00",
            b"-----BEGIN OPENSSH PRIVATE KEY-----\ngarbage\n-----END OPENSSH PRIVATE KEY-----\n",
            b"-----BEGIN OPENSSH PRIVATE KEY-----",
            b"ssh-ed25519",
            b"ssh-ed25519 AAAA",
            b"ssh-ed25519 !!!! comment",
            b"\n\n# just a comment\n",
            b"Host *\n  User me\n",
        ] {
            let _ = classify(input);
        }
        assert!(matches!(
            classify(b"ssh-ed25519 !!!! c"),
            Content::Skip(SkipReason::Malformed)
        ));
        assert!(matches!(
            classify(b"Host x"),
            Content::Skip(SkipReason::NotAKey)
        ));
        // Files saved with Windows line endings or a BOM are still keys.
        let crlf = td::OPENSSH_ED25519.replace('\n', "\r\n");
        assert!(matches!(classify(crlf.as_bytes()), Content::Private(_)));
        let crlf_pub = format!("\u{feff}{}", td::OPENSSH_ED25519_PUB.replace('\n', "\r\n"));
        assert!(matches!(classify(crlf_pub.as_bytes()), Content::Public(_)));
        let pem_crlf = td::RSA_PEM.replace('\n', "\r\n");
        assert!(matches!(classify(pem_crlf.as_bytes()), Content::Private(_)));
    }

    #[test]
    fn scan_pairs_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        write(d, "id_ed25519", td::OPENSSH_ED25519);
        write(d, "id_ed25519.pub", td::OPENSSH_ED25519_PUB);
        write(d, "work", td::OPENSSH_ED25519_ENCRYPTED);
        write(d, "legacy_rsa", td::RSA_PEM);
        write(d, "legacy_rsa.pub", td::RSA_PEM_PUB);
        write(d, "old_enc", td::RSA_PEM_ENCRYPTED);
        write(d, "orphan.pub", td::OPENSSH_ED25519_ENCRYPTED_PUB);
        write(d, "putty.ppk", "PuTTY-User-Key-File-3: ssh-ed25519\n");
        write(
            d,
            "id_ed25519-cert.pub",
            "ssh-ed25519-cert-v01@openssh.com AAAA x\n",
        );
        write(d, "broken", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n");
        write(d, "notes.txt", "hello");
        write(d, "config", "Host *\n");
        write(d, "known_hosts", "x");
        write(d, "known_hosts.old", "x");
        write(d, "authorized_keys", td::OPENSSH_ED25519_PUB);
        write(d, "id_ed25519.bak", td::OPENSSH_ED25519);
        write(d, ".DS_Store", "x");
        fs::write(d.join("huge"), vec![b'a'; 70 * 1024]).unwrap();
        fs::create_dir(d.join("config.d")).unwrap();

        let scan = scan(d).unwrap();
        let names: Vec<_> = scan.keys.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(
            names,
            ["id_ed25519", "legacy_rsa", "old_enc", "orphan", "work"]
        );

        let plain = by_name(&scan, "id_ed25519");
        assert_eq!(plain.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(plain.format, KeyFormat::Openssh);
        assert_eq!(plain.encrypted, Some(false));
        assert_eq!(plain.comment, "plain@test");
        assert_eq!(plain.bits, Some(256));
        assert!(!plain.pair_mismatch);
        assert!(plain.public_path.is_some());
        assert!(plain.fingerprint.as_deref().unwrap().starts_with("SHA256:"));
        assert_eq!(
            plain.public_key.as_deref(),
            Some(td::OPENSSH_ED25519_PUB.trim())
        );
        assert!(plain.id.ends_with("#id_ed25519"));
        assert!(plain.modified.as_deref().unwrap().ends_with('Z'));

        // Encrypted, no .pub: fingerprint from the unencrypted public section.
        let work = by_name(&scan, "work");
        assert_eq!(work.encrypted, Some(true));
        assert!(work.public_path.is_none());
        let orphan = by_name(&scan, "orphan");
        assert_eq!(orphan.format, KeyFormat::PublicOnly);
        assert_eq!(orphan.encrypted, None);
        assert_eq!(work.fingerprint, orphan.fingerprint);
        assert_ne!(work.id, orphan.id);

        let legacy = by_name(&scan, "legacy_rsa");
        assert_eq!(legacy.format, KeyFormat::Pem);
        assert_eq!(legacy.bits, Some(2048));
        assert_eq!(legacy.comment, "legacy@test");
        assert!(!legacy.pair_mismatch);

        let old = by_name(&scan, "old_enc");
        assert_eq!(old.encrypted, Some(true));
        assert_eq!(old.algorithm, KeyAlgorithm::Rsa);
        assert_eq!(old.fingerprint, None);
        assert!(old.id.starts_with("unknown#"));

        let reasons: Vec<_> = scan
            .skipped
            .iter()
            .map(|s| {
                (
                    Path::new(&s.path).file_name().unwrap().to_str().unwrap(),
                    s.reason,
                )
            })
            .collect();
        assert_eq!(
            reasons,
            [
                ("broken", SkipReason::Malformed),
                ("huge", SkipReason::TooLarge),
                ("id_ed25519-cert.pub", SkipReason::Certificate),
                ("notes.txt", SkipReason::NotAKey),
                ("putty.ppk", SkipReason::Putty),
            ]
        );
    }

    #[test]
    fn scan_flags_pair_mismatch_and_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let private = write(d, "id", td::OPENSSH_ED25519);
        write(d, "id.pub", td::OPENSSH_ED25519_ENCRYPTED_PUB);
        let scan = scan(d).unwrap();
        let key = by_name(&scan, "id");
        assert!(key.pair_mismatch);
        // The private key's own public key wins.
        assert_eq!(
            key.public_key.as_deref(),
            Some(
                format!(
                    "{} keygen@test",
                    td::OPENSSH_ED25519_PUB
                        .split_whitespace()
                        .take(2)
                        .collect::<Vec<_>>()
                        .join(" ")
                )
                .as_str()
            )
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(key.permissions.ok);
            fs::set_permissions(&private, fs::Permissions::from_mode(0o644)).unwrap();
            let key = inspect(&private).unwrap();
            assert!(!key.permissions.ok);
            assert_eq!(key.permissions.mode.as_deref(), Some("644"));
        }
        #[cfg(not(unix))]
        let _ = private;
    }

    #[test]
    fn missing_dir_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let scan = scan(&dir.path().join("nope")).unwrap();
        assert_eq!(scan, ScanResult::default());
    }

    #[test]
    fn inspect_private_public_and_errors() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        let private = write(d, "k", td::OPENSSH_ED25519);
        let public = write(d, "k.pub", td::OPENSSH_ED25519_PUB);
        let a = inspect(&private).unwrap();
        let b = inspect(&public).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.name, "k");

        let pem = write(d, "ec", td::EC_PEM_EXPLICIT);
        let info = inspect(&pem).unwrap();
        assert_eq!(info.algorithm, KeyAlgorithm::EcdsaP256);
        assert_eq!(info.format, KeyFormat::Pem);
        let expected = PublicKey::from_openssh(td::EC_PEM_EXPLICIT_PUB.trim()).unwrap();
        assert_eq!(info.fingerprint, Some(fingerprint(expected.key_data())));

        let ppk = write(d, "p.ppk", "PuTTY-User-Key-File-2: ssh-rsa\n");
        assert_eq!(
            inspect(&ppk).unwrap_err().code(),
            crate::ErrorCode::Unsupported
        );
        let txt = write(d, "t", "hello");
        assert_eq!(inspect(&txt).unwrap_err().code(), crate::ErrorCode::Parse);
        assert_eq!(
            inspect(&d.join("missing")).unwrap_err().code(),
            crate::ErrorCode::NotFound
        );
    }

    #[test]
    fn key_info_serializes_camel_case() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "k", td::OPENSSH_ED25519);
        let v = serde_json::to_value(inspect(&p).unwrap()).unwrap();
        assert_eq!(v["algorithm"], "ed25519");
        assert_eq!(v["format"], "openssh");
        assert!(v["privatePath"].is_string());
        assert!(v["publicPath"].is_null());
        assert_eq!(v["pairMismatch"], false);
        assert!(v.get("publicKey").is_some());
        assert_eq!(
            serde_json::to_value(KeyAlgorithm::EcdsaP256).unwrap(),
            "ecdsaP256"
        );
        assert_eq!(
            serde_json::to_value(KeyAlgorithm::SkEd25519).unwrap(),
            "skEd25519"
        );
        assert_eq!(
            serde_json::to_value(KeyFormat::PublicOnly).unwrap(),
            "publicOnly"
        );
    }

    #[test]
    fn mpint_bit_lengths() {
        let m = Mpint::from_positive_bytes(&[0x01, 0x00]).unwrap();
        assert_eq!(mpint_bits(&m), Some(9));
        let m = Mpint::from_positive_bytes(&[0xff; 256]).unwrap();
        assert_eq!(mpint_bits(&m), Some(2048));
    }
}
