//! Operations that create or modify key files.

use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use rand_core::OsRng;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use ssh_key::{
    EcdsaCurve as SshCurve, HashAlg, LineEnding, PrivateKey, PublicKey,
    private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair},
    public::KeyData,
};
use zeroize::Zeroizing;

use super::{
    Content, KeyAlgorithm, KeyInfo, MAX_KEY_FILE_SIZE, classify, inspect,
    legacy::{self, LegacyKey, PemKind},
    sibling_pub, skip_error,
};
use crate::{Error, Result, fsutil};

/// Longest accepted key file name.
const MAX_FILE_NAME: usize = 200;
/// Longest accepted key comment.
const MAX_COMMENT: usize = 1024;

/// ECDSA curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum EcdsaCurve {
    /// NIST P-256
    P256,
    /// NIST P-384
    P384,
    /// NIST P-521
    P521,
}

impl From<EcdsaCurve> for SshCurve {
    fn from(c: EcdsaCurve) -> Self {
        match c {
            EcdsaCurve::P256 => Self::NistP256,
            EcdsaCurve::P384 => Self::NistP384,
            EcdsaCurve::P521 => Self::NistP521,
        }
    }
}

/// Algorithm of a key to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum GenerateAlgorithm {
    /// Ed25519 (recommended).
    Ed25519,
    /// RSA with 3072 or 4096 bits.
    Rsa {
        /// 3072 or 4096.
        bits: u32,
    },
    /// ECDSA on a NIST curve.
    Ecdsa {
        /// The curve.
        curve: EcdsaCurve,
    },
}

/// Parameters of [`generate`].
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct GenerateRequest {
    /// Algorithm and size.
    pub algorithm: GenerateAlgorithm,
    /// File name of the private key (`[A-Za-z0-9._-]+`, no leading dot); the
    /// public key is written to `<fileName>.pub`.
    pub file_name: String,
    /// Key comment, conventionally `user@host` or an e-mail address.
    #[serde(default)]
    pub comment: String,
    /// Passphrase; `None` or empty for an unencrypted key. Never serialised.
    #[serde(default, skip_serializing)]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub passphrase: Option<SecretString>,
}

/// A decrypted private key, ready to be added to the agent.
///
/// Holds key material: it is zeroized on drop, cannot be serialised, and its
/// `Debug` output shows only the fingerprint.
pub struct UnlockedKey {
    key: PrivateKey,
}

impl UnlockedKey {
    /// `SHA256:…` fingerprint.
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint(HashAlg::Sha256).to_string()
    }

    /// One-line OpenSSH public key with comment.
    pub fn public_key(&self) -> String {
        self.key.public_key().to_openssh().unwrap_or_default()
    }

    /// The comment stored in the key (may be empty).
    pub fn comment(&self) -> &str {
        self.key.comment()
    }

    /// Algorithm.
    pub fn algorithm(&self) -> KeyAlgorithm {
        KeyAlgorithm::from_ssh(&self.key.algorithm())
    }

    pub(crate) fn keypair(&self) -> &KeypairData {
        self.key.key_data()
    }

    #[cfg(test)]
    pub(crate) fn public_key_data(&self) -> &KeyData {
        self.key.public_key().key_data()
    }
}

impl fmt::Debug for UnlockedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockedKey")
            .field("fingerprint", &self.fingerprint())
            .finish_non_exhaustive()
    }
}

/// Checks a key file name: `[A-Za-z0-9._-]+`, no leading dot, not ending in
/// `.pub`, not a reserved OpenSSH or Windows device name.
pub fn validate_file_name(name: &str) -> Result<()> {
    const RESERVED: &[&str] = &[
        "config",
        "known_hosts",
        "known_hosts2",
        "authorized_keys",
        "authorized_keys2",
        "environment",
        "rc",
        "allowed_signers",
    ];
    const WINDOWS_DEVICES: &[&str] = &[
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    let valid_chars = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.is_empty()
        || name.len() > MAX_FILE_NAME
        || !valid_chars
        || name.starts_with('.')
        || name.ends_with('.')
        || Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"))
        || RESERVED.contains(&name)
        || WINDOWS_DEVICES.contains(&stem.as_str())
    {
        return Err(Error::invalid(format!("invalid key file name: {name:?}")));
    }
    Ok(())
}

fn validate_comment(comment: &str) -> Result<()> {
    if comment.len() > MAX_COMMENT || comment.chars().any(char::is_control) {
        return Err(Error::invalid("comment must be one line of text"));
    }
    Ok(())
}

fn non_empty(secret: Option<&SecretString>) -> Option<&str> {
    secret
        .map(ExposeSecret::expose_secret)
        .filter(|s| !s.is_empty())
}

fn key_error(context: &str, err: &ssh_key::Error) -> Error {
    Error::Io {
        context: context.to_owned(),
        source: io::Error::other(err.to_string()),
    }
}

/// Generates a key pair in `dir` (created with mode 0700 if missing).
///
/// The private key is written in OpenSSH format — encrypted with
/// bcrypt-pbkdf (16 rounds) and aes256-ctr, exactly like `ssh-keygen`, when a
/// passphrase is given — with mode 0600, the public key with 0644. Existing
/// files are never overwritten ([`Error::AlreadyExists`]).
pub fn generate(dir: &Path, request: &GenerateRequest) -> Result<KeyInfo> {
    validate_file_name(&request.file_name)?;
    validate_comment(&request.comment)?;
    let private_path = dir.join(&request.file_name);
    let public_path = sibling_pub(&private_path);
    for p in [&private_path, &public_path] {
        if fs::symlink_metadata(p).is_ok() {
            return Err(Error::AlreadyExists(p.display().to_string()));
        }
    }

    let mut rng = OsRng;
    let keypair = match request.algorithm {
        GenerateAlgorithm::Ed25519 => KeypairData::Ed25519(Ed25519Keypair::random(&mut rng)),
        GenerateAlgorithm::Rsa { bits } => {
            if !matches!(bits, 3072 | 4096) {
                return Err(Error::invalid(format!(
                    "RSA key size must be 3072 or 4096, not {bits}"
                )));
            }
            let bits = usize::try_from(bits).unwrap_or(4096);
            KeypairData::Rsa(
                RsaKeypair::random(&mut rng, bits)
                    .map_err(|e| key_error("generating RSA key", &e))?,
            )
        }
        GenerateAlgorithm::Ecdsa { curve } => KeypairData::Ecdsa(
            EcdsaKeypair::random(&mut rng, curve.into())
                .map_err(|e| key_error("generating ECDSA key", &e))?,
        ),
    };
    let key = PrivateKey::new(keypair, request.comment.clone())
        .map_err(|e| key_error("building key", &e))?;
    // Taken before encryption: the encrypted form keeps the comment only in
    // its encrypted section.
    let public_line = public_line(key.public_key())?;
    let key = match non_empty(request.passphrase.as_ref()) {
        Some(pass) => key
            .encrypt(&mut rng, pass.as_bytes())
            .map_err(|e| key_error("encrypting key", &e))?,
        None => key,
    };
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| key_error("encoding key", &e))?;

    fsutil::ensure_private_dir(dir)?;
    fsutil::write_new(&private_path, pem.as_bytes(), 0o600)?;
    if let Err(e) = fsutil::write_new(&public_path, public_line.as_bytes(), 0o644) {
        let _ = fs::remove_file(&private_path);
        return Err(e);
    }
    restrict_private_key(&private_path);
    inspect(&private_path)
}

/// Changes, adds (`old = None` for an unencrypted key) or removes
/// (`new = None` or empty) the passphrase of an OpenSSH private key.
///
/// The file is rewritten atomically and keeps its permissions. Legacy PEM and
/// PKCS#8 keys are [`Error::Unsupported`] (`ssh-keygen -p` converts them).
pub fn change_passphrase(
    private_path: &Path,
    old: Option<&SecretString>,
    new: Option<&SecretString>,
) -> Result<KeyInfo> {
    let text = read_private_text(private_path)?;
    let key = match open_private(&text, private_path)? {
        Opened::OpenSsh(key) => *key,
        Opened::Legacy(_) => {
            return Err(Error::Unsupported(
                "legacy PEM/PKCS#8 key; convert it with `ssh-keygen -p` first".into(),
            ));
        }
    };
    let key = unlock(key, old)?;
    let key = match non_empty(new) {
        Some(pass) => key
            .encrypt(&mut OsRng, pass.as_bytes())
            .map_err(|e| key_error("encrypting key", &e))?,
        None => key,
    };
    let pem = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| key_error("encoding key", &e))?;
    fsutil::atomic_write(private_path, pem.as_bytes(), 0o600)?;
    restrict_private_key(private_path);
    inspect(private_path)
}

/// Loads and decrypts a private key, e.g. to add it to the agent.
///
/// OpenSSH keys (encrypted or not) and unencrypted legacy RSA/ECDSA/Ed25519
/// PEM/PKCS#8 keys are supported; encrypted legacy keys are
/// [`Error::Unsupported`].
pub fn load_private(private_path: &Path, passphrase: Option<&SecretString>) -> Result<UnlockedKey> {
    let text = read_private_text(private_path)?;
    let key = match open_private(&text, private_path)? {
        Opened::OpenSsh(key) => unlock(*key, passphrase)?,
        Opened::Legacy(legacy) if legacy.encrypted => {
            return Err(Error::Unsupported(
                "encrypted legacy PEM/PKCS#8 key; convert it with `ssh-keygen -p` first".into(),
            ));
        }
        Opened::Legacy(legacy) => {
            let keypair = legacy.keypair.ok_or_else(|| {
                Error::Unsupported("this legacy key type cannot be loaded".into())
            })?;
            let comment = public_comment(&sibling_pub(private_path)).unwrap_or_default();
            PrivateKey::new(keypair, comment).map_err(|e| key_error("building key", &e))?
        }
    };
    Ok(UnlockedKey { key })
}

/// Writes the missing `<private>.pub` from the private key. No passphrase is
/// needed for OpenSSH keys (their public half is stored unencrypted); the
/// comment is copied when the key is unencrypted.
pub fn regenerate_public(private_path: &Path) -> Result<KeyInfo> {
    let public_path = sibling_pub(private_path);
    if fs::symlink_metadata(&public_path).is_ok() {
        return Err(Error::AlreadyExists(public_path.display().to_string()));
    }
    let text = read_private_text(private_path)?;
    let public = derived_public(&open_private(&text, private_path)?).ok_or_else(|| {
        Error::Unsupported(
            "the public key of an encrypted legacy key cannot be derived without decrypting it"
                .into(),
        )
    })?;
    fsutil::write_new(&public_path, public_line(&public)?.as_bytes(), 0o644)?;
    inspect(private_path)
}

/// Copies an existing private key (and its `.pub`, or a public key derived
/// from it) into `dir` under `file_name` (default: the source's name), with
/// modes 0600 / 0644. The key bytes are copied unchanged. Existing files are
/// never overwritten.
pub fn import(dir: &Path, source: &Path, file_name: Option<&str>) -> Result<KeyInfo> {
    let text = read_private_text(source)?;
    let opened = open_private(&text, source)?;
    let name = match file_name {
        Some(name) => name.to_owned(),
        None => source
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| Error::invalid("source has no usable file name"))?
            .to_owned(),
    };
    validate_file_name(&name)?;
    let dest = dir.join(&name);
    let dest_pub = sibling_pub(&dest);
    for p in [&dest, &dest_pub] {
        if fs::symlink_metadata(p).is_ok() {
            return Err(Error::AlreadyExists(p.display().to_string()));
        }
    }

    let source_pub = sibling_pub(source);
    let public_text = match fsutil::read_limited(&source_pub, MAX_KEY_FILE_SIZE) {
        Ok(bytes) if matches!(classify(&bytes), Content::Public(_)) => {
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => derived_public(&opened).and_then(|p| public_line(&p).ok()),
    };

    fsutil::ensure_private_dir(dir)?;
    fsutil::write_new(&dest, text.as_bytes(), 0o600)?;
    if let Some(public_text) = public_text
        && let Err(e) = fsutil::write_new(&dest_pub, public_text.as_bytes(), 0o644)
    {
        let _ = fs::remove_file(&dest);
        return Err(e);
    }
    restrict_private_key(&dest);
    inspect(&dest)
}

/// Moves files to the system trash / recycle bin, so deletion can be undone.
/// All paths must exist. On macOS the files go to the Trash via
/// `NSFileManager`, which needs no Finder automation permission.
pub fn move_to_trash(paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    for p in paths {
        fs::symlink_metadata(p).map_err(|e| Error::io(e, p))?;
    }
    #[cfg_attr(not(target_os = "macos"), allow(unused_mut))]
    let mut ctx = trash::TrashContext::default();
    #[cfg(target_os = "macos")]
    {
        use trash::macos::{DeleteMethod, TrashContextExtMacos};
        ctx.set_delete_method(DeleteMethod::NsFileManager);
    }
    ctx.delete_all(paths).map_err(|e| Error::Io {
        context: "moving files to the trash".into(),
        source: io::Error::other(e.to_string()),
    })
}

// ---------------------------------------------------------------------------

enum Opened {
    OpenSsh(Box<PrivateKey>),
    Legacy(LegacyKey),
}

/// Reads a key file into memory that is zeroized afterwards.
fn read_private_text(path: &Path) -> Result<Zeroizing<String>> {
    let meta = fs::metadata(path).map_err(|e| Error::io(e, path))?;
    if !meta.is_file() {
        return Err(Error::invalid(format!("not a file: {}", path.display())));
    }
    let mut bytes = Zeroizing::new(fsutil::read_limited(path, MAX_KEY_FILE_SIZE)?);
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(s) => Ok(Zeroizing::new(s)),
        Err(e) => {
            drop(Zeroizing::new(e.into_bytes()));
            Err(Error::Parse(format!("not an SSH key: {}", path.display())))
        }
    }
}

fn open_private(text: &str, path: &Path) -> Result<Opened> {
    let trimmed = text.trim_start_matches('\u{feff}').trim();
    match legacy::pem_kind(trimmed) {
        Some(PemKind::OpenSsh) => PrivateKey::from_openssh(trimmed)
            .map(|key| Opened::OpenSsh(Box::new(key)))
            .map_err(|_| Error::Parse(format!("malformed key: {}", path.display()))),
        Some(kind) => legacy::parse(trimmed, kind)
            .map(Opened::Legacy)
            .ok_or_else(|| Error::Parse(format!("malformed key: {}", path.display()))),
        None => Err(match classify(text.as_bytes()) {
            Content::Public(_) => Error::invalid(format!(
                "{} is a public key; select the private key",
                path.display()
            )),
            Content::Skip(reason) => skip_error(reason, path),
            Content::Private(_) => Error::Parse(format!("not an SSH key: {}", path.display())),
        }),
    }
}

fn unlock(key: PrivateKey, passphrase: Option<&SecretString>) -> Result<PrivateKey> {
    if !key.is_encrypted() {
        return Ok(key);
    }
    let pass = non_empty(passphrase).ok_or(Error::PassphraseRequired)?;
    // A wrong passphrase shows up as a check-int mismatch or, rarely, as
    // garbage that fails to decode; both mean "wrong passphrase".
    key.decrypt(pass.as_bytes())
        .map_err(|_| Error::WrongPassphrase)
}

fn derived_public(opened: &Opened) -> Option<PublicKey> {
    match opened {
        Opened::OpenSsh(key) => Some(key.public_key().clone()),
        Opened::Legacy(legacy) => legacy
            .keypair
            .as_ref()
            .and_then(|kp| KeyData::try_from(kp).ok())
            .map(|kd| PublicKey::new(kd, "")),
    }
}

fn public_line(public: &PublicKey) -> Result<String> {
    let mut line = public
        .to_openssh()
        .map_err(|e| key_error("encoding public key", &e))?;
    line.push('\n');
    Ok(line)
}

fn public_comment(path: &Path) -> Option<String> {
    let bytes = fsutil::read_limited(path, MAX_KEY_FILE_SIZE).ok()?;
    match classify(&bytes) {
        Content::Public(key) => Some(key.comment().to_owned()),
        _ => None,
    }
}

/// OpenSSH for Windows only accepts private keys whose ACL grants access to the
/// user, SYSTEM and Administrators alone; a new file inherits its directory's
/// ACL, so tighten it (best effort — the audit reports any remaining problem).
fn restrict_private_key(path: &Path) {
    #[cfg(windows)]
    {
        let _ = crate::perms::fix(path, crate::perms::PermKind::PrivateKey);
    }
    #[cfg(not(windows))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ErrorCode,
        keys::{KeyFormat, scan, testdata as td},
    };

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn request(name: &str, algorithm: GenerateAlgorithm, pass: Option<&str>) -> GenerateRequest {
        GenerateRequest {
            algorithm,
            file_name: name.into(),
            comment: "me@example.com".into(),
            passphrase: pass.map(secret),
        }
    }

    #[test]
    fn file_name_validation() {
        for ok in ["id_ed25519", "github-work", "a.b_c-1", "K"] {
            validate_file_name(ok).unwrap();
        }
        for bad in [
            "",
            ".hidden",
            "a/b",
            "a\\b",
            "..",
            "a b",
            "id.pub",
            "config",
            "known_hosts",
            "x.",
            "ключ",
            "CON",
            "nul.txt",
            "a\nb",
        ] {
            assert_eq!(
                validate_file_name(bad).unwrap_err().code(),
                ErrorCode::InvalidInput,
                "{bad:?}"
            );
        }
        assert!(validate_file_name(&"a".repeat(MAX_FILE_NAME + 1)).is_err());
    }

    #[test]
    fn generate_scan_change_passphrase_load() {
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh");

        let info = generate(
            &dir,
            &request("id_ed25519", GenerateAlgorithm::Ed25519, None),
        )
        .unwrap();
        assert_eq!(info.algorithm, KeyAlgorithm::Ed25519);
        assert_eq!(info.encrypted, Some(false));
        assert_eq!(info.comment, "me@example.com");
        assert!(info.permissions.ok, "{:?}", info.permissions);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir), 0o700);
            assert_eq!(mode(&dir.join("id_ed25519")), 0o600);
            assert_eq!(mode(&dir.join("id_ed25519.pub")), 0o644);
        }

        // Refuses to overwrite.
        let err = generate(
            &dir,
            &request("id_ed25519", GenerateAlgorithm::Ed25519, None),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::AlreadyExists);

        let scanned = scan(&dir).unwrap();
        assert_eq!(scanned.keys.len(), 1);
        assert_eq!(scanned.keys[0], info);

        let path = dir.join("id_ed25519");
        let pass = secret("first pass");
        let enc = change_passphrase(&path, None, Some(&pass)).unwrap();
        assert_eq!(enc.encrypted, Some(true));
        assert_eq!(enc.fingerprint, info.fingerprint);
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----")
        );

        assert_eq!(
            load_private(&path, None).unwrap_err().code(),
            ErrorCode::PassphraseRequired
        );
        assert_eq!(
            load_private(&path, Some(&secret("nope")))
                .unwrap_err()
                .code(),
            ErrorCode::WrongPassphrase
        );
        let unlocked = load_private(&path, Some(&pass)).unwrap();
        assert_eq!(Some(unlocked.fingerprint()), info.fingerprint);
        assert_eq!(unlocked.comment(), "me@example.com");
        assert!(!format!("{unlocked:?}").contains("PRIVATE"));

        assert_eq!(
            change_passphrase(&path, Some(&secret("bad")), None)
                .unwrap_err()
                .code(),
            ErrorCode::WrongPassphrase
        );
        let second = secret("second pass");
        change_passphrase(&path, Some(&pass), Some(&second)).unwrap();
        load_private(&path, Some(&second)).unwrap();
        let plain = change_passphrase(&path, Some(&second), None).unwrap();
        assert_eq!(plain.encrypted, Some(false));
        assert_eq!(
            load_private(&path, None).unwrap().comment(),
            "me@example.com"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn generate_encrypted_ecdsa_and_rsa() {
        let dir = tempfile::tempdir().unwrap();
        let pass = "s3cret";
        let ec = generate(
            dir.path(),
            &request(
                "ec",
                GenerateAlgorithm::Ecdsa {
                    curve: EcdsaCurve::P384,
                },
                Some(pass),
            ),
        )
        .unwrap();
        assert_eq!(ec.algorithm, KeyAlgorithm::EcdsaP384);
        assert_eq!(ec.encrypted, Some(true));
        // The comment survives in the .pub even though the private key is encrypted.
        assert_eq!(ec.comment, "me@example.com");
        let raw = fs::read_to_string(dir.path().join("ec")).unwrap();
        let parsed = PrivateKey::from_openssh(&raw).unwrap();
        assert_eq!(parsed.cipher(), ssh_key::Cipher::Aes256Ctr);
        assert!(
            matches!(parsed.kdf(), ssh_key::Kdf::Bcrypt { rounds: 16, salt } if salt.len() == 16)
        );

        let rsa = generate(
            dir.path(),
            &request("rsa", GenerateAlgorithm::Rsa { bits: 3072 }, None),
        )
        .unwrap();
        assert_eq!(rsa.bits, Some(3072));
        let err = generate(
            dir.path(),
            &request("rsa2", GenerateAlgorithm::Rsa { bits: 1024 }, None),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
        let err = generate(
            dir.path(),
            &GenerateRequest {
                comment: "two\nlines".into(),
                ..request("c", GenerateAlgorithm::Ed25519, None)
            },
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn decrypts_keys_encrypted_by_ssh_keygen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k");
        fs::write(&path, td::OPENSSH_ED25519_ENCRYPTED).unwrap();
        let key = load_private(&path, Some(&secret(td::KEYGEN_PASSPHRASE))).unwrap();
        assert_eq!(key.comment(), "keygen@test");
        let expected = PublicKey::from_openssh(td::OPENSSH_ED25519_ENCRYPTED_PUB.trim()).unwrap();
        assert_eq!(key.public_key_data(), expected.key_data());
    }

    #[test]
    fn legacy_keys_load_but_cannot_change_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let rsa = dir.path().join("rsa");
        fs::write(&rsa, td::RSA_PEM).unwrap();
        fs::write(sibling_pub(&rsa), td::RSA_PEM_PUB).unwrap();
        let key = load_private(&rsa, None).unwrap();
        assert_eq!(key.algorithm(), KeyAlgorithm::Rsa);
        assert_eq!(key.comment(), "legacy@test");
        assert_eq!(
            change_passphrase(&rsa, None, Some(&secret("x")))
                .unwrap_err()
                .code(),
            ErrorCode::Unsupported
        );
        let enc = dir.path().join("enc");
        fs::write(&enc, td::RSA_PEM_ENCRYPTED).unwrap();
        assert_eq!(
            load_private(&enc, None).unwrap_err().code(),
            ErrorCode::Unsupported
        );
        let public = dir.path().join("pub");
        fs::write(&public, td::RSA_PEM_PUB).unwrap();
        assert_eq!(
            load_private(&public, None).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn regenerate_public_without_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("work");
        fs::write(&path, td::OPENSSH_ED25519_ENCRYPTED).unwrap();
        let info = regenerate_public(&path).unwrap();
        let written = fs::read_to_string(sibling_pub(&path)).unwrap();
        let expected = PublicKey::from_openssh(td::OPENSSH_ED25519_ENCRYPTED_PUB.trim()).unwrap();
        assert_eq!(
            PublicKey::from_openssh(written.trim()).unwrap().key_data(),
            expected.key_data()
        );
        assert!(!info.pair_mismatch);
        assert_eq!(
            regenerate_public(&path).unwrap_err().code(),
            ErrorCode::AlreadyExists
        );

        // Unencrypted key: comment is preserved.
        let plain = dir.path().join("plain");
        fs::write(&plain, td::OPENSSH_ED25519).unwrap();
        assert_eq!(regenerate_public(&plain).unwrap().comment, "plain@test");

        // Legacy unencrypted EC key: derived from the private scalar.
        let ec = dir.path().join("ec");
        fs::write(&ec, td::EC_PEM_EXPLICIT).unwrap();
        let info = regenerate_public(&ec).unwrap();
        assert_eq!(info.format, KeyFormat::Pem);
        assert!(!info.pair_mismatch);

        let enc = dir.path().join("enc");
        fs::write(&enc, td::RSA_PEM_ENCRYPTED).unwrap();
        assert_eq!(
            regenerate_public(&enc).unwrap_err().code(),
            ErrorCode::Unsupported
        );
    }

    #[test]
    fn import_copies_pair_with_permissions() {
        let src = tempfile::tempdir().unwrap();
        let source = src.path().join("downloaded_key");
        fs::write(&source, td::OPENSSH_ED25519).unwrap();
        fs::write(sibling_pub(&source), td::OPENSSH_ED25519_PUB).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();
        }
        let home = tempfile::tempdir().unwrap();
        let dir = home.path().join(".ssh");
        let info = import(&dir, &source, Some("imported")).unwrap();
        assert_eq!(info.name, "imported");
        assert!(info.permissions.ok);
        assert_eq!(
            fs::read_to_string(dir.join("imported")).unwrap(),
            td::OPENSSH_ED25519
        );
        assert_eq!(
            fs::read_to_string(dir.join("imported.pub")).unwrap(),
            td::OPENSSH_ED25519_PUB
        );
        assert_eq!(
            import(&dir, &source, Some("imported")).unwrap_err().code(),
            ErrorCode::AlreadyExists
        );

        // Without a source .pub the public key is derived.
        let lone = src.path().join("lone");
        fs::write(&lone, td::OPENSSH_ED25519_ENCRYPTED).unwrap();
        let info = import(&dir, &lone, None).unwrap();
        assert!(info.public_path.is_some());
        assert_eq!(info.encrypted, Some(true));

        let ppk = src.path().join("k.ppk");
        fs::write(&ppk, "PuTTY-User-Key-File-3: ssh-ed25519\n").unwrap();
        assert_eq!(
            import(&dir, &ppk, None).unwrap_err().code(),
            ErrorCode::Unsupported
        );
        assert_eq!(
            import(&dir, &src.path().join("lone"), Some("../evil"))
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn trash_validates_paths() {
        move_to_trash(&[]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let err = move_to_trash(&[dir.path().join("missing")]).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    /// Moves a temporary file to the real trash; run manually with `--ignored`.
    #[test]
    #[ignore = "touches the user's trash"]
    fn trash_moves_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sshkm-trash-test");
        fs::write(&path, "x").unwrap();
        move_to_trash(std::slice::from_ref(&path)).unwrap();
        assert!(!path.exists());
    }

    /// `ssh-keygen` must accept generated and re-encrypted keys. Works on
    /// temporary files only.
    #[test]
    #[ignore = "needs the ssh-keygen binary"]
    fn ssh_keygen_reads_generated_keys() {
        use std::process::Command;
        let keygen_public = |path: &Path, pass: &str| -> String {
            let out = Command::new("ssh-keygen")
                .args(["-y", "-P", pass, "-f"])
                .arg(path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let line = String::from_utf8(out.stdout).unwrap();
            line.split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ")
        };
        let dir = tempfile::tempdir().unwrap();
        for (name, algorithm) in [
            ("ed", GenerateAlgorithm::Ed25519),
            ("rsa", GenerateAlgorithm::Rsa { bits: 3072 }),
            (
                "p256",
                GenerateAlgorithm::Ecdsa {
                    curve: EcdsaCurve::P256,
                },
            ),
            (
                "p521",
                GenerateAlgorithm::Ecdsa {
                    curve: EcdsaCurve::P521,
                },
            ),
        ] {
            let info = generate(dir.path(), &request(name, algorithm, Some("pw one"))).unwrap();
            let path = dir.path().join(name);
            let ours = info.public_key.unwrap();
            let ours = ours
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(keygen_public(&path, "pw one"), ours, "{name}");
            change_passphrase(&path, Some(&secret("pw one")), Some(&secret("pw two"))).unwrap();
            assert_eq!(keygen_public(&path, "pw two"), ours, "{name}");
            let out = Command::new("ssh-keygen")
                .arg("-l")
                .arg("-f")
                .arg(&path)
                .output()
                .unwrap();
            let listed = String::from_utf8(out.stdout).unwrap();
            assert!(
                listed.contains(info.fingerprint.as_deref().unwrap()),
                "{listed}"
            );
        }
    }

    #[test]
    fn generate_request_deserializes_and_hides_passphrase() {
        let req: GenerateRequest = serde_json::from_str(
            r#"{"algorithm":{"kind":"ecdsa","curve":"p256"},"fileName":"k","passphrase":"pw"}"#,
        )
        .unwrap();
        assert_eq!(
            req.algorithm,
            GenerateAlgorithm::Ecdsa {
                curve: EcdsaCurve::P256
            }
        );
        assert_eq!(req.passphrase.as_ref().unwrap().expose_secret(), "pw");
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("pw\""), "{json}");
        assert!(!format!("{req:?}").contains("\"pw\""));
        let rsa: GenerateAlgorithm = serde_json::from_str(r#"{"kind":"rsa","bits":4096}"#).unwrap();
        assert_eq!(rsa, GenerateAlgorithm::Rsa { bits: 4096 });
    }
}
