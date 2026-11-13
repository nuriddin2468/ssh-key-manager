//! Converting private keys between the OpenSSH format, PuTTY's `.ppk`
//! (versions 2 and 3) and PEM / PKCS#8, and what the Key converter shows of
//! a key: its fingerprints (SHA-256 and MD5) and randomart.
//!
//! Reading takes every format the app knows, encrypted ones included:
//! OpenSSH keys with their bcrypt limit ([`super::ops`]), PuTTY keys
//! ([`super::ppk`]), traditional OpenSSL PEM encryption with AES
//! (`DEK-Info: AES-128-CBC`, what `ssh-keygen -m PEM` and `openssl genrsa
//! -aes256` write) and PKCS#8 with PBES2, PBKDF2 and AES (what `openssl
//! pkcs8` and `ssh-keygen -m PKCS8` write). Triple DES and scrypt are
//! refused.
//!
//! Writing: an OpenSSH key, encrypted as `ssh-keygen` does when a passphrase
//! is given; a PuTTY key; a PEM key (PKCS#1 for RSA, SEC1 for ECDSA), which
//! is never encrypted, since OpenSSL's way of doing that derives the key
//! with one round of MD5; or PKCS#8, encrypted with PBES2 (PBKDF2-HMAC-SHA256,
//! AES-256-CBC) when a passphrase is given. PEM and PKCS#8 hold no comment.
//!
//! Converted keys are added to `~/.ssh` only in the OpenSSH format, through
//! [`super::ops::write_pair`], the end of every import. One saved where the
//! user picks ([`save`]) is a private file there, and never replaces a file
//! in `~/.ssh`.

use std::path::Path;

use base64ct::{Base64, Encoding};
use md5::Md5;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha1::Digest;
use sha2::{Sha256, Sha384, Sha512};
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::{Cipher, HashAlg, LineEnding, PrivateKey, PublicKey};
use zeroize::Zeroizing;

use super::legacy::{self, PemKind, der_tlv, header_fields, pem_body};
use super::ops::{read_private_text, unlock, write_pair};
use super::randomart::randomart;
use super::{
    Content, KeyAlgorithm, KeyInfo, MAX_KEY_FILE_SIZE, classify, key_bits, ppk, sibling_pub,
};
use crate::{Error, Result, fsutil};

/// The most PBKDF2 iterations of an encrypted PKCS#8 key that is decrypted,
/// some seconds' work; `openssl` uses 2048.
const MAX_PBKDF2_ITERATIONS: u32 = 5_000_000;
/// PBKDF2 iterations of the PKCS#8 keys this app writes: a tenth of a
/// second. Fewer in tests, which build this crate without optimisation.
const WRITE_PBKDF2_ITERATIONS: u32 = if cfg!(test) { 2048 } else { 200_000 };

const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const OID_HMAC_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07];
const OID_HMAC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09];
const OID_HMAC_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a];
const OID_HMAC_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b];
const OID_AES128_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02];
const OID_AES192_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x16];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];

/// A key file's format, as read or as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum KeyFileFormat {
    /// `-----BEGIN OPENSSH PRIVATE KEY-----`
    Openssh,
    /// `PuTTY-User-Key-File-3`, PuTTY 0.75 and later.
    Ppk3,
    /// `PuTTY-User-Key-File-2`, for older PuTTY and the tools built on it.
    Ppk2,
    /// `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY` (PKCS#1, SEC1).
    Pem,
    /// `BEGIN PRIVATE KEY` or `BEGIN ENCRYPTED PRIVATE KEY`.
    Pkcs8,
}

impl KeyFileFormat {
    /// The file name extension a saved copy gets (`None`: none, as OpenSSH
    /// keys have).
    pub const fn extension(self) -> Option<&'static str> {
        match self {
            Self::Openssh => None,
            Self::Ppk3 | Self::Ppk2 => Some("ppk"),
            Self::Pem | Self::Pkcs8 => Some("pem"),
        }
    }
}

/// How to tell a key at a glance, as `ssh-keygen -l` and `-lv` show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct KeyFingerprints {
    /// `SHA256:…`
    pub sha256: String,
    /// `MD5:aa:bb:…`, what older tools and some web consoles show.
    pub md5: String,
    /// `ssh-keygen -lv`'s picture of the SHA-256 fingerprint, eleven lines.
    pub randomart: String,
    /// The one-line OpenSSH public key, with the comment.
    pub public_key: String,
}

/// What a key file holds, without its private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct KeyFileInfo {
    pub format: KeyFileFormat,
    /// `None` for an encrypted PEM or PKCS#8 key not opened yet.
    pub algorithm: Option<KeyAlgorithm>,
    pub bits: Option<u32>,
    /// What the file says; PEM and PKCS#8 keys take it from a `.pub` file
    /// next to them, if there is one.
    pub comment: String,
    pub encrypted: bool,
    /// The private key was read: it isn't encrypted, or the passphrase given
    /// opened it.
    pub opened: bool,
    /// `None` for an encrypted PEM or PKCS#8 key not opened yet with no
    /// `.pub` file beside it.
    pub fingerprints: Option<KeyFingerprints>,
    /// The file's name without its extension: a name for the converted copy.
    pub suggested_name: String,
}

/// `rsa`'s key for an RSA key pair. (`ssh-key` 0.6 has a conversion, but it
/// passes `p` twice instead of `p` and `q`, so the result never validates.)
pub(super) fn rsa_private_key(rsa: &ssh_key::private::RsaKeypair) -> Option<rsa::RsaPrivateKey> {
    let uint = |m: &ssh_key::Mpint| m.as_positive_bytes().map(rsa::BigUint::from_bytes_be);
    rsa::RsaPrivateKey::from_components(
        uint(&rsa.public.n)?,
        uint(&rsa.public.e)?,
        uint(&rsa.private.d)?,
        vec![uint(&rsa.private.p)?, uint(&rsa.private.q)?],
    )
    .ok()
}

/// Fingerprints, randomart and the public key line of `key`.
pub fn fingerprints(key: &PublicKey) -> KeyFingerprints {
    let blob = key.to_bytes().unwrap_or_default();
    let sha256 = key.key_data().fingerprint(HashAlg::Sha256);
    let md5 = Md5::digest(&blob)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    let bits = key_bits(key.key_data()).unwrap_or_default();
    let title = format!("{} {bits}", art_name(key.key_data()));
    KeyFingerprints {
        sha256: sha256.to_string(),
        md5: format!("MD5:{md5}"),
        randomart: randomart(sha256.as_bytes(), &title, "SHA256"),
        public_key: key.to_openssh().unwrap_or_default(),
    }
}

/// The type as `ssh-keygen` names it in randomart.
fn art_name(key: &KeyData) -> &'static str {
    match key {
        KeyData::Rsa(_) => "RSA",
        KeyData::Ecdsa(_) => "ECDSA",
        KeyData::Ed25519(_) => "ED25519",
        KeyData::Dsa(_) => "DSA",
        KeyData::SkEd25519(_) => "ED25519-SK",
        KeyData::SkEcdsaSha2NistP256(_) => "ECDSA-SK",
        _ => "KEY",
    }
}

/// Describes the key file at `path`. With a `passphrase`, an encrypted key
/// is opened too, failing with `wrong_passphrase` if it doesn't open it.
pub fn inspect(path: &Path, passphrase: Option<&SecretString>) -> Result<KeyFileInfo> {
    let text = read_private_text(path)?;
    let source = Source::read(&text, path)?;
    let given = passphrase.is_some_and(|p| !p.expose_secret().is_empty());
    let suggested_name = suggested_name(path);
    if !source.encrypted() || given {
        let key = source.open(passphrase)?;
        return Ok(describe(
            source.format(),
            key.public_key(),
            source.encrypted(),
            true,
            suggested_name,
        ));
    }
    match source.public()? {
        Some(public) => Ok(describe(
            source.format(),
            &public,
            true,
            false,
            suggested_name,
        )),
        None => Ok(KeyFileInfo {
            format: source.format(),
            algorithm: source.algorithm(),
            bits: None,
            comment: String::new(),
            encrypted: true,
            opened: false,
            fingerprints: None,
            suggested_name,
        }),
    }
}

fn describe(
    format: KeyFileFormat,
    public: &PublicKey,
    encrypted: bool,
    opened: bool,
    suggested_name: String,
) -> KeyFileInfo {
    KeyFileInfo {
        format,
        algorithm: Some(KeyAlgorithm::from_ssh(&public.algorithm())),
        bits: key_bits(public.key_data()),
        comment: public.comment().to_owned(),
        encrypted,
        opened,
        fingerprints: Some(fingerprints(public)),
        suggested_name,
    }
}

/// The file's name up to its last dot, or `key` if nothing is left.
fn suggested_name(path: &Path) -> String {
    let name = path
        .file_stem()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_owned();
    if name.is_empty() { "key".into() } else { name }
}

/// The key at `path` written out in `format`; `new_passphrase` encrypts it
/// (refused for [`KeyFileFormat::Pem`]), `comment` replaces the comment.
pub fn convert(
    path: &Path,
    passphrase: Option<&SecretString>,
    format: KeyFileFormat,
    new_passphrase: Option<&SecretString>,
    comment: Option<&str>,
) -> Result<Zeroizing<String>> {
    let key = open_for_output(path, passphrase, comment)?;
    let new_passphrase = new_passphrase.filter(|p| !p.expose_secret().is_empty());
    match format {
        KeyFileFormat::Openssh => openssh_text(&key, new_passphrase),
        KeyFileFormat::Ppk3 => ppk::encode(&key, 3, new_passphrase),
        KeyFileFormat::Ppk2 => ppk::encode(&key, 2, new_passphrase),
        KeyFileFormat::Pem if new_passphrase.is_some() => Err(Error::Unsupported(
            "PEM keys are written without a passphrase; choose PKCS#8 for one".into(),
        )),
        KeyFileFormat::Pem => pem_text(key.key_data()),
        KeyFileFormat::Pkcs8 => pkcs8_text(key.key_data(), new_passphrase),
    }
}

/// Saves `text`, a key [`convert`] wrote out (often unencrypted), at
/// `target`, picked in a save dialog, in a new file only this user can open
/// ([`fsutil::write_private`]): mode 0600 from the first byte whatever was
/// there, on Windows the private access list from creation (a drive that
/// can't keep one is refused). The file is renamed onto `target` itself, so
/// a link there is replaced, never written through. Inside `ssh_dir`
/// (compared by file identity, [`fsutil::is_within`]) it is only ever a new
/// file: [`Error::AlreadyExists`] if something is there.
pub fn save(target: &Path, text: &str, ssh_dir: &Path) -> Result<()> {
    let in_ssh_dir = fsutil::is_within(target, ssh_dir);
    if fsutil::write_private(target, text.as_bytes(), !in_ssh_dir)? {
        Ok(())
    } else {
        Err(Error::AlreadyExists(format!(
            "{} is in ~/.ssh already",
            target.display()
        )))
    }
}

/// Converts the key at `path` into the OpenSSH format and adds it to `dir`
/// (`~/.ssh`) as `file_name` and `file_name.pub`, as an import does.
pub fn import(
    dir: &Path,
    path: &Path,
    passphrase: Option<&SecretString>,
    file_name: &str,
    new_passphrase: Option<&SecretString>,
    comment: Option<&str>,
) -> Result<KeyInfo> {
    let key = open_for_output(path, passphrase, comment)?;
    let new_passphrase = new_passphrase.filter(|p| !p.expose_secret().is_empty());
    // The public key from the open key: an encrypted one keeps its comment
    // inside the encryption.
    let text = openssh_text(&key, new_passphrase)?;
    write_pair(dir, file_name, &text, Some(key.public_key()))
}

/// The key at `path`, opened, with `comment` if one is given.
fn open_for_output(
    path: &Path,
    passphrase: Option<&SecretString>,
    comment: Option<&str>,
) -> Result<PrivateKey> {
    let text = read_private_text(path)?;
    let mut key = Source::read(&text, path)?.open(passphrase)?;
    if let Some(comment) = comment {
        validate_comment(comment)?;
        key.set_comment(comment);
    }
    Ok(key)
}

fn validate_comment(comment: &str) -> Result<()> {
    if comment.len() > 1024 || comment.chars().any(char::is_control) {
        return Err(Error::invalid(
            "the comment must be one line of at most 1024 bytes",
        ));
    }
    Ok(())
}

fn openssh_text(key: &PrivateKey, passphrase: Option<&SecretString>) -> Result<Zeroizing<String>> {
    let failed = |e: ssh_key::Error| Error::Parse(format!("encoding key: {e}"));
    match passphrase {
        Some(passphrase) => key
            .encrypt(&mut OsRng, passphrase.expose_secret().as_bytes())
            .map_err(failed)?
            .to_openssh(LineEnding::LF)
            .map_err(failed),
        None => key.to_openssh(LineEnding::LF).map_err(failed),
    }
}

/// A key file as read, before its passphrase.
enum Source<'a> {
    OpenSsh(Box<PrivateKey>),
    Ppk(Box<ppk::Ppk>),
    Legacy {
        text: &'a str,
        kind: PemKind,
        key: Box<legacy::LegacyKey>,
        /// The `.pub` file next to it, if any.
        public: Option<PublicKey>,
    },
}

impl<'a> Source<'a> {
    fn read(text: &'a str, path: &Path) -> Result<Self> {
        let text = text.trim_start_matches('\u{feff}').trim();
        if ppk::is_ppk(text) {
            return Ok(Self::Ppk(Box::new(ppk::parse(text)?)));
        }
        let malformed = || Error::Parse(format!("malformed key: {}", path.display()));
        match legacy::pem_kind(text) {
            Some(PemKind::OpenSsh) => PrivateKey::from_openssh(text)
                .map(|key| Self::OpenSsh(Box::new(key)))
                .map_err(|_| malformed()),
            Some(kind) => {
                let key = Box::new(legacy::parse(text, kind).ok_or_else(malformed)?);
                let public = fsutil::read_limited(&sibling_pub(path), MAX_KEY_FILE_SIZE)
                    .ok()
                    .and_then(|bytes| match classify(&bytes) {
                        Content::Public(key) => Some(key),
                        _ => None,
                    });
                Ok(Self::Legacy {
                    text,
                    kind,
                    key,
                    public,
                })
            }
            None => Err(match classify(text.as_bytes()) {
                Content::Public(_) => Error::invalid(format!(
                    "{} is a public key; select the private key",
                    path.display()
                )),
                _ => Error::Parse(format!("not an SSH key: {}", path.display())),
            }),
        }
    }

    fn format(&self) -> KeyFileFormat {
        match self {
            Self::OpenSsh(_) => KeyFileFormat::Openssh,
            Self::Ppk(ppk) if ppk.version == 2 => KeyFileFormat::Ppk2,
            Self::Ppk(_) => KeyFileFormat::Ppk3,
            Self::Legacy {
                kind: PemKind::Pkcs8 | PemKind::Pkcs8Encrypted,
                ..
            } => KeyFileFormat::Pkcs8,
            Self::Legacy { .. } => KeyFileFormat::Pem,
        }
    }

    fn encrypted(&self) -> bool {
        match self {
            Self::OpenSsh(key) => key.is_encrypted(),
            Self::Ppk(ppk) => ppk.encrypted(),
            Self::Legacy { key, .. } => key.encrypted,
        }
    }

    fn algorithm(&self) -> Option<KeyAlgorithm> {
        match self {
            Self::Legacy { key, .. } => key.algorithm,
            _ => None,
        }
    }

    /// The public key, where it can be had without the passphrase.
    fn public(&self) -> Result<Option<PublicKey>> {
        Ok(match self {
            Self::OpenSsh(key) => Some(key.public_key().clone()),
            Self::Ppk(ppk) => Some(ppk.public_key()?),
            Self::Legacy { public, .. } => public.clone(),
        })
    }

    /// The private key, decrypted with `passphrase` if it is encrypted.
    fn open(&self, passphrase: Option<&SecretString>) -> Result<PrivateKey> {
        match self {
            Self::OpenSsh(key) => unlock((**key).clone(), passphrase),
            Self::Ppk(ppk) => ppk.decrypt(passphrase),
            Self::Legacy {
                text,
                kind,
                key,
                public,
            } => {
                let comment = public
                    .as_ref()
                    .map(|p| p.comment().to_owned())
                    .unwrap_or_default();
                let keypair = if key.encrypted {
                    let pass = passphrase
                        .map(|p| p.expose_secret().as_bytes())
                        .filter(|p| !p.is_empty())
                        .ok_or(Error::PassphraseRequired)?;
                    decrypt_legacy(text, *kind, pass)?
                } else {
                    key.keypair.clone().ok_or_else(|| {
                        Error::Unsupported("this legacy key type cannot be converted".into())
                    })?
                };
                PrivateKey::new(keypair, comment)
                    .map_err(|e| Error::Parse(format!("building key: {e}")))
            }
        }
    }
}

/// Decrypts an encrypted PEM or PKCS#8 key and reads what comes out.
fn decrypt_legacy(text: &str, kind: PemKind, passphrase: &[u8]) -> Result<KeypairData> {
    let body = pem_body(text).ok_or_else(|| Error::Parse("malformed PEM key".into()))?;
    let (plain, label, plain_kind) = match kind {
        PemKind::Pkcs8Encrypted => (
            decrypt_pbes2(&body, passphrase)?,
            "PRIVATE KEY",
            PemKind::Pkcs8,
        ),
        PemKind::Rsa => (
            decrypt_traditional(text, &body, passphrase)?,
            "RSA PRIVATE KEY",
            PemKind::Rsa,
        ),
        PemKind::Ec => (
            decrypt_traditional(text, &body, passphrase)?,
            "EC PRIVATE KEY",
            PemKind::Ec,
        ),
        _ => {
            return Err(Error::Unsupported(
                "this encrypted key type cannot be converted".into(),
            ));
        }
    };
    // Garbage that happened to end in valid padding: the passphrase was
    // wrong all the same.
    let pem = pem_wrap(label, &plain);
    legacy::parse(&pem, plain_kind)
        .and_then(|key| key.keypair)
        .ok_or(Error::WrongPassphrase)
}

/// OpenSSL's traditional PEM encryption: `DEK-Info: AES-…-CBC,<IV>`, the key
/// from `EVP_BytesToKey` (MD5, one round, the IV's first 8 bytes as salt).
fn decrypt_traditional(text: &str, body: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let headers = header_fields(text);
    let dek = headers
        .iter()
        .find(|(name, _)| *name == "DEK-Info")
        .map(|(_, value)| *value)
        .ok_or_else(|| Error::Parse("malformed encrypted PEM key".into()))?;
    let (cipher, iv) = dek
        .split_once(',')
        .ok_or_else(|| Error::Parse("malformed encrypted PEM key".into()))?;
    let (cipher, key_len) = match cipher {
        "AES-128-CBC" => (Cipher::Aes128Cbc, 16),
        "AES-192-CBC" => (Cipher::Aes192Cbc, 24),
        "AES-256-CBC" => (Cipher::Aes256Cbc, 32),
        other => {
            return Err(Error::Unsupported(format!(
                "PEM keys encrypted with {other}; only AES is supported"
            )));
        }
    };
    let iv = from_hex(iv)
        .filter(|iv| iv.len() == 16)
        .ok_or_else(|| Error::Parse("malformed encrypted PEM key".into()))?;
    let mut key = Zeroizing::new(Vec::with_capacity(key_len + 16));
    let mut previous = Zeroizing::new(Vec::new());
    while key.len() < key_len {
        let mut hash = Md5::new();
        hash.update(&*previous);
        hash.update(passphrase);
        hash.update(&iv[..8]);
        *previous = hash.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    cbc_decrypt(cipher, &key, &iv, body)
}

/// PKCS#8's `EncryptedPrivateKeyInfo` with PBES2: PBKDF2 (HMAC-SHA-1 or
/// SHA-2) and AES-CBC.
fn decrypt_pbes2(der: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let bad = || Error::Parse("malformed encrypted PKCS#8 key".into());
    let unsupported = || {
        Error::Unsupported(
            "this PKCS#8 encryption; only PBES2 with PBKDF2 and AES is supported".into(),
        )
    };
    let take = |tag: u8, input: &'_ [u8]| -> Result<(Vec<u8>, Vec<u8>)> {
        match der_tlv(input) {
            Some((t, body, rest)) if t == tag => Ok((body.to_vec(), rest.to_vec())),
            _ => Err(bad()),
        }
    };
    let (info, _) = take(0x30, der)?;
    let (algorithm, rest) = take(0x30, &info)?;
    let (data, _) = take(0x04, &rest)?;
    let (oid, params) = take(0x06, &algorithm)?;
    if oid != OID_PBES2 {
        return Err(unsupported());
    }
    let (params, _) = take(0x30, &params)?;
    let (kdf, rest) = take(0x30, &params)?;
    let (scheme, _) = take(0x30, &rest)?;

    let (kdf_oid, kdf_params) = take(0x06, &kdf)?;
    if kdf_oid != OID_PBKDF2 {
        return Err(unsupported());
    }
    let (kdf_params, _) = take(0x30, &kdf_params)?;
    let (salt, rest) = take(0x04, &kdf_params)?;
    let (iterations, mut rest) = take(0x02, &rest)?;
    let iterations = der_u32(&iterations).ok_or_else(bad)?;
    if iterations == 0 || iterations > MAX_PBKDF2_ITERATIONS {
        return Err(Error::Unsupported(format!(
            "the key asks for {iterations} PBKDF2 iterations, more than this app allows"
        )));
    }
    if let Some((0x02, _, after)) = der_tlv(&rest) {
        rest = after.to_vec();
    }
    let prf = match der_tlv(&rest) {
        Some((0x30, prf, _)) => take(0x06, prf)?.0,
        _ => OID_HMAC_SHA1.to_vec(),
    };

    let (cipher_oid, cipher_params) = take(0x06, &scheme)?;
    let (cipher, key_len) = match cipher_oid.as_slice() {
        OID_AES128_CBC => (Cipher::Aes128Cbc, 16),
        OID_AES192_CBC => (Cipher::Aes192Cbc, 24),
        OID_AES256_CBC => (Cipher::Aes256Cbc, 32),
        _ => return Err(unsupported()),
    };
    let (iv, _) = take(0x04, &cipher_params)?;
    if iv.len() != 16 {
        return Err(bad());
    }
    let mut key = Zeroizing::new(vec![0; key_len]);
    match prf.as_slice() {
        OID_HMAC_SHA1 => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(passphrase, &salt, iterations, &mut key),
        OID_HMAC_SHA256 => pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, &salt, iterations, &mut key),
        OID_HMAC_SHA384 => pbkdf2::pbkdf2_hmac::<Sha384>(passphrase, &salt, iterations, &mut key),
        OID_HMAC_SHA512 => pbkdf2::pbkdf2_hmac::<Sha512>(passphrase, &salt, iterations, &mut key),
        _ => return Err(unsupported()),
    }
    cbc_decrypt(cipher, &key, &iv, &data)
}

/// AES-CBC with PKCS#7 padding; padding that doesn't check out means a
/// wrong passphrase.
fn cbc_decrypt(cipher: Cipher, key: &[u8], iv: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(Error::Parse("malformed encrypted key".into()));
    }
    let mut plain = Zeroizing::new(data.to_vec());
    cipher
        .decrypt(key, iv, &mut plain, None)
        .map_err(|_| Error::WrongPassphrase)?;
    let pad = usize::from(*plain.last().unwrap_or(&0));
    if pad == 0
        || pad > 16
        || plain[plain.len() - pad..]
            .iter()
            .any(|b| usize::from(*b) != pad)
    {
        return Err(Error::WrongPassphrase);
    }
    let len = plain.len() - pad;
    plain.truncate(len);
    Ok(plain)
}

/// A DER INTEGER's contents as a non-negative `u32`.
fn der_u32(bytes: &[u8]) -> Option<u32> {
    let bytes = match bytes {
        [0, rest @ ..] if !rest.is_empty() => rest,
        [first, ..] if first & 0x80 != 0 => return None,
        _ => bytes,
    };
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    Some(bytes.iter().fold(0, |n, b| (n << 8) | u32::from(*b)))
}

/// PKCS#1 (RSA) or SEC1 (ECDSA); Ed25519 has no such format.
fn pem_text(keypair: &KeypairData) -> Result<Zeroizing<String>> {
    use p256::pkcs8::LineEnding as PemLines;
    let failed = |e: &dyn std::fmt::Display| Error::Parse(format!("encoding key: {e}"));
    match keypair {
        KeypairData::Rsa(rsa) => {
            use rsa::pkcs1::EncodeRsaPrivateKey;
            let key = rsa_private_key(rsa).ok_or_else(|| failed(&"invalid RSA key"))?;
            key.to_pkcs1_pem(PemLines::LF).map_err(|e| failed(&e))
        }
        KeypairData::Ecdsa(ecdsa) => {
            let bytes = ecdsa.private_key_bytes();
            let pem = match bytes.len() {
                32 => p256::SecretKey::from_slice(bytes)
                    .map_err(|e| failed(&e))?
                    .to_sec1_pem(PemLines::LF),
                48 => p384::SecretKey::from_slice(bytes)
                    .map_err(|e| failed(&e))?
                    .to_sec1_pem(PemLines::LF),
                _ => p521::SecretKey::from_slice(bytes)
                    .map_err(|e| failed(&e))?
                    .to_sec1_pem(PemLines::LF),
            };
            pem.map_err(|e| failed(&e))
        }
        KeypairData::Ed25519(_) => Err(Error::Unsupported(
            "Ed25519 keys have no PEM format; choose PKCS#8".into(),
        )),
        _ => Err(Error::Unsupported(
            "this key type cannot be converted".into(),
        )),
    }
}

/// PKCS#8, encrypted with PBES2 when a passphrase is given.
fn pkcs8_text(
    keypair: &KeypairData,
    passphrase: Option<&SecretString>,
) -> Result<Zeroizing<String>> {
    use p256::pkcs8::EncodePrivateKey;
    let failed = |e: &dyn std::fmt::Display| Error::Parse(format!("encoding key: {e}"));
    let document = match keypair {
        KeypairData::Rsa(rsa) => rsa_private_key(rsa)
            .ok_or_else(|| failed(&"invalid RSA key"))?
            .to_pkcs8_der(),
        KeypairData::Ecdsa(ecdsa) => {
            let bytes = ecdsa.private_key_bytes();
            match bytes.len() {
                32 => p256::SecretKey::from_slice(bytes)
                    .map_err(|e| failed(&e))?
                    .to_pkcs8_der(),
                48 => p384::SecretKey::from_slice(bytes)
                    .map_err(|e| failed(&e))?
                    .to_pkcs8_der(),
                _ => p521::SecretKey::from_slice(bytes)
                    .map_err(|e| failed(&e))?
                    .to_pkcs8_der(),
            }
        }
        KeypairData::Ed25519(ed25519) => {
            ed25519_dalek::SigningKey::from_bytes(&ed25519.private.to_bytes()).to_pkcs8_der()
        }
        _ => {
            return Err(Error::Unsupported(
                "this key type cannot be converted".into(),
            ));
        }
    }
    .map_err(|e| failed(&e))?;
    match passphrase {
        None => Ok(pem_wrap("PRIVATE KEY", document.as_bytes())),
        Some(passphrase) => {
            let der = encrypt_pbes2(document.as_bytes(), passphrase.expose_secret().as_bytes())?;
            Ok(pem_wrap("ENCRYPTED PRIVATE KEY", &der))
        }
    }
}

/// `EncryptedPrivateKeyInfo` with PBES2: PBKDF2-HMAC-SHA256 and AES-256-CBC.
fn encrypt_pbes2(der: &[u8], passphrase: &[u8]) -> Result<Vec<u8>> {
    let mut salt = [0; 16];
    let mut iv = [0; 16];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut iv);
    let mut key = Zeroizing::new([0; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase, &salt, WRITE_PBKDF2_ITERATIONS, &mut *key);
    let pad = 16 - der.len() % 16;
    let mut data = Zeroizing::new(der.to_vec());
    data.extend(std::iter::repeat_n(u8::try_from(pad).unwrap_or(16), pad));
    Cipher::Aes256Cbc
        .encrypt(&*key, &iv, &mut data)
        .map_err(|e| Error::Parse(format!("encrypting key: {e}")))?;

    let iterations = tlv(0x02, &der_uint(WRITE_PBKDF2_ITERATIONS));
    let prf = tlv(0x30, &[tlv(0x06, OID_HMAC_SHA256), tlv(0x05, &[])].concat());
    let kdf_params = tlv(0x30, &[tlv(0x04, &salt), iterations, prf].concat());
    let kdf = tlv(0x30, &[tlv(0x06, OID_PBKDF2), kdf_params].concat());
    let scheme = tlv(0x30, &[tlv(0x06, OID_AES256_CBC), tlv(0x04, &iv)].concat());
    let pbes2 = tlv(0x30, &[kdf, scheme].concat());
    let algorithm = tlv(0x30, &[tlv(0x06, OID_PBES2), pbes2].concat());
    Ok(tlv(0x30, &[algorithm, tlv(0x04, &data)].concat()))
}

/// A DER TLV with a definite length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes: Vec<u8> = len
            .to_be_bytes()
            .into_iter()
            .skip_while(|b| *b == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap_or(0));
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

/// A non-negative DER INTEGER's contents.
fn der_uint(n: u32) -> Vec<u8> {
    let mut bytes: Vec<u8> = n
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        bytes.insert(0, 0);
    }
    bytes
}

/// A PEM block: Base64 in lines of 64.
fn pem_wrap(label: &str, der: &[u8]) -> Zeroizing<String> {
    let body = Zeroizing::new(Base64::encode_string(der));
    let mut out = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(text.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::ErrorCode;
    use crate::keys::{KeyFormat, testdata as td};

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    fn file(dir: &Path, name: &str, text: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn fingerprints_are_what_ssh_keygen_prints() {
        let key = PublicKey::from_openssh(td::OPENSSH_ED25519_PUB).unwrap();
        let prints = fingerprints(&key);
        assert_eq!(
            prints.sha256,
            "SHA256:76vvbGumhP/HpDH4tlyySHWs5hgRZJHr2wQ7hSDwRK8"
        );
        assert_eq!(
            prints.md5,
            "MD5:f8:47:27:8f:4b:69:51:69:dd:36:e9:2b:e5:13:28:b0"
        );
        assert!(
            prints
                .randomart
                .starts_with("+--[ED25519 256]--+\n|  .oo   +o       |")
        );
        assert_eq!(prints.public_key, td::OPENSSH_ED25519_PUB.trim());
    }

    #[test]
    fn inspects_each_format_without_its_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            (
                "a.ppk",
                td::PPK_ECDSA_P256_ENC,
                KeyFileFormat::Ppk3,
                true,
                true,
            ),
            ("b.ppk", td::PPK2_RSA_3072, KeyFileFormat::Ppk2, false, true),
            (
                "c",
                td::OPENSSH_ED25519_ENCRYPTED,
                KeyFileFormat::Openssh,
                true,
                true,
            ),
            ("d.pem", td::RSA_PEM, KeyFileFormat::Pem, false, true),
            (
                "e.pem",
                td::RSA_PKCS8_ENCRYPTED,
                KeyFileFormat::Pkcs8,
                true,
                false,
            ),
        ];
        for (name, text, format, encrypted, known) in cases {
            let info = inspect(&file(dir.path(), name, text), None).unwrap();
            assert_eq!(info.format, format, "{name}");
            assert_eq!(info.encrypted, encrypted, "{name}");
            assert_eq!(info.opened, !encrypted, "{name}");
            assert_eq!(info.fingerprints.is_some(), known, "{name}");
        }
        let info = inspect(&dir.path().join("a.ppk"), None).unwrap();
        assert_eq!(info.suggested_name, "a");
        assert_eq!(info.comment, "user@example.com");
        assert_eq!(info.algorithm, Some(KeyAlgorithm::EcdsaP256));
    }

    #[test]
    fn encrypted_legacy_keys_open_with_their_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        // As `ssh-keygen -y -P legacy-pass` reads them.
        for (name, text, expected) in [
            (
                "pem",
                td::RSA_PEM_ENCRYPTED,
                "SHA256:wRfD8DWlRSmH24xjvAKFFJh5AgRgVXgQGVqWKm7Q9h8",
            ),
            (
                "pkcs8",
                td::RSA_PKCS8_ENCRYPTED,
                "SHA256:q5EZ02CpbogtN4UBn+7+kGVPIR9dbAr2WBXRBckW8Ew",
            ),
        ] {
            let path = file(dir.path(), name, text);
            let info = inspect(&path, Some(&secret("legacy-pass"))).unwrap();
            assert!(info.opened);
            assert_eq!(info.fingerprints.unwrap().sha256, expected);
            let error = inspect(&path, Some(&secret("wrong"))).unwrap_err();
            assert_eq!(error.code(), ErrorCode::WrongPassphrase, "{name}");
            let error = convert(&path, None, KeyFileFormat::Openssh, None, None).unwrap_err();
            assert_eq!(error.code(), ErrorCode::PassphraseRequired, "{name}");
        }
    }

    /// Every format to every other and back gives the same key.
    #[test]
    fn conversions_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let pass = secret("convert me");
        for source in [
            td::PPK_RSA_3072_OPENSSH,
            td::PPK_ECDSA_P256_OPENSSH,
            td::OPENSSH_ED25519,
        ] {
            let original = PrivateKey::from_openssh(source).unwrap();
            let path = file(dir.path(), "source", source);
            for format in [
                KeyFileFormat::Openssh,
                KeyFileFormat::Ppk3,
                KeyFileFormat::Ppk2,
                KeyFileFormat::Pem,
                KeyFileFormat::Pkcs8,
            ] {
                let is_ed25519 = matches!(original.key_data(), KeypairData::Ed25519(_));
                for passphrase in [None, Some(&pass)] {
                    let result = convert(&path, None, format, passphrase, Some("new comment"));
                    if format == KeyFileFormat::Pem && (is_ed25519 || passphrase.is_some()) {
                        assert_eq!(result.unwrap_err().code(), ErrorCode::Unsupported);
                        continue;
                    }
                    let out = file(dir.path(), "out", &result.unwrap());
                    let info = inspect(&out, passphrase).unwrap();
                    assert_eq!(info.format, format);
                    assert_eq!(info.encrypted, passphrase.is_some());
                    let back =
                        convert(&out, passphrase, KeyFileFormat::Openssh, None, None).unwrap();
                    let back = PrivateKey::from_openssh(back.as_str()).unwrap();
                    assert_eq!(back.key_data(), original.key_data(), "{format:?}");
                    if matches!(
                        format,
                        KeyFileFormat::Openssh | KeyFileFormat::Ppk3 | KeyFileFormat::Ppk2
                    ) {
                        assert_eq!(back.comment(), "new comment");
                    }
                }
            }
        }
    }

    #[test]
    fn written_keys_open_in_openssl() {
        if std::process::Command::new("openssl")
            .arg("version")
            .output()
            .is_err()
        {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = file(dir.path(), "rsa", td::PPK_RSA_3072_OPENSSH);
        let out = convert(&path, None, KeyFileFormat::Pkcs8, Some(&secret("p")), None).unwrap();
        let pkcs8 = file(dir.path(), "rsa.pem", &out);
        let opened = std::process::Command::new("openssl")
            .args(["pkey", "-noout", "-passin", "pass:p", "-in"])
            .arg(&pkcs8)
            .output()
            .unwrap();
        assert!(
            opened.status.success(),
            "{}",
            String::from_utf8_lossy(&opened.stderr)
        );
    }

    #[test]
    fn imports_a_putty_key_into_the_ssh_folder() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        let source = file(dir.path(), "work.ppk", td::PPK_ECDSA_P256_ENC);
        let pass = secret("123");
        let info = import(
            &ssh,
            &source,
            Some(&pass),
            "work",
            Some(&secret("new")),
            None,
        )
        .unwrap();
        assert_eq!(info.format, KeyFormat::Openssh);
        assert_eq!(info.encrypted, Some(true));
        assert_eq!(info.comment, "user@example.com");
        assert!(ssh.join("work.pub").is_file());
        // Never over an existing key.
        let again = import(&ssh, &source, Some(&pass), "work", None, None).unwrap_err();
        assert_eq!(again.code(), ErrorCode::AlreadyExists);
        let bad = import(&ssh, &source, Some(&pass), "../x", None, None).unwrap_err();
        assert_eq!(bad.code(), ErrorCode::InvalidInput);
        let comment = convert(
            &source,
            Some(&pass),
            KeyFileFormat::Ppk3,
            None,
            Some("a\nb"),
        );
        assert_eq!(comment.unwrap_err().code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn saved_keys_are_private_and_never_written_through_a_link() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        fs::create_dir(&ssh).unwrap();
        let source = file(dir.path(), "id_ed25519", td::OPENSSH_ED25519);
        // Unencrypted, as without a new passphrase.
        let text = convert(&source, None, KeyFileFormat::Pkcs8, None, None).unwrap();
        assert!(text.contains("BEGIN PRIVATE KEY"));
        #[cfg(unix)]
        let mode = |p: &Path| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(p).unwrap().permissions().mode() & 0o777
        };

        // Over an older file that others could read, the key is private.
        let target = file(dir.path(), "id_ed25519.pem", "old");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
        }
        save(&target, &text, &ssh).unwrap();
        assert_eq!(fs::read_to_string(&target).unwrap(), *text);
        #[cfg(unix)]
        assert_eq!(mode(&target), 0o600);
        #[cfg(windows)]
        {
            let report = crate::perms::check(&target, crate::perms::PermKind::PrivateKey);
            assert!(report.ok, "{report:?}");
        }

        // A link at the path is replaced; what it leads to is left alone.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let elsewhere = file(dir.path(), "elsewhere", "keep");
            fs::set_permissions(&elsewhere, fs::Permissions::from_mode(0o666)).unwrap();
            let link = dir.path().join("deploy.pem");
            std::os::unix::fs::symlink(&elsewhere, &link).unwrap();
            save(&link, &text, &ssh).unwrap();
            assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "keep");
            assert!(fs::symlink_metadata(&link).unwrap().is_file());
            assert_eq!(fs::read_to_string(&link).unwrap(), *text);
            assert_eq!(mode(&link), 0o600);
        }

        // Into `~/.ssh` only as a new file, however the path gets there.
        let in_ssh = ssh.join("id_ed25519.pem");
        save(&in_ssh, &text, &ssh).unwrap();
        let again = save(&in_ssh, "other", &ssh).unwrap_err();
        assert_eq!(again.code(), ErrorCode::AlreadyExists);
        let dotted = dir.path().join("x").join("..").join(".ssh");
        fs::create_dir(dir.path().join("x")).unwrap();
        let again = save(&dotted.join("id_ed25519.pem"), "other", &ssh).unwrap_err();
        assert_eq!(again.code(), ErrorCode::AlreadyExists);
        #[cfg(unix)]
        {
            let dotfiles = dir.path().join("dotfiles");
            std::os::unix::fs::symlink(&ssh, &dotfiles).unwrap();
            let again = save(&dotfiles.join("id_ed25519.pem"), "other", &ssh).unwrap_err();
            assert_eq!(again.code(), ErrorCode::AlreadyExists);
        }
        assert_eq!(fs::read_to_string(&in_ssh).unwrap(), *text);
        // No temporary file is left behind.
        assert_eq!(fs::read_dir(&ssh).unwrap().count(), 1);
    }
}
