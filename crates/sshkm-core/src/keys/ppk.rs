//! PuTTY's private key files (`.ppk`), versions 2 and 3, read and written.
//!
//! A file is a few `Name: value` headers, the public key blob and the
//! private blob in Base64, and a MAC over the algorithm, the encryption, the
//! comment and both blobs, which tells a wrong passphrase from a damaged
//! file. As in PuTTY (`sshpubk.c`):
//!
//! - version 2 derives the AES-256-CBC key from the passphrase with SHA-1
//!   (the IV is zero) and MACs with HMAC-SHA-1 under
//!   `SHA-1("putty-private-key-file-mac-key" ‖ passphrase)`;
//! - version 3 derives the key, IV and MAC key with Argon2 (`id`, `i` or
//!   `d`) and MACs with HMAC-SHA-256; an unencrypted file's MAC key is empty;
//! - the private blob is padded to the cipher's block with the start of its
//!   own SHA-1 hash, and the MAC covers the padded plaintext.
//!
//! RSA, ECDSA (NIST P-256, P-384, P-521) and Ed25519 keys are supported;
//! DSA, Ed448 and version 1 files are recognised and refused. The Argon2
//! parameters come from the file, so they are bounded, like the bcrypt
//! rounds of an OpenSSH key: a file can't keep a thread busy for hours or
//! claim gigabytes of memory.

use std::fmt::Write as _;

use base64ct::{Base64, Encoding};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use ssh_encoding::{Decode, Encode};
use ssh_key::private::{Ed25519Keypair, KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::public::KeyData;
use ssh_key::{Cipher, Mpint, PrivateKey, PublicKey};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::legacy::{ec_p256, ec_p384, ec_p521};
use crate::{Error, Result};

const MAGIC: &str = "PuTTY-User-Key-File-";
/// The most Base64 lines of a blob, as in PuTTY (256 KiB of data).
const MAX_LINES: usize = 262_144 / 48;
/// Bounds on what a file may ask of Argon2: memory in KiB, passes, lanes,
/// and memory times passes (16 GiB worked through, some seconds). `puttygen`
/// uses 8 MiB and as many passes as take a tenth of a second.
const MAX_ARGON2_MEMORY: u32 = 1024 * 1024;
const MAX_ARGON2_PASSES: u32 = 1000;
const MAX_ARGON2_LANES: u32 = 64;
const MAX_ARGON2_WORK: u64 = 16 * 1024 * 1024;
const AES_BLOCK: usize = 16;

/// Argon2 settings this app writes version 3 files with: `puttygen`'s
/// memory and flavour, and passes that take about as long as its default.
pub(crate) const WRITE_ARGON2: Argon2Params = Argon2Params {
    flavour: Flavour::Id,
    memory: 8192,
    passes: 21,
    parallelism: 1,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavour {
    D,
    I,
    Id,
}

impl Flavour {
    fn name(self) -> &'static str {
        match self {
            Self::D => "Argon2d",
            Self::I => "Argon2i",
            Self::Id => "Argon2id",
        }
    }

    fn variant(self) -> argon2::Variant {
        match self {
            Self::D => argon2::Variant::Argon2d,
            Self::I => argon2::Variant::Argon2i,
            Self::Id => argon2::Variant::Argon2id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Argon2Params {
    pub(crate) flavour: Flavour,
    /// KiB.
    pub(crate) memory: u32,
    pub(crate) passes: u32,
    pub(crate) parallelism: u32,
}

/// A parsed `.ppk` file; the private blob is still as stored.
pub(crate) struct Ppk {
    pub(crate) version: u8,
    algorithm: String,
    encrypted: bool,
    pub(crate) comment: String,
    public_blob: Vec<u8>,
    argon2: Option<(Argon2Params, Vec<u8>)>,
    private: Zeroizing<Vec<u8>>,
    mac: Vec<u8>,
}

/// Whether `text` is meant to be a PuTTY key file.
pub(crate) fn is_ppk(text: &str) -> bool {
    text.trim_start_matches('\u{feff}').starts_with(MAGIC)
}

/// Reads the headers and blobs of a version 2 or 3 file; checks nothing
/// that needs the passphrase.
pub(crate) fn parse(text: &str) -> Result<Ppk> {
    let damaged = |what: &str| Error::Parse(format!("not a valid PuTTY key file: {what}"));
    let mut lines = text
        .trim_start_matches('\u{feff}')
        .lines()
        .map(str::trim_end);

    let (name, algorithm) = header(lines.next()).ok_or_else(|| damaged("no header"))?;
    let version = match name.strip_prefix(MAGIC) {
        Some("2") => 2,
        Some("3") => 3,
        Some("1") => {
            return Err(Error::Unsupported(
                "PuTTY key files of version 1; save the key again in a newer PuTTYgen".into(),
            ));
        }
        _ => return Err(damaged("unknown version")),
    };
    let encrypted = match field(lines.next(), "Encryption").ok_or_else(|| damaged("encryption"))? {
        "none" => false,
        "aes256-cbc" => true,
        other => return Err(Error::Unsupported(format!("PuTTY key encryption {other}"))),
    };
    let comment = field(lines.next(), "Comment")
        .ok_or_else(|| damaged("comment"))?
        .to_owned();
    let public_blob = blob(&mut lines, "Public-Lines").ok_or_else(|| damaged("public key"))?;

    let argon2 = if version == 3 && encrypted {
        let flavour = match field(lines.next(), "Key-Derivation") {
            Some("Argon2d") => Flavour::D,
            Some("Argon2i") => Flavour::I,
            Some("Argon2id") => Flavour::Id,
            _ => return Err(damaged("key derivation")),
        };
        let mut number = |name| {
            field(lines.next(), name)
                .and_then(|v| v.parse::<u32>().ok())
                .ok_or_else(|| damaged(name))
        };
        let params = Argon2Params {
            flavour,
            memory: number("Argon2-Memory")?,
            passes: number("Argon2-Passes")?,
            parallelism: number("Argon2-Parallelism")?,
        };
        let salt = field(lines.next(), "Argon2-Salt")
            .and_then(from_hex)
            .ok_or_else(|| damaged("salt"))?;
        Some((params, salt))
    } else {
        None
    };

    let private =
        Zeroizing::new(blob(&mut lines, "Private-Lines").ok_or_else(|| damaged("private key"))?);
    let mac = field(lines.next(), "Private-MAC")
        .and_then(from_hex)
        .ok_or_else(|| damaged("MAC"))?;
    if mac.len() != if version == 2 { 20 } else { 32 } {
        return Err(damaged("MAC"));
    }
    if encrypted && (private.is_empty() || !private.len().is_multiple_of(AES_BLOCK)) {
        return Err(damaged("private key"));
    }
    Ok(Ppk {
        version,
        algorithm: algorithm.to_owned(),
        encrypted,
        comment,
        public_blob,
        argon2,
        private,
        mac,
    })
}

impl Ppk {
    pub(crate) fn encrypted(&self) -> bool {
        self.encrypted
    }

    /// The public key, with the file's comment. Needs no passphrase.
    pub(crate) fn public_key(&self) -> Result<PublicKey> {
        let key_data = KeyData::decode(&mut self.public_blob.as_slice())
            .map_err(|_| Error::Parse("not a valid PuTTY key file: public key".into()))?;
        if key_data.algorithm().as_str() != self.algorithm {
            return Err(Error::Parse(
                "not a valid PuTTY key file: the header names another algorithm".into(),
            ));
        }
        supported(&key_data)?;
        Ok(PublicKey::new(key_data, self.comment.clone()))
    }

    /// Checks the MAC and decodes the private key. A MAC that doesn't match
    /// means a wrong passphrase if the file is encrypted, and a damaged file
    /// otherwise.
    pub(crate) fn decrypt(&self, passphrase: Option<&SecretString>) -> Result<PrivateKey> {
        let public = self.public_key()?;
        let passphrase = passphrase.map_or("", |p| p.expose_secret());
        if self.encrypted && passphrase.is_empty() {
            return Err(Error::PassphraseRequired);
        }
        if let Some((params, _)) = &self.argon2 {
            check_argon2(params)?;
        }
        let keys = derive(
            self.version,
            self.encrypted,
            passphrase,
            self.argon2.as_ref().map(|(p, s)| (p, s.as_slice())),
        )?;
        let mut private = self.private.clone();
        if self.encrypted {
            Cipher::Aes256Cbc
                .decrypt(&keys.cipher_key, &keys.iv, &mut private, None)
                .map_err(|_| Error::Parse("not a valid PuTTY key file: private key".into()))?;
        }
        let mac = mac(
            self.version,
            &keys.mac_key,
            &self.algorithm,
            self.encrypted,
            &self.comment,
            &self.public_blob,
            &private,
        );
        if !bool::from(mac.ct_eq(&self.mac)) {
            return Err(if self.encrypted {
                Error::WrongPassphrase
            } else {
                Error::Parse("the PuTTY key file is damaged: its MAC does not match".into())
            });
        }
        let keypair = keypair(public.key_data(), &private)?;
        PrivateKey::new(keypair, self.comment.clone())
            .map_err(|e| Error::Parse(format!("not a valid PuTTY key: {e}")))
    }
}

/// `key` as a version 2 or 3 file, encrypted with `passphrase` if one is
/// given (version 3 with [`WRITE_ARGON2`] and a random salt).
pub(crate) fn encode(
    key: &PrivateKey,
    version: u8,
    passphrase: Option<&SecretString>,
) -> Result<Zeroizing<String>> {
    let mut salt = [0; 16];
    OsRng.fill_bytes(&mut salt);
    encode_with(key, version, passphrase, WRITE_ARGON2, &salt)
}

pub(crate) fn encode_with(
    key: &PrivateKey,
    version: u8,
    passphrase: Option<&SecretString>,
    params: Argon2Params,
    salt: &[u8],
) -> Result<Zeroizing<String>> {
    if key.is_encrypted() {
        return Err(Error::PassphraseRequired);
    }
    let passphrase = passphrase
        .map(ExposeSecret::expose_secret)
        .filter(|p| !p.is_empty());
    let encrypted = passphrase.is_some();
    let algorithm = key.algorithm().as_str().to_owned();
    let public_blob = key
        .public_key()
        .to_bytes()
        .map_err(|e| Error::Parse(format!("encoding public key: {e}")))?;
    let mut private = private_blob(key.key_data())?;

    // Padded with the start of the blob's SHA-1 hash, as PuTTY does.
    let block = if encrypted { AES_BLOCK } else { 1 };
    let padding = (block - private.len() % block) % block;
    let hash = Sha1::digest(private.as_slice());
    private.extend_from_slice(&hash[..padding]);

    let argon2 = (version == 3 && encrypted).then_some((&params, salt));
    let keys = derive(version, encrypted, passphrase.unwrap_or(""), argon2)?;
    let mac = mac(
        version,
        &keys.mac_key,
        &algorithm,
        encrypted,
        key.comment(),
        &public_blob,
        &private,
    );
    if encrypted {
        Cipher::Aes256Cbc
            .encrypt(&keys.cipher_key, &keys.iv, &mut private)
            .map_err(|e| Error::Parse(format!("encrypting key: {e}")))?;
    }

    // Writing to a `String` can't fail.
    let mut out = Zeroizing::new(String::new());
    let _ = writeln!(out, "{MAGIC}{version}: {algorithm}");
    let cipher = if encrypted { "aes256-cbc" } else { "none" };
    let _ = writeln!(out, "Encryption: {cipher}");
    let _ = writeln!(out, "Comment: {}", key.comment());
    push_blob(&mut out, "Public-Lines", &public_blob);
    if let Some((params, salt)) = argon2 {
        let _ = writeln!(out, "Key-Derivation: {}", params.flavour.name());
        let _ = writeln!(out, "Argon2-Memory: {}", params.memory);
        let _ = writeln!(out, "Argon2-Passes: {}", params.passes);
        let _ = writeln!(out, "Argon2-Parallelism: {}", params.parallelism);
        let _ = writeln!(out, "Argon2-Salt: {}", to_hex(salt));
    }
    push_blob(&mut out, "Private-Lines", &private);
    let _ = writeln!(out, "Private-MAC: {}", to_hex(&mac));
    Ok(out)
}

/// `Name: value` → (name, value); PuTTY writes one space after the colon,
/// which an editor may have trimmed off an empty value.
fn header(line: Option<&str>) -> Option<(&str, &str)> {
    let (name, value) = line?.split_once(':')?;
    Some((name, value.strip_prefix(' ').unwrap_or(value)))
}

fn field<'a>(line: Option<&'a str>, name: &str) -> Option<&'a str> {
    header(line).filter(|(n, _)| *n == name).map(|(_, v)| v)
}

/// A `<name>: <count>` line and that many lines of Base64.
fn blob<'a>(lines: &mut impl Iterator<Item = &'a str>, name: &str) -> Option<Vec<u8>> {
    let count: usize = field(lines.next(), name)?.parse().ok()?;
    if count > MAX_LINES {
        return None;
    }
    let mut text = Zeroizing::new(String::new());
    for _ in 0..count {
        text.push_str(lines.next()?.trim());
    }
    Base64::decode_vec(&text).ok()
}

fn push_blob(out: &mut String, name: &str, data: &[u8]) {
    let text = Zeroizing::new(Base64::encode_string(data));
    let lines: Vec<&str> = text
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect();
    let _ = writeln!(out, "{name}: {}", lines.len());
    for line in lines {
        out.push_str(line);
        out.push('\n');
    }
}

struct Keys {
    cipher_key: Zeroizing<Vec<u8>>,
    iv: Zeroizing<Vec<u8>>,
    mac_key: Zeroizing<Vec<u8>>,
}

fn derive(
    version: u8,
    encrypted: bool,
    passphrase: &str,
    argon2: Option<(&Argon2Params, &[u8])>,
) -> Result<Keys> {
    if version == 3 {
        let Some((params, salt)) = argon2.filter(|_| encrypted) else {
            return Ok(Keys {
                cipher_key: Zeroizing::default(),
                iv: Zeroizing::default(),
                mac_key: Zeroizing::default(),
            });
        };
        let config = argon2::Config {
            variant: params.flavour.variant(),
            version: argon2::Version::Version13,
            mem_cost: params.memory,
            time_cost: params.passes,
            lanes: params.parallelism,
            thread_mode: argon2::ThreadMode::Sequential,
            secret: &[],
            ad: &[],
            hash_length: 80,
        };
        let out = Zeroizing::new(
            argon2::hash_raw(passphrase.as_bytes(), salt, &config)
                .map_err(|e| Error::Unsupported(format!("PuTTY key derivation: {e}")))?,
        );
        return Ok(Keys {
            cipher_key: Zeroizing::new(out[..32].to_vec()),
            iv: Zeroizing::new(out[32..48].to_vec()),
            mac_key: Zeroizing::new(out[48..80].to_vec()),
        });
    }
    let mut cipher_key = Zeroizing::new(Vec::with_capacity(40));
    for counter in 0u32..2 {
        let mut hash = Sha1::new();
        hash.update(counter.to_be_bytes());
        hash.update(passphrase.as_bytes());
        cipher_key.extend_from_slice(&hash.finalize());
    }
    cipher_key.truncate(32);
    let mut mac_key = Sha1::new();
    mac_key.update(b"putty-private-key-file-mac-key");
    mac_key.update(passphrase.as_bytes());
    Ok(Keys {
        cipher_key,
        iv: Zeroizing::new(vec![0; AES_BLOCK]),
        mac_key: Zeroizing::new(mac_key.finalize().to_vec()),
    })
}

fn check_argon2(params: &Argon2Params) -> Result<()> {
    let work = u64::from(params.memory) * u64::from(params.passes);
    if params.memory > MAX_ARGON2_MEMORY
        || params.passes > MAX_ARGON2_PASSES
        || params.parallelism > MAX_ARGON2_LANES
        || work > MAX_ARGON2_WORK
    {
        return Err(Error::Unsupported(format!(
            "the PuTTY key asks Argon2 for {} KiB and {} passes, more than this app allows; \
             save it again in PuTTYgen with the default settings",
            params.memory, params.passes
        )));
    }
    Ok(())
}

fn mac(
    version: u8,
    key: &[u8],
    algorithm: &str,
    encrypted: bool,
    comment: &str,
    public_blob: &[u8],
    private: &[u8],
) -> Vec<u8> {
    let mut data = Zeroizing::new(Vec::new());
    for part in [
        algorithm.as_bytes(),
        if encrypted {
            b"aes256-cbc".as_slice()
        } else {
            b"none"
        },
        comment.as_bytes(),
        public_blob,
        private,
    ] {
        put_string(&mut data, part);
    }
    if version == 2 {
        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes any key");
        mac.update(&data);
        mac.finalize().into_bytes().to_vec()
    } else {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key");
        mac.update(&data);
        mac.finalize().into_bytes().to_vec()
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The key types this module reads and writes.
fn supported(key: &KeyData) -> Result<()> {
    match key {
        KeyData::Rsa(_) | KeyData::Ecdsa(_) | KeyData::Ed25519(_) => Ok(()),
        other => Err(Error::Unsupported(format!(
            "{} keys can't be converted",
            other.algorithm().as_str()
        ))),
    }
}

/// The private key from PuTTY's private blob, checked against the public key.
fn keypair(public: &KeyData, private: &[u8]) -> Result<KeypairData> {
    let damaged = || Error::Parse("not a valid PuTTY key file: private key".into());
    let mut reader = private;
    let keypair = match public {
        KeyData::Rsa(public) => {
            let mut mpint = || Mpint::decode(&mut reader).map_err(|_| damaged());
            let (d, p, q, iqmp) = (mpint()?, mpint()?, mpint()?, mpint()?);
            let keypair = RsaKeypair {
                public: public.clone(),
                private: RsaPrivateKey { d, iqmp, p, q },
            };
            // The factors must make the modulus.
            super::convert::rsa_private_key(&keypair).ok_or_else(damaged)?;
            KeypairData::Rsa(keypair)
        }
        KeyData::Ecdsa(_) => {
            let scalar = Mpint::decode(&mut reader).map_err(|_| damaged())?;
            let bytes = scalar.as_positive_bytes().ok_or_else(damaged)?;
            let size = match public.algorithm().as_str() {
                "ecdsa-sha2-nistp256" => 32,
                "ecdsa-sha2-nistp384" => 48,
                _ => 66,
            };
            if bytes.len() > size {
                return Err(damaged());
            }
            let mut fixed = Zeroizing::new(vec![0; size]);
            fixed[size - bytes.len()..].copy_from_slice(bytes);
            match size {
                32 => ec_p256(&p256::SecretKey::from_slice(&fixed).map_err(|_| damaged())?),
                48 => ec_p384(&p384::SecretKey::from_slice(&fixed).map_err(|_| damaged())?),
                _ => ec_p521(&p521::SecretKey::from_slice(&fixed).map_err(|_| damaged())?),
            }
        }
        KeyData::Ed25519(_) => {
            let seed = <Vec<u8>>::decode(&mut reader).map_err(|_| damaged())?;
            let seed = Zeroizing::new(seed);
            let seed: &[u8; 32] = seed.as_slice().try_into().map_err(|_| damaged())?;
            KeypairData::Ed25519(Ed25519Keypair::from_seed(seed))
        }
        other => return supported(other).map(|()| unreachable!()),
    };
    if KeyData::try_from(&keypair).ok().as_ref() != Some(public) {
        return Err(Error::Parse(
            "the PuTTY key file's private key does not match its public key".into(),
        ));
    }
    Ok(keypair)
}

/// PuTTY's private blob of a key.
fn private_blob(keypair: &KeypairData) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::new());
    let failed = |e: ssh_encoding::Error| Error::Parse(format!("encoding key: {e}"));
    match keypair {
        KeypairData::Rsa(rsa) => {
            for mpint in [
                &rsa.private.d,
                &rsa.private.p,
                &rsa.private.q,
                &rsa.private.iqmp,
            ] {
                mpint.encode(&mut *out).map_err(failed)?;
            }
        }
        KeypairData::Ecdsa(ecdsa) => {
            Mpint::from_positive_bytes(ecdsa.private_key_bytes())
                .map_err(|e| Error::Parse(format!("encoding key: {e}")))?
                .encode(&mut *out)
                .map_err(failed)?;
        }
        KeypairData::Ed25519(ed25519) => {
            put_string(&mut out, &ed25519.private.to_bytes());
        }
        other => {
            let key = KeyData::try_from(other).map_err(|e| Error::Unsupported(e.to_string()))?;
            supported(&key)?;
        }
    }
    Ok(out)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
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
    use super::*;
    use crate::keys::testdata as td;

    fn secret(s: &str) -> SecretString {
        SecretString::from(s.to_owned())
    }

    // PuTTY's own test vectors (`test/cryptsuite.py`, `testPPKLoadSave`):
    // one Ed25519 key in four files, passphrase `test-passphrase`.
    const PUTTY_V3_CLEAR: &str = "\
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: ed25519-key-20200105
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6F
JH1W
Private-Lines: 1
AAAAIGvvIpl8jyqn8Xufkw6v3FnEGtXF3KWw55AP3/AGEBpY
Private-MAC: 816c84093fc4877e8411b8e5139c5ce35d8387a2630ff087214911d67417a54d
";
    const PUTTY_V3_ENCRYPTED: &str = "\
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: aes256-cbc
Comment: ed25519-key-20200105
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6F
JH1W
Key-Derivation: Argon2id
Argon2-Memory: 8192
Argon2-Passes: 13
Argon2-Parallelism: 1
Argon2-Salt: 37c3911bfefc8c1d11ec579627d2b3d9
Private-Lines: 1
amviz4sVUBN64jLO3gt4HGXJosUArghc4Soi7aVVLb2Tir5Baj0OQClorycuaPRd
Private-MAC: 6f5e588e475e55434106ec2c3569695b03f423228b44993a9e97d52ffe7be5a8
";
    const PUTTY_V2_CLEAR: &str = "\
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: none
Comment: ed25519-key-20200105
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6F
JH1W
Private-Lines: 1
AAAAIGvvIpl8jyqn8Xufkw6v3FnEGtXF3KWw55AP3/AGEBpY
Private-MAC: 2a629acfcfbe28488a1ba9b6948c36406bc28422
";
    const PUTTY_V2_ENCRYPTED: &str = "\
PuTTY-User-Key-File-2: ssh-ed25519
Encryption: aes256-cbc
Comment: ed25519-key-20200105
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIHJCszOHaI9X/yGLtjn22f0hO6VPMQDVtctkym6F
JH1W
Private-Lines: 1
4/jKlTgC652oa9HLVGrMjHZw7tj0sKRuZaJPOuLhGTvb25Jzpcqpbi+Uf+y+uo+Z
Private-MAC: 5b1f6f4cc43eb0060d2c3e181bc0129343adba2b
";
    const PUTTY_SALT: &str = "37c3911bfefc8c1d11ec579627d2b3d9";
    const PUTTY_PASSPHRASE: &str = "test-passphrase";

    fn load(text: &str, passphrase: Option<&str>) -> Result<PrivateKey> {
        parse(text)?.decrypt(passphrase.map(secret).as_ref())
    }

    #[test]
    fn putty_vectors_load_to_one_key() {
        let key = load(PUTTY_V3_CLEAR, None).unwrap();
        assert_eq!(key.comment(), "ed25519-key-20200105");
        let public = key.public_key().to_bytes().unwrap();
        assert_eq!(
            to_hex(&public),
            "0000000b7373682d65643235353139000000207242b33387688f57ff218bb639\
             f6d9fd213ba54f3100d5b5cb64ca6e85247d56"
        );
        for (text, passphrase) in [
            (PUTTY_V3_ENCRYPTED, Some(PUTTY_PASSPHRASE)),
            (PUTTY_V2_CLEAR, None),
            (PUTTY_V2_ENCRYPTED, Some(PUTTY_PASSPHRASE)),
        ] {
            assert_eq!(load(text, passphrase).unwrap().key_data(), key.key_data());
        }
        // The public key needs no passphrase.
        let encrypted = parse(PUTTY_V3_ENCRYPTED).unwrap();
        assert!(encrypted.encrypted());
        assert_eq!(encrypted.version, 3);
        assert_eq!(encrypted.public_key().unwrap(), *key.public_key());
    }

    #[test]
    fn putty_vectors_are_written_byte_for_byte() {
        let key = load(PUTTY_V3_CLEAR, None).unwrap();
        let salt = from_hex(PUTTY_SALT).unwrap();
        let params = Argon2Params {
            passes: 13,
            ..WRITE_ARGON2
        };
        let pass = secret(PUTTY_PASSPHRASE);
        let write = |version, passphrase| {
            encode_with(&key, version, passphrase, params, &salt)
                .unwrap()
                .to_string()
        };
        assert_eq!(write(3, None), PUTTY_V3_CLEAR);
        assert_eq!(write(3, Some(&pass)), PUTTY_V3_ENCRYPTED);
        assert_eq!(write(2, None), PUTTY_V2_CLEAR);
        assert_eq!(write(2, Some(&pass)), PUTTY_V2_ENCRYPTED);
    }

    #[test]
    fn wrong_or_missing_passphrases_and_damage_are_told_apart() {
        for text in [PUTTY_V3_ENCRYPTED, PUTTY_V2_ENCRYPTED] {
            assert!(matches!(load(text, None), Err(Error::PassphraseRequired)));
            assert!(matches!(
                load(text, Some("")),
                Err(Error::PassphraseRequired)
            ));
            assert!(matches!(
                load(text, Some("wrong")),
                Err(Error::WrongPassphrase)
            ));
        }
        // A changed comment breaks the MAC of a file without a passphrase.
        let changed = PUTTY_V2_CLEAR.replace("ed25519-key-20200105", "edited");
        assert!(matches!(load(&changed, None), Err(Error::Parse(_))));
        for broken in [
            "",
            "PuTTY-User-Key-File-9: ssh-ed25519\n",
            &PUTTY_V2_CLEAR.replace("Public-Lines: 2", "Public-Lines: 9999999"),
            &PUTTY_V2_CLEAR.replace("Private-MAC: 2a", "Private-MAC: 2"),
            &PUTTY_V3_ENCRYPTED.replace("Argon2-Salt", "Argon2-Pepper"),
        ] {
            assert!(load(broken, Some("x")).is_err(), "{broken}");
        }
        assert!(matches!(
            load("PuTTY-User-Key-File-1: ssh-rsa\nEncryption: none\n", None),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn argon2_demands_are_bounded() {
        let greedy = PUTTY_V3_ENCRYPTED.replace("Argon2-Memory: 8192", "Argon2-Memory: 4194304");
        assert!(matches!(
            load(&greedy, Some(PUTTY_PASSPHRASE)),
            Err(Error::Unsupported(_))
        ));
        let slow = PUTTY_V3_ENCRYPTED.replace("Argon2-Passes: 13", "Argon2-Passes: 900000");
        assert!(matches!(
            load(&slow, Some(PUTTY_PASSPHRASE)),
            Err(Error::Unsupported(_))
        ));
    }

    /// `puttygen` files from the `ssh-key` crate's tests (passphrase `123`),
    /// with the same keys in OpenSSH format.
    #[test]
    fn puttygen_files_match_their_openssh_keys() {
        for (ppk, passphrase, openssh) in [
            (td::PPK_RSA_3072, None, td::PPK_RSA_3072_OPENSSH),
            (td::PPK_RSA_3072_ENC, Some("123"), td::PPK_RSA_3072_OPENSSH),
            (td::PPK2_RSA_3072, None, td::PPK_RSA_3072_OPENSSH),
            (td::PPK2_RSA_3072_ENC, Some("123"), td::PPK_RSA_3072_OPENSSH),
            (td::PPK_ECDSA_P256, None, td::PPK_ECDSA_P256_OPENSSH),
            (
                td::PPK_ECDSA_P256_ENC,
                Some("123"),
                td::PPK_ECDSA_P256_OPENSSH,
            ),
        ] {
            let expected = PrivateKey::from_openssh(openssh).unwrap();
            let key = load(ppk, passphrase).unwrap();
            assert_eq!(key.key_data(), expected.key_data(), "{ppk}");
            assert_eq!(key.comment(), "user@example.com");
        }
        assert!(matches!(
            load(td::PPK_DSA_1024, None),
            Err(Error::Unsupported(_))
        ));
    }

    #[test]
    fn every_supported_key_round_trips() {
        let pass = secret("round trip");
        for openssh in [
            td::PPK_RSA_3072_OPENSSH,
            td::PPK_ECDSA_P256_OPENSSH,
            td::OPENSSH_ED25519,
        ] {
            let key = PrivateKey::from_openssh(openssh).unwrap();
            for version in [2, 3] {
                for passphrase in [None, Some(&pass)] {
                    let text = encode(&key, version, passphrase).unwrap();
                    let back = parse(&text).unwrap().decrypt(passphrase).unwrap();
                    assert_eq!(back.key_data(), key.key_data());
                    assert_eq!(back.comment(), key.comment());
                }
            }
        }
        let p384 = PrivateKey::random(
            &mut OsRng,
            ssh_key::Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP384,
            },
        )
        .unwrap();
        let text = encode(&p384, 3, None).unwrap();
        assert_eq!(
            parse(&text).unwrap().decrypt(None).unwrap().key_data(),
            p384.key_data()
        );
        // An encrypted OpenSSH key must be opened first.
        let locked = PrivateKey::from_openssh(td::OPENSSH_ED25519_ENCRYPTED).unwrap();
        assert!(matches!(
            encode(&locked, 3, None),
            Err(Error::PassphraseRequired)
        ));
    }
}
