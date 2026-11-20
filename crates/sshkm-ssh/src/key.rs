//! The phone's own key: ECDSA P-256 in Android Keystore, never exportable.
//!
//! The private half never reaches Rust. The app gives the public half (as
//! Keystore gives it, an X.509 `SubjectPublicKeyInfo`, or as an OpenSSH
//! line) and signs what the server needs signed when asked. Keystore's
//! `SHA256withECDSA` returns the signature in DER (`SEQUENCE { r, s }`);
//! SSH wants `string "ecdsa-sha2-nistp256"`, then a string of `mpint r`
//! and `mpint s` (RFC 5656 §3.1.2). [`PhoneKey::ssh_signature`] converts
//! and checks the signature against the key first, so a wrong key or a
//! broken signer is reported as such instead of as a refusal by the server.

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use russh::keys::PublicKey;

const KEY_TYPE: &str = "ecdsa-sha2-nistp256";
const CURVE: &str = "nistp256";

/// What is wrong with a key or a signature the app gave.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("not an ECDSA P-256 public key")]
    NotP256,
    #[error("not a DER ECDSA signature")]
    NotDer,
    #[error("the signature is not by the phone's key over this data")]
    WrongSignature,
}

/// The public half of the phone's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhoneKey {
    verifying: VerifyingKey,
    public: PublicKey,
}

impl PhoneKey {
    /// From an X.509 `SubjectPublicKeyInfo` in DER, as Android's
    /// `PublicKey.getEncoded()` gives it.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, KeyError> {
        let verifying = VerifyingKey::from_public_key_der(der).map_err(|_| KeyError::NotP256)?;
        Self::from_verifying(verifying)
    }

    /// From an OpenSSH line, `ecdsa-sha2-nistp256 AAAA… [comment]`.
    pub fn from_openssh(line: &str) -> Result<Self, KeyError> {
        let public = PublicKey::from_openssh(line.trim()).map_err(|_| KeyError::NotP256)?;
        let point = public
            .key_data()
            .ecdsa()
            .filter(|key| key.curve() == russh::keys::EcdsaCurve::NistP256)
            .ok_or(KeyError::NotP256)?;
        let verifying =
            VerifyingKey::from_sec1_bytes(point.as_sec1_bytes()).map_err(|_| KeyError::NotP256)?;
        Self::from_verifying(verifying)
    }

    fn from_verifying(verifying: VerifyingKey) -> Result<Self, KeyError> {
        let point = verifying.to_encoded_point(false);
        let mut blob = Vec::with_capacity(104);
        put_string(&mut blob, KEY_TYPE.as_bytes());
        put_string(&mut blob, CURVE.as_bytes());
        put_string(&mut blob, point.as_bytes());
        let public = PublicKey::from_bytes(&blob).map_err(|_| KeyError::NotP256)?;
        Ok(Self { verifying, public })
    }

    /// The key as russh offers it to servers.
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    /// The OpenSSH line, `ecdsa-sha2-nistp256 AAAA… comment`, for
    /// `authorized_keys`.
    pub fn to_openssh(&self, comment: &str) -> String {
        let line = self
            .public
            .to_openssh()
            .expect("an ECDSA key always encodes");
        let comment = comment.trim();
        if comment.is_empty() {
            line
        } else {
            format!("{line} {comment}")
        }
    }

    /// The `SHA256:…` fingerprint, as `ssh-keygen -l` prints it.
    pub fn fingerprint(&self) -> String {
        crate::host_keys::fingerprint(&self.public)
    }

    /// The SSH signature blob of `der`, Keystore's `SHA256withECDSA`
    /// signature over `data`, after checking it is the phone key's.
    pub fn ssh_signature(&self, data: &[u8], der: &[u8]) -> Result<Vec<u8>, KeyError> {
        let signature = Signature::from_der(der).map_err(|_| KeyError::NotDer)?;
        // Either form verifies with OpenSSH; low S is the one every
        // verifier takes.
        let signature = signature.normalize_s().unwrap_or(signature);
        self.verifying
            .verify(data, &signature)
            .map_err(|_| KeyError::WrongSignature)?;
        let (r, s) = signature.split_bytes();
        let mut inner = Vec::with_capacity(74);
        put_mpint(&mut inner, &r);
        put_mpint(&mut inner, &s);
        let mut blob = Vec::with_capacity(inner.len() + 27);
        put_string(&mut blob, KEY_TYPE.as_bytes());
        put_string(&mut blob, &inner);
        Ok(blob)
    }
}

/// Appends an SSH `string`: a 32-bit big-endian length, then the bytes.
pub(crate) fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("SSH strings are short here");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Appends an SSH `mpint` of the unsigned big-endian `bytes`: without
/// leading zeros, with one zero byte when the top bit is set (RFC 4251
/// §5).
fn put_mpint(out: &mut Vec<u8>, bytes: &[u8]) {
    let start = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    let digits = &bytes[start..];
    let pad = digits.first().is_some_and(|b| b & 0x80 != 0);
    let len = u32::try_from(digits.len() + usize::from(pad)).expect("short");
    out.extend_from_slice(&len.to_be_bytes());
    if pad {
        out.push(0);
    }
    out.extend_from_slice(digits);
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::EncodePublicKey;
    use russh::keys::signature::Verifier as _;

    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32].into()).unwrap()
    }

    #[test]
    fn spki_and_openssh_give_the_same_key() {
        let key = signing_key();
        let der = key.verifying_key().to_public_key_der().unwrap();
        let from_spki = PhoneKey::from_spki_der(der.as_bytes()).unwrap();
        let line = from_spki.to_openssh("phone");
        assert!(line.starts_with("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY"));
        assert!(line.ends_with(" phone"));
        let from_line = PhoneKey::from_openssh(&line).unwrap();
        assert_eq!(from_line, from_spki);
        assert!(from_line.fingerprint().starts_with("SHA256:"));
        // Other keys are refused.
        assert_eq!(
            PhoneKey::from_openssh(include_str!(
                "../../sshkm-core/src/keys/testdata/openssh_ed25519.pub"
            )),
            Err(KeyError::NotP256)
        );
        assert_eq!(PhoneKey::from_spki_der(b"junk"), Err(KeyError::NotP256));
    }

    #[test]
    fn der_signatures_become_ssh_signatures() {
        let key = signing_key();
        let phone =
            PhoneKey::from_spki_der(key.verifying_key().to_public_key_der().unwrap().as_bytes())
                .unwrap();
        let data = b"session id and userauth request";
        let signature: Signature = key.sign(data);
        let der = signature.to_der();
        let blob = phone.ssh_signature(data, der.as_bytes()).unwrap();
        // russh reads it back and it verifies with the public key.
        let parsed = russh::keys::ssh_key::Signature::try_from(blob.as_slice()).unwrap();
        assert_eq!(parsed.algorithm().as_str(), KEY_TYPE);
        phone.public_key().key_data().verify(data, &parsed).unwrap();

        assert_eq!(
            phone.ssh_signature(b"other data", der.as_bytes()),
            Err(KeyError::WrongSignature)
        );
        assert_eq!(
            phone.ssh_signature(data, b"\x30\x00"),
            Err(KeyError::NotDer)
        );
        let other = SigningKey::from_bytes(&[0x43; 32].into()).unwrap();
        let theirs: Signature = other.sign(data);
        assert_eq!(
            phone.ssh_signature(data, theirs.to_der().as_bytes()),
            Err(KeyError::WrongSignature)
        );
    }

    #[test]
    fn mpints() {
        let encode = |bytes: &[u8]| {
            let mut out = Vec::new();
            put_mpint(&mut out, bytes);
            out
        };
        assert_eq!(encode(&[0, 0, 0x7f]), [0, 0, 0, 1, 0x7f]);
        assert_eq!(encode(&[0x80, 1]), [0, 0, 0, 3, 0, 0x80, 1]);
        assert_eq!(encode(&[0, 0]), [0, 0, 0, 0]);
    }
}
