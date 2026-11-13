//! The encrypted channel between the browser extension and the app.
//!
//! Built only from what `WebCrypto` offers in every browser, so the extension
//! needs no crypto code of its own:
//!
//! - **Pairing.** The extension makes a P-256 key pair and a random client
//!   id, and first sends only a hash of its public key
//!   ([`pairing_commitment`]). The app makes a P-256 key pair for this
//!   pairing ([`AppPairing`]) and replies with its public key; only then does
//!   the extension send its own. Both sides show a six-digit [`pairing_code`]
//!   computed from the id and both keys; the user approves in the app after
//!   checking that the browser shows the same code. Something between the two
//!   must choose the key it gives each side before it learns the other's, so
//!   it can't make the two codes agree but by chance. From the ECDH secret
//!   both sides derive two AES-256-GCM keys with HKDF-SHA-256: one for
//!   requests, one for responses ([`ChannelKeys`]).
//! - **Messages.** A request is sealed with the request key, a random 96-bit
//!   nonce and the client id as associated data. Its response is sealed with
//!   the response key and a fresh nonce, with the client id and the request's
//!   nonce as associated data, so it answers that request and no other.
//!
//! Byte strings travel as standard base64. The labels below are part of the
//! protocol; `extension/src/shared/channel.ts` must use the same ones, and
//! `channel-vectors.json` checks that both agree.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64ct::{Base64, Encoding};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Version of the protocol; changes with any of the labels, and with the way
/// pairing goes. 2: the extension commits to its key first, and the code
/// covers both keys.
pub const PROTOCOL: u32 = 2;

const LABEL: &[u8] = b"sshkm-browser-v1";
const KEYS_INFO: &[u8] = b" keys ";
const CODE_INFO: &[u8] = b" code ";
const COMMIT_INFO: &[u8] = b" commit ";
const REQUEST_AAD: &[u8] = b" request ";
const RESPONSE_AAD: &[u8] = b" response ";

/// Bytes in a nonce.
pub const NONCE_LEN: usize = 12;
/// Bytes in an uncompressed P-256 public key.
pub const PUBLIC_KEY_LEN: usize = 65;
/// Bytes in a [`pairing_commitment`].
pub const COMMITMENT_LEN: usize = 32;

pub type MessageNonce = [u8; NONCE_LEN];

/// The two keys of a paired browser.
#[derive(Clone)]
pub struct ChannelKeys {
    request: Zeroizing<[u8; 32]>,
    response: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for ChannelKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelKeys(..)")
    }
}

/// The app's side of a completed pairing.
#[derive(Debug)]
pub struct Pairing {
    /// The app's public key, uncompressed SEC1, for the extension.
    pub app_public: Vec<u8>,
    pub keys: ChannelKeys,
}

/// Checks a client id: 16 to 64 characters of base64url.
pub fn check_client_id(client_id: &str) -> Result<()> {
    let valid = (16..=64).contains(&client_id.len())
        && client_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(Error::invalid("not a client id"))
    }
}

/// What the extension sends first while pairing: a hash of the public key it
/// sends only once it has the app's.
pub fn pairing_commitment(client_id: &str, client_public: &[u8]) -> [u8; COMMITMENT_LEN] {
    Sha256::new()
        .chain_update(LABEL)
        .chain_update(COMMIT_INFO)
        .chain_update(client_id.as_bytes())
        .chain_update(client_public)
        .finalize()
        .into()
}

/// The six digits both sides show while pairing, from the client id and both
/// public keys.
pub fn pairing_code(client_id: &str, client_public: &[u8], app_public: &[u8]) -> String {
    let digest = Sha256::new()
        .chain_update(LABEL)
        .chain_update(CODE_INFO)
        .chain_update(client_id.as_bytes())
        .chain_update(client_public)
        .chain_update(app_public)
        .finalize();
    let number = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", number % 1_000_000)
}

/// The app's key pair for one pairing: made once the extension committed to
/// its key, and sent to it before it reveals that key.
pub struct AppPairing {
    secret: SecretKey,
    public: Vec<u8>,
}

impl std::fmt::Debug for AppPairing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AppPairing(..)")
    }
}

impl AppPairing {
    pub fn new() -> Self {
        Self::with(SecretKey::random(&mut OsRng))
    }

    fn with(secret: SecretKey) -> Self {
        let public = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { secret, public }
    }

    /// Uncompressed SEC1, as sent to the extension.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// Completes a pairing with the key the extension revealed: the channel
    /// keys.
    pub fn accept(&self, client_id: &str, client_public: &[u8]) -> Result<Pairing> {
        accept_pairing_with(&self.secret, client_id, client_public)
    }
}

impl Default for AppPairing {
    fn default() -> Self {
        Self::new()
    }
}

/// A new key pair for the app, and the channel keys with `client_public`, at
/// once: for a key change over the sealed channel, where no code is shown.
pub fn accept_pairing(client_id: &str, client_public: &[u8]) -> Result<Pairing> {
    AppPairing::new().accept(client_id, client_public)
}

fn accept_pairing_with(
    app_secret: &SecretKey,
    client_id: &str,
    client_public: &[u8],
) -> Result<Pairing> {
    check_client_id(client_id)?;
    let client = parse_public_key(client_public)?;
    let app_public = app_secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let shared = p256::ecdh::diffie_hellman(app_secret.to_nonzero_scalar(), client.as_affine());
    let keys = ChannelKeys::derive(
        shared.raw_secret_bytes(),
        client_id,
        client_public,
        &app_public,
    )?;
    Ok(Pairing { app_public, keys })
}

/// The extension's side of pairing, in Rust: for tests, and as the reference
/// for `extension/src/shared/channel.ts`.
pub struct ClientPairing {
    secret: SecretKey,
    public: Vec<u8>,
}

impl ClientPairing {
    pub fn new() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public = secret
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Self { secret, public }
    }

    /// Uncompressed SEC1, as sent once the app sent its own.
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// What is sent first: a hash of the public key.
    pub fn commitment(&self, client_id: &str) -> [u8; COMMITMENT_LEN] {
        pairing_commitment(client_id, &self.public)
    }

    /// The channel keys, once the app replied with its public key.
    pub fn complete(&self, client_id: &str, app_public: &[u8]) -> Result<ChannelKeys> {
        let app = parse_public_key(app_public)?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), app.as_affine());
        ChannelKeys::derive(
            shared.raw_secret_bytes(),
            client_id,
            &self.public,
            app_public,
        )
    }
}

impl Default for ClientPairing {
    fn default() -> Self {
        Self::new()
    }
}

fn parse_public_key(bytes: &[u8]) -> Result<PublicKey> {
    if bytes.len() != PUBLIC_KEY_LEN {
        return Err(Error::invalid("not an uncompressed P-256 public key"));
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| Error::invalid("not a P-256 public key"))
}

impl ChannelKeys {
    fn derive(
        shared: &[u8],
        client_id: &str,
        client_public: &[u8],
        app_public: &[u8],
    ) -> Result<Self> {
        let mut info = Vec::with_capacity(LABEL.len() + 128 + client_id.len());
        info.extend_from_slice(LABEL);
        info.extend_from_slice(KEYS_INFO);
        info.extend_from_slice(client_id.as_bytes());
        info.extend_from_slice(client_public);
        info.extend_from_slice(app_public);
        let mut okm = Zeroizing::new([0_u8; 64]);
        Hkdf::<Sha256>::new(Some(LABEL), shared)
            .expand(&info, okm.as_mut())
            .map_err(|_| Error::invalid("key derivation failed"))?;
        let mut request = Zeroizing::new([0; 32]);
        let mut response = Zeroizing::new([0; 32]);
        request.copy_from_slice(&okm[..32]);
        response.copy_from_slice(&okm[32..]);
        Ok(Self { request, response })
    }

    /// Both keys as standard base64, request key first, for storage in the
    /// vault.
    pub(crate) fn to_base64(&self) -> (Zeroizing<String>, Zeroizing<String>) {
        (
            Zeroizing::new(Base64::encode_string(self.request.as_ref())),
            Zeroizing::new(Base64::encode_string(self.response.as_ref())),
        )
    }

    pub(crate) fn from_base64(request: &str, response: &str) -> Result<Self> {
        let decode = |text: &str| -> Result<Zeroizing<[u8; 32]>> {
            let mut key = Zeroizing::new([0; 32]);
            let decoded = Base64::decode(text, key.as_mut())
                .map_err(|_| Error::Parse("unreadable browser key".into()))?;
            if decoded.len() != 32 {
                return Err(Error::Parse("unreadable browser key".into()));
            }
            Ok(key)
        };
        Ok(Self {
            request: decode(request)?,
            response: decode(response)?,
        })
    }

    /// Opens a request. Fails if it was not sealed with this browser's key
    /// for this client id, or was changed on the way.
    pub fn open_request(
        &self,
        client_id: &str,
        nonce: &MessageNonce,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        open(
            &self.request,
            nonce,
            sealed,
            &aad(REQUEST_AAD, client_id, None),
        )
    }

    /// Seals the response to the request with `request_nonce`. Returns the
    /// response's own nonce and the sealed bytes.
    pub fn seal_response(
        &self,
        client_id: &str,
        request_nonce: &MessageNonce,
        plain: &[u8],
    ) -> Result<(MessageNonce, Vec<u8>)> {
        let aad = aad(RESPONSE_AAD, client_id, Some(request_nonce));
        seal(&self.response, plain, &aad)
    }

    /// The extension's side of [`Self::open_request`], for tests.
    pub fn seal_request(&self, client_id: &str, plain: &[u8]) -> Result<(MessageNonce, Vec<u8>)> {
        seal(&self.request, plain, &aad(REQUEST_AAD, client_id, None))
    }

    /// The extension's side of [`Self::seal_response`], for tests.
    pub fn open_response(
        &self,
        client_id: &str,
        request_nonce: &MessageNonce,
        nonce: &MessageNonce,
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let aad = aad(RESPONSE_AAD, client_id, Some(request_nonce));
        open(&self.response, nonce, sealed, &aad)
    }
}

fn aad(kind: &[u8], client_id: &str, request_nonce: Option<&MessageNonce>) -> Vec<u8> {
    let mut aad = Vec::with_capacity(LABEL.len() + kind.len() + client_id.len() + NONCE_LEN);
    aad.extend_from_slice(LABEL);
    aad.extend_from_slice(kind);
    aad.extend_from_slice(client_id.as_bytes());
    if let Some(nonce) = request_nonce {
        aad.extend_from_slice(nonce);
    }
    aad
}

fn seal(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Result<(MessageNonce, Vec<u8>)> {
    let mut nonce = [0; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let sealed = seal_with(key, &nonce, plain, aad)?;
    Ok((nonce, sealed))
}

fn seal_with(key: &[u8; 32], nonce: &MessageNonce, plain: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Aes256Gcm::new(key.into())
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| Error::invalid("encryption failed"))
}

fn open(
    key: &[u8; 32],
    nonce: &MessageNonce,
    sealed: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    Aes256Gcm::new(key.into())
        .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::invalid("the message does not open with this browser's key"))
}

/// Standard base64.
pub fn encode(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// Decodes standard base64 of at most `max` bytes.
pub fn decode(text: &str, max: usize) -> Result<Vec<u8>> {
    if text.len() > max.div_ceil(3) * 4 {
        return Err(Error::invalid("a value is too long"));
    }
    Base64::decode_vec(text).map_err(|_| Error::invalid("not base64"))
}

/// Decodes a base64 nonce.
pub fn decode_nonce(text: &str) -> Result<MessageNonce> {
    decode(text, NONCE_LEN)?
        .try_into()
        .map_err(|_| Error::invalid("not a nonce"))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    /// Shared with the extension's tests, so both sides compute the same.
    const VECTORS: &str = include_str!("channel-vectors.json");

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Vectors {
        client_id: String,
        /// Hex scalars.
        client_secret: String,
        app_secret: String,
        /// Base64, uncompressed SEC1.
        client_public: String,
        app_public: String,
        /// Base64.
        commitment: String,
        code: String,
        request_key: String,
        response_key: String,
        request_nonce: String,
        request_plain: String,
        request_sealed: String,
        response_nonce: String,
        response_plain: String,
        response_sealed: String,
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn vectors() -> Vectors {
        serde_json::from_str(VECTORS).unwrap()
    }

    #[test]
    fn matches_the_shared_vectors() {
        let v = vectors();
        let client_secret = SecretKey::from_slice(&hex(&v.client_secret)).unwrap();
        let client_public = client_secret.public_key().to_encoded_point(false);
        assert_eq!(encode(client_public.as_bytes()), v.client_public);
        assert_eq!(
            encode(&pairing_commitment(&v.client_id, client_public.as_bytes())),
            v.commitment
        );

        let app = AppPairing::with(SecretKey::from_slice(&hex(&v.app_secret)).unwrap());
        assert_eq!(encode(app.public_key()), v.app_public);
        assert_eq!(
            pairing_code(&v.client_id, client_public.as_bytes(), app.public_key()),
            v.code
        );
        let pairing = app.accept(&v.client_id, client_public.as_bytes()).unwrap();
        assert_eq!(encode(&pairing.app_public), v.app_public);
        let (request_key, response_key) = pairing.keys.to_base64();
        assert_eq!(*request_key, v.request_key);
        assert_eq!(*response_key, v.response_key);

        let request_nonce = decode_nonce(&v.request_nonce).unwrap();
        let sealed = seal_with(
            &pairing.keys.request,
            &request_nonce,
            v.request_plain.as_bytes(),
            &aad(REQUEST_AAD, &v.client_id, None),
        )
        .unwrap();
        assert_eq!(encode(&sealed), v.request_sealed);
        let opened = pairing
            .keys
            .open_request(&v.client_id, &request_nonce, &sealed)
            .unwrap();
        assert_eq!(opened.as_slice(), v.request_plain.as_bytes());

        let response_nonce = decode_nonce(&v.response_nonce).unwrap();
        let sealed = seal_with(
            &pairing.keys.response,
            &response_nonce,
            v.response_plain.as_bytes(),
            &aad(RESPONSE_AAD, &v.client_id, Some(&request_nonce)),
        )
        .unwrap();
        assert_eq!(encode(&sealed), v.response_sealed);
    }

    #[test]
    fn both_sides_derive_the_same_keys() {
        let client = ClientPairing::new();
        let pairing = accept_pairing("client-id-0123456789", client.public_key()).unwrap();
        let keys = client
            .complete("client-id-0123456789", &pairing.app_public)
            .unwrap();
        let (nonce, sealed) = keys
            .seal_request("client-id-0123456789", b"{\"hi\":1}")
            .unwrap();
        let opened = pairing
            .keys
            .open_request("client-id-0123456789", &nonce, &sealed)
            .unwrap();
        assert_eq!(opened.as_slice(), b"{\"hi\":1}");
    }

    #[test]
    fn messages_are_bound_to_their_client_key_and_request() {
        let v = vectors();
        let client_secret = SecretKey::from_slice(&hex(&v.client_secret)).unwrap();
        let public = client_secret.public_key().to_encoded_point(false);
        let keys = accept_pairing(&v.client_id, public.as_bytes())
            .unwrap()
            .keys;
        let other = accept_pairing(&v.client_id, public.as_bytes())
            .unwrap()
            .keys;

        let (nonce, mut sealed) = keys.seal_request(&v.client_id, b"hello").unwrap();
        assert!(keys.open_request(&v.client_id, &nonce, &sealed).is_ok());
        assert!(other.open_request(&v.client_id, &nonce, &sealed).is_err());
        assert!(
            keys.open_request("another-client-id-000", &nonce, &sealed)
                .is_err()
        );
        let mut wrong_nonce = nonce;
        wrong_nonce[0] ^= 1;
        assert!(
            keys.open_request(&v.client_id, &wrong_nonce, &sealed)
                .is_err()
        );
        sealed[0] ^= 1;
        assert!(keys.open_request(&v.client_id, &nonce, &sealed).is_err());

        // A response opens only for the request it answers.
        let (reply_nonce, reply) = keys.seal_response(&v.client_id, &nonce, b"ok").unwrap();
        assert!(
            keys.open_response(&v.client_id, &nonce, &reply_nonce, &reply)
                .is_ok()
        );
        assert!(
            keys.open_response(&v.client_id, &wrong_nonce, &reply_nonce, &reply)
                .is_err()
        );
        // And a request key can't open a response, or the other way round.
        assert!(
            keys.open_request(&v.client_id, &reply_nonce, &reply)
                .is_err()
        );
    }

    #[test]
    fn keys_survive_storage() {
        let v = vectors();
        let keys = ChannelKeys::from_base64(&v.request_key, &v.response_key).unwrap();
        let (request, response) = keys.to_base64();
        assert_eq!(
            (request.as_str(), response.as_str()),
            (v.request_key.as_str(), v.response_key.as_str())
        );
        assert!(ChannelKeys::from_base64("AAAA", &v.response_key).is_err());
        assert!(ChannelKeys::from_base64("not base64!", &v.response_key).is_err());
    }

    #[test]
    fn bad_pairing_input_is_refused() {
        let public = SecretKey::random(&mut OsRng)
            .public_key()
            .to_encoded_point(false);
        assert!(accept_pairing("short", public.as_bytes()).is_err());
        assert!(accept_pairing("has spaces in the id!", public.as_bytes()).is_err());
        assert!(accept_pairing("client-id-0123456789", &public.as_bytes()[..33]).is_err());
        let mut off_curve = public.as_bytes().to_vec();
        off_curve[64] ^= 1;
        assert!(accept_pairing("client-id-0123456789", &off_curve).is_err());
        let compressed = SecretKey::random(&mut OsRng)
            .public_key()
            .to_encoded_point(true);
        assert!(accept_pairing("client-id-0123456789", compressed.as_bytes()).is_err());
    }

    #[test]
    fn codes_are_six_digits_from_the_id_and_both_keys() {
        let client = [4_u8; 65];
        let app = [5_u8; 65];
        let code = pairing_code("client-id-0123456789", &client, &app);
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        assert_ne!(code, pairing_code("client-id-0123456780", &client, &app));
        let mut other_app = app;
        other_app[64] ^= 1;
        assert_ne!(
            code,
            pairing_code("client-id-0123456789", &client, &other_app),
            "another key for the app gives another code"
        );
    }

    #[test]
    fn the_commitment_binds_the_key_and_the_id() {
        let client = ClientPairing::new();
        let commitment = client.commitment("client-id-0123456789");
        assert_eq!(
            commitment,
            pairing_commitment("client-id-0123456789", client.public_key())
        );
        assert_ne!(
            commitment,
            pairing_commitment("client-id-0123456789", ClientPairing::new().public_key())
        );
        assert_ne!(commitment, client.commitment("client-id-0123456780"));
    }

    #[test]
    fn base64_limits_hold() {
        assert_eq!(decode(&encode(&[1, 2, 3]), 3).unwrap(), vec![1, 2, 3]);
        assert!(decode(&encode(&[0; 16]), 12).is_err());
        assert!(decode_nonce(&encode(&[0; 11])).is_err());
        assert!(decode_nonce(&encode(&[0; 12])).is_ok());
    }
}
