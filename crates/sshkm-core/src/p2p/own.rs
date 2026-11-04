//! The user's own devices: whether two computers have the same vault, and
//! the names under which only they recognise each other on the network.
//!
//! Both come from [`OwnKey`], derived from the vault secret. Every computer
//! with the vault has it; nobody else learns anything from what it makes.
//! Once the vault has a new recovery key, a computer that is gone no
//! longer has it.
//!
//! - **Proof.** In its `Hello` a side sends an HMAC of the session's
//!   handshake hash and its role. A peer with the same vault checks it; any
//!   other peer sees random bytes. Being bound to the session, a proof can't
//!   be replayed in another one.
//! - **Presence.** An own device announces itself under an HMAC of its
//!   device key and the current ten-minute window, so the name changes, says
//!   nothing about the device, and only the user's other devices can tell
//!   whose it is.

use std::fmt::{self, Write as _};

use base64ct::{Base64, Encoding};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use zeroize::Zeroizing;

use super::PeerKey;

/// Seconds a presence name lasts.
pub const PRESENCE_WINDOW: u64 = 600;

const SALT: &[u8] = b"sshkm own devices";
const PROOF_LABEL: &[u8] = b"sshkm own proof";
const PRESENCE_LABEL: &[u8] = b"sshkm presence";
/// Hex digits of a presence name.
const PRESENCE_LEN: usize = 16;

/// The key own devices share, derived from the vault secret.
pub struct OwnKey(Zeroizing<[u8; 32]>);

impl OwnKey {
    pub fn from_secret(secret: &SecretString) -> Self {
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), secret.expose_secret().as_bytes());
        let mut key = Zeroizing::new([0; 32]);
        hkdf.expand(b"v1", key.as_mut())
            .unwrap_or_else(|_| unreachable!("32 bytes is a valid length"));
        Self(key)
    }

    /// Proof that the side that is (or isn't) the `initiator` of the
    /// session with this handshake hash has this vault.
    pub fn proof(&self, hash: &[u8], initiator: bool) -> String {
        Base64::encode_string(&self.proof_mac(hash, initiator).finalize().into_bytes())
    }

    /// Whether `proof` is the peer's proof for this session: made with the
    /// same vault, by the side that is (or isn't) the `initiator`.
    pub fn verify(&self, hash: &[u8], initiator: bool, proof: &str) -> bool {
        Base64::decode_vec(proof)
            .is_ok_and(|bytes| self.proof_mac(hash, initiator).verify_slice(&bytes).is_ok())
    }

    /// The name `device` announces itself under during `window`.
    pub fn presence_name(&self, device: &PeerKey, window: u64) -> String {
        let mut mac = self.mac(PRESENCE_LABEL);
        mac.update(device.as_bytes());
        mac.update(&window.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        let mut name = String::with_capacity(PRESENCE_LEN);
        for byte in &digest[..PRESENCE_LEN / 2] {
            let _ = write!(name, "{byte:02x}");
        }
        name
    }

    /// Which of `devices` announces itself as `name` around `window` (the
    /// one before and after too, for clocks a little apart).
    pub fn recognize(&self, name: &str, devices: &[PeerKey], window: u64) -> Option<PeerKey> {
        let windows = [window.saturating_sub(1), window, window.saturating_add(1)];
        devices.iter().copied().find(|device| {
            windows
                .iter()
                .any(|w| self.presence_name(device, *w).eq_ignore_ascii_case(name))
        })
    }

    fn proof_mac(&self, hash: &[u8], initiator: bool) -> Hmac<Sha256> {
        let mut mac = self.mac(PROOF_LABEL);
        mac.update(hash);
        mac.update(&[u8::from(initiator)]);
        mac
    }

    fn mac(&self, label: &[u8]) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.0.as_ref())
            .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
        mac.update(label);
        mac
    }
}

impl fmt::Debug for OwnKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnKey(…)")
    }
}

/// The presence window of a time, in seconds since 1970.
pub fn window(unix_seconds: u64) -> u64 {
    unix_seconds / PRESENCE_WINDOW
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p2p::Identity;

    fn key(secret: &str) -> OwnKey {
        OwnKey::from_secret(&SecretString::from(secret))
    }

    #[test]
    fn a_proof_holds_for_the_same_vault_session_and_role_only() {
        let (ours, other) = (key("vault one"), key("vault two"));
        let hash = [7; 32];
        let proof = ours.proof(&hash, true);
        assert!(key("vault one").verify(&hash, true, &proof));
        assert!(!other.verify(&hash, true, &proof));
        assert!(!ours.verify(&hash, false, &proof), "the other role");
        assert!(!ours.verify(&[8; 32], true, &proof), "another session");
        assert!(!ours.verify(&hash, true, "not base64!"));
        assert_ne!(ours.proof(&hash, true), other.proof(&hash, true));
    }

    #[test]
    fn presence_names_change_and_only_own_devices_tell_them_apart() {
        let ours = key("vault one");
        let (laptop, desktop) = (
            Identity::generate().unwrap().public(),
            Identity::generate().unwrap().public(),
        );
        let now = window(1_800_000_000);
        let name = ours.presence_name(&laptop, now);
        assert_eq!(name.len(), PRESENCE_LEN);
        assert!(name.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(name, ours.presence_name(&laptop, now + 1));
        assert_ne!(name, ours.presence_name(&desktop, now));
        assert_ne!(name, key("vault two").presence_name(&laptop, now));

        let devices = [desktop, laptop];
        assert_eq!(ours.recognize(&name, &devices, now), Some(laptop));
        assert_eq!(ours.recognize(&name, &devices, now + 1), Some(laptop));
        assert_eq!(ours.recognize(&name, &devices, now + 2), None);
        assert_eq!(key("vault two").recognize(&name, &devices, now), None);
    }
}
