//! The device's key pair: a Curve25519 key, the Noise static key of every
//! session. Contacts keep its public half; a session whose peer presents
//! another key is not that contact.

use std::fmt;

use base64ct::{Base64, Encoding};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use super::session::PARAMS;
use crate::{Error, Result};

const KEY_LEN: usize = 32;

/// A device's public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerKey([u8; KEY_LEN]);

impl PeerKey {
    /// The key from its 32 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        <[u8; KEY_LEN]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::invalid("a device key is 32 bytes"))
    }

    /// The key from its standard base64, as [`fmt::Display`] writes it.
    pub fn from_base64(text: &str) -> Result<Self> {
        let bytes = Base64::decode_vec(text.trim())
            .map_err(|_| Error::invalid("a device key is not base64"))?;
        Self::from_bytes(&bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Display for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&Base64::encode_string(&self.0))
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerKey({self})")
    }
}

/// This device's key pair. Its private half never leaves the app but through
/// [`Identity::to_secret`], to be kept in the system's credential store.
pub struct Identity {
    private: Zeroizing<[u8; KEY_LEN]>,
    public: PeerKey,
}

impl Identity {
    /// A new random key pair.
    pub fn generate() -> Result<Self> {
        let pair = snow::Builder::new(params())
            .generate_keypair()
            .map_err(|e| Error::Unsupported(format!("device key: {e}")))?;
        let mut private = Zeroizing::new([0; KEY_LEN]);
        private.copy_from_slice(&pair.private);
        Ok(Self {
            private,
            public: PeerKey::from_bytes(&pair.public)?,
        })
    }

    /// The key pair [`Identity::to_secret`] wrote.
    pub fn from_secret(secret: &SecretString) -> Result<Self> {
        let bytes = Zeroizing::new(
            Base64::decode_vec(secret.expose_secret())
                .map_err(|_| Error::invalid("the device key is not base64"))?,
        );
        if bytes.len() != 2 * KEY_LEN {
            return Err(Error::invalid("the device key has the wrong length"));
        }
        let mut private = Zeroizing::new([0; KEY_LEN]);
        private.copy_from_slice(&bytes[..KEY_LEN]);
        Ok(Self {
            private,
            public: PeerKey::from_bytes(&bytes[KEY_LEN..])?,
        })
    }

    /// The private and the public key, together, in standard base64.
    pub fn to_secret(&self) -> SecretString {
        let mut bytes = Zeroizing::new([0; 2 * KEY_LEN]);
        bytes[..KEY_LEN].copy_from_slice(self.private.as_slice());
        bytes[KEY_LEN..].copy_from_slice(self.public.as_bytes());
        SecretString::from(Base64::encode_string(bytes.as_slice()))
    }

    pub fn public(&self) -> PeerKey {
        self.public
    }

    pub(crate) fn private(&self) -> &[u8] {
        self.private.as_slice()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.public)
    }
}

pub(crate) fn params() -> snow::params::NoiseParams {
    // A constant that parses; `session` tests that it does.
    PARAMS
        .parse()
        .unwrap_or_else(|_| unreachable!("valid Noise parameters"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip() {
        let identity = Identity::generate().unwrap();
        let again = Identity::from_secret(&identity.to_secret()).unwrap();
        assert_eq!(again.public(), identity.public());
        assert_eq!(again.private(), identity.private());
        assert_ne!(Identity::generate().unwrap().public(), identity.public());

        let text = identity.public().to_string();
        assert_eq!(PeerKey::from_base64(&text).unwrap(), identity.public());
        assert!(!format!("{identity:?}").contains(&Base64::encode_string(identity.private())));
    }

    #[test]
    fn rejects_bad_keys() {
        assert!(PeerKey::from_base64("not base64!").is_err());
        assert!(PeerKey::from_base64("AAAA").is_err());
        assert!(Identity::from_secret(&SecretString::from("AAAA")).is_err());
    }
}
