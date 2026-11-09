//! The ciphers browsers encrypt saved logins with. Every function returns
//! `None` when the key is wrong or the data is damaged; plaintext only ever
//! sits in [`Zeroizing`] buffers.

use aes::{Aes128, Aes256};
use aes_gcm::aead::{Aead, KeyInit as _};
use aes_gcm::{Aes256Gcm, Nonce};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;
use zeroize::Zeroizing;

/// A block cipher in CBC mode with PKCS #7 padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cbc {
    Aes128,
    Aes256,
    /// Triple DES (EDE, three keys).
    Tdes,
}

impl Cbc {
    pub(super) const fn key_len(self) -> usize {
        match self {
            Self::Aes128 => 16,
            Self::Aes256 => 32,
            Self::Tdes => 24,
        }
    }

    pub(super) const fn iv_len(self) -> usize {
        match self {
            Self::Aes128 | Self::Aes256 => 16,
            Self::Tdes => 8,
        }
    }

    /// Decrypts `data` with the first [`Self::key_len`] bytes of `key`.
    pub(super) fn decrypt(self, key: &[u8], iv: &[u8], data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let key = key.get(..self.key_len())?;
        if iv.len() != self.iv_len() || data.is_empty() || !data.len().is_multiple_of(self.iv_len())
        {
            return None;
        }
        let mut buf = Zeroizing::new(data.to_vec());
        let len = match self {
            Self::Aes128 => cbc::Decryptor::<Aes128>::new_from_slices(key, iv)
                .ok()?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .ok()?
                .len(),
            Self::Aes256 => cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
                .ok()?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .ok()?
                .len(),
            Self::Tdes => cbc::Decryptor::<TdesEde3>::new_from_slices(key, iv)
                .ok()?
                .decrypt_padded_mut::<Pkcs7>(&mut buf)
                .ok()?
                .len(),
        };
        buf.truncate(len);
        Some(buf)
    }
}

/// AES-256-GCM, as Chromium on Windows uses it: a 12-byte nonce, then the
/// ciphertext with its 16-byte tag.
pub(super) fn aes256_gcm_decrypt(key: &[u8], data: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if data.len() < 12 + 16 {
        return None;
    }
    let (nonce, sealed) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    cipher
        .decrypt(Nonce::from_slice(nonce), sealed)
        .ok()
        .map(Zeroizing::new)
}

/// Plaintext as text; `None` if it isn't UTF-8.
pub(super) fn text(plain: &Zeroizing<Vec<u8>>) -> Option<Zeroizing<String>> {
    std::str::from_utf8(plain)
        .ok()
        .map(|text| Zeroizing::new(text.to_owned()))
}

#[cfg(test)]
pub(super) mod encrypt {
    //! Encryption for the tests' fixtures.

    use aes::{Aes128, Aes256};
    use aes_gcm::aead::{Aead, KeyInit as _};
    use aes_gcm::{Aes256Gcm, Nonce};
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use des::TdesEde3;

    use super::Cbc;

    pub(in super::super) fn cbc(cipher: Cbc, key: &[u8], iv: &[u8], plain: &[u8]) -> Vec<u8> {
        let key = &key[..cipher.key_len()];
        let block = cipher.iv_len();
        let mut buf = plain.to_vec();
        buf.resize((plain.len() / block + 1) * block, 0);
        let len = match cipher {
            Cbc::Aes128 => cbc::Encryptor::<Aes128>::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plain.len())
                .unwrap()
                .len(),
            Cbc::Aes256 => cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plain.len())
                .unwrap()
                .len(),
            Cbc::Tdes => cbc::Encryptor::<TdesEde3>::new_from_slices(key, iv)
                .unwrap()
                .encrypt_padded_mut::<Pkcs7>(&mut buf, plain.len())
                .unwrap()
                .len(),
        };
        buf.truncate(len);
        buf
    }

    pub(in super::super) fn gcm(key: &[u8], nonce: &[u8; 12], plain: &[u8]) -> Vec<u8> {
        let sealed = Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt(Nonce::from_slice(nonce), plain)
            .unwrap();
        [nonce.as_slice(), &sealed].concat()
    }
}
