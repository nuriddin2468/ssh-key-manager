//! A copy's payload, decrypted here rather than by the `keepass` crate, so
//! that it is checked before that crate allocates anything for it: the
//! attachments of its inner header counted, its XML scanned
//! ([`super::copy`]). The crate keeps a value for every attachment record
//! and a map entry for each, so a file of millions of empty records would
//! take gigabytes before any of its own checks ran.
//!
//! Only what a copy may be: KDBX 4 without compression (checked before,
//! [`crate::vault::kdf`]), the vault's secret as a password; AES-256,
//! Twofish or ChaCha20; AES-KDF, Argon2d or Argon2id, as the crate reads
//! them.

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::{Error, Result};

/// Outer header field ids.
const END: u8 = 0;
const CIPHER: u8 = 2;
const MASTER_SEED: u8 = 4;
const IV: u8 = 7;
const KDF_PARAMETERS: u8 = 11;
/// Inner header field ids.
const INNER_END: u8 = 0;
const INNER_BINARY: u8 = 3;

const AES256: [u8; 16] = uuid_bytes(0x31c1_f2e6_bf71_4350_be58_0521_6afc_5aff);
const TWOFISH: [u8; 16] = uuid_bytes(0xad68_f29f_576f_4bb9_a36a_d47a_f965_346c);
const CHACHA20: [u8; 16] = uuid_bytes(0xd603_8a2b_8b6f_4cb5_a524_339a_31db_b59a);
const KDF_AES_KDBX3: [u8; 16] = uuid_bytes(0xc9d9_f39a_628a_4460_bf74_0d08_c18a_4fea);
const KDF_AES_KDBX4: [u8; 16] = uuid_bytes(0x7c02_bb82_79a7_4ac0_927d_114a_0064_8238);
const KDF_ARGON2D: [u8; 16] = uuid_bytes(0xef63_6ddf_8c29_444b_91f7_a9a4_03e3_0a0c);
const KDF_ARGON2ID: [u8; 16] = uuid_bytes(0x9e29_8b19_56db_4773_b23d_fc3e_c6f0_a1e6);

const fn uuid_bytes(value: u128) -> [u8; 16] {
    value.to_be_bytes()
}

type HmacSha256 = Hmac<Sha256>;

/// The payload of a KDBX 4 file without compression (its inner header,
/// then its XML), decrypted with `secret` after the file's header and
/// blocks were checked against it. A wrong secret is
/// [`Error::WrongPassphrase`].
pub(super) fn decrypt(bytes: &[u8], secret: &SecretString) -> Result<Zeroizing<Vec<u8>>> {
    let header = OuterHeader::parse(bytes)?;
    let head = &bytes[..header.end];
    let hash = bytes.get(header.end..header.end + 32).ok_or_else(cut_off)?;
    if Sha256::digest(head).as_slice() != hash {
        return Err(malformed());
    }
    let header_hmac = bytes
        .get(header.end + 32..header.end + 64)
        .ok_or_else(cut_off)?;
    let composite = Zeroizing::new(Sha256::digest(Sha256::digest(
        secret.expose_secret().as_bytes(),
    )));
    let transformed = transform(header.kdf, composite.as_slice())?;
    let master_key = Zeroizing::new(
        Sha256::new()
            .chain_update(header.master_seed)
            .chain_update(transformed.as_slice())
            .finalize(),
    );
    let hmac_key = Zeroizing::new(
        Sha512::new()
            .chain_update(header.master_seed)
            .chain_update(transformed.as_slice())
            .chain_update([1u8])
            .finalize(),
    );
    let block_key = |index: u64| {
        Zeroizing::new(
            Sha512::new()
                .chain_update(index.to_le_bytes())
                .chain_update(hmac_key.as_slice())
                .finalize(),
        )
    };
    let mut mac = HmacSha256::new_from_slice(&block_key(u64::MAX)).map_err(|_| malformed())?;
    mac.update(head);
    mac.verify_slice(header_hmac)
        .map_err(|_| Error::WrongPassphrase)?;

    let mut payload = Zeroizing::new(Vec::new());
    let mut pos = header.end + 64;
    for index in 0u64.. {
        let hmac = bytes.get(pos..pos + 32).ok_or_else(cut_off)?;
        let size_bytes = bytes.get(pos + 32..pos + 36).ok_or_else(cut_off)?;
        let size = usize::try_from(u32::from_le_bytes(
            size_bytes.try_into().map_err(|_| cut_off())?,
        ))
        .map_err(|_| malformed())?;
        let block = bytes.get(pos + 36..pos + 36 + size).ok_or_else(cut_off)?;
        let mut mac = HmacSha256::new_from_slice(&block_key(index)).map_err(|_| malformed())?;
        mac.update(&index.to_le_bytes());
        mac.update(size_bytes);
        mac.update(block);
        mac.verify_slice(hmac).map_err(|_| malformed())?;
        if size == 0 {
            break;
        }
        payload.extend_from_slice(block);
        pos += 36 + size;
    }
    decrypt_outer(header.cipher, &master_key, header.iv, &mut payload)?;
    Ok(payload)
}

/// Where a payload's XML starts, after its inner header: refused if the
/// header holds more than `max` attachments.
pub(super) fn xml_start(payload: &[u8], max: usize) -> Result<usize> {
    let mut pos = 0;
    let mut attachments = 0usize;
    loop {
        let id = *payload.get(pos).ok_or_else(cut_off)?;
        let len = u32::from_le_bytes(
            payload
                .get(pos + 1..pos + 5)
                .and_then(|len| len.try_into().ok())
                .ok_or_else(cut_off)?,
        );
        let len = usize::try_from(len).map_err(|_| malformed())?;
        payload.get(pos + 5..pos + 5 + len).ok_or_else(cut_off)?;
        pos += 5 + len;
        match id {
            INNER_END => return Ok(pos),
            INNER_BINARY => {
                attachments += 1;
                if attachments > max {
                    return Err(Error::invalid("the copy has too many attachments"));
                }
            }
            _ => {}
        }
    }
}

/// What the outer header says of how the payload is encrypted.
struct OuterHeader<'a> {
    cipher: &'a [u8],
    master_seed: &'a [u8],
    iv: &'a [u8],
    kdf: &'a [u8],
    /// Where the header ends.
    end: usize,
}

impl<'a> OuterHeader<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self> {
        let (mut cipher, mut master_seed, mut iv, mut kdf) = (None, None, None, None);
        let mut pos = 12;
        loop {
            let id = *bytes.get(pos).ok_or_else(cut_off)?;
            let len = u32::from_le_bytes(
                bytes
                    .get(pos + 1..pos + 5)
                    .and_then(|len| len.try_into().ok())
                    .ok_or_else(cut_off)?,
            );
            let len = usize::try_from(len).map_err(|_| malformed())?;
            let value = bytes.get(pos + 5..pos + 5 + len).ok_or_else(cut_off)?;
            pos += 5 + len;
            match id {
                END => break,
                CIPHER => cipher = Some(value),
                MASTER_SEED => master_seed = Some(value),
                IV => iv = Some(value),
                KDF_PARAMETERS => kdf = Some(value),
                _ => {}
            }
        }
        Ok(Self {
            cipher: cipher.ok_or_else(malformed)?,
            master_seed: master_seed.ok_or_else(malformed)?,
            iv: iv.ok_or_else(malformed)?,
            kdf: kdf.ok_or_else(malformed)?,
            end: pos,
        })
    }
}

/// The key derived from `composite` as the header's KDF parameters say.
fn transform(dict: &[u8], composite: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let entries = variant_dictionary(dict)?;
    let get = |key: &[u8]| {
        entries
            .iter()
            .rev()
            .find(|(k, _)| *k == key)
            .map(|(_, value)| *value)
    };
    let number = |key: &[u8]| -> Result<u64> {
        match get(key).ok_or_else(malformed)? {
            value if value.len() == 8 => Ok(u64::from_le_bytes(
                value.try_into().map_err(|_| malformed())?,
            )),
            value if value.len() == 4 => Ok(u64::from(u32::from_le_bytes(
                value.try_into().map_err(|_| malformed())?,
            ))),
            _ => Err(malformed()),
        }
    };
    let id = get(b"$UUID").ok_or_else(malformed)?;
    let salt = get(b"S").ok_or_else(malformed)?;
    if id == KDF_AES_KDBX3 || id == KDF_AES_KDBX4 {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let cipher = aes::Aes256::new_from_slice(salt).map_err(|_| malformed())?;
        let mut key = Zeroizing::new(composite.to_vec());
        for _ in 0..number(b"R")? {
            for half in key.as_chunks_mut::<16>().0 {
                cipher.encrypt_block(aes::Block::from_mut_slice(half));
            }
        }
        return Ok(Zeroizing::new(Sha256::digest(key.as_slice()).to_vec()));
    }
    let variant = match id {
        id if id == KDF_ARGON2D => argon2::Variant::Argon2d,
        id if id == KDF_ARGON2ID => argon2::Variant::Argon2id,
        _ => {
            return Err(Error::Unsupported(
                "a key derivation this app doesn't know".into(),
            ));
        }
    };
    let version = argon2::Version::from_u32(u32::try_from(number(b"V")?).map_err(|_| malformed())?)
        .map_err(|_| malformed())?;
    let to_u32 = |n: u64| u32::try_from(n).map_err(|_| malformed());
    // As the `keepass` crate derives it: memory in bytes, no secret and no
    // associated data.
    let config = argon2::Config {
        ad: &[],
        hash_length: 32,
        lanes: to_u32(number(b"P")?)?,
        mem_cost: to_u32(number(b"M")? / 1024)?,
        secret: &[],
        thread_mode: argon2::ThreadMode::Parallel,
        time_cost: to_u32(number(b"I")?)?,
        variant,
        version,
    };
    argon2::hash_raw(composite, salt, &config)
        .map(Zeroizing::new)
        .map_err(|_| malformed())
}

/// A KDBX 4 variant dictionary's entries: key and value bytes, in order.
fn variant_dictionary(dict: &[u8]) -> Result<Vec<(&[u8], &[u8])>> {
    let mut entries = Vec::new();
    let mut pos = 2;
    loop {
        let kind = *dict.get(pos).ok_or_else(cut_off)?;
        if kind == 0 {
            return Ok(entries);
        }
        let field = |at: usize| -> Result<(&[u8], usize)> {
            let len = u32::from_le_bytes(
                dict.get(at..at + 4)
                    .and_then(|len| len.try_into().ok())
                    .ok_or_else(cut_off)?,
            );
            let len = usize::try_from(len).map_err(|_| malformed())?;
            Ok((
                dict.get(at + 4..at + 4 + len).ok_or_else(cut_off)?,
                at + 4 + len,
            ))
        };
        let (key, next) = field(pos + 1)?;
        let (value, next) = field(next)?;
        entries.push((key, value));
        pos = next;
    }
}

/// Decrypts `payload` in place with the outer cipher `id`.
fn decrypt_outer(id: &[u8], key: &[u8], iv: &[u8], payload: &mut Zeroizing<Vec<u8>>) -> Result<()> {
    if id == CHACHA20 {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        let mut cipher = chacha20::ChaCha20::new_from_slices(key, iv).map_err(|_| malformed())?;
        cipher.apply_keystream(payload);
        return Ok(());
    }
    let iv: [u8; 16] = iv.try_into().map_err(|_| malformed())?;
    if id == AES256 {
        use aes::cipher::{BlockDecrypt, KeyInit};
        let cipher = aes::Aes256::new_from_slice(key).map_err(|_| malformed())?;
        cbc_decrypt(payload, iv, |block| {
            cipher.decrypt_block(aes::Block::from_mut_slice(block));
        })
    } else if id == TWOFISH {
        use twofish::cipher::{BlockCipherDecrypt, KeyInit};
        let cipher = twofish::Twofish::new_from_slice(key).map_err(|_| malformed())?;
        cbc_decrypt(payload, iv, |block| {
            let mut array = twofish::cipher::Block::<twofish::Twofish>::default();
            array.copy_from_slice(block);
            cipher.decrypt_block(&mut array);
            block.copy_from_slice(&array);
        })
    } else {
        Err(Error::Unsupported("a cipher this app doesn't know".into()))
    }
}

/// CBC with PKCS #7 padding, each 16-byte block decrypted by `decrypt`.
fn cbc_decrypt(
    data: &mut Zeroizing<Vec<u8>>,
    iv: [u8; 16],
    mut decrypt: impl FnMut(&mut [u8]),
) -> Result<()> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return Err(malformed());
    }
    let mut previous = iv;
    for block in data.as_chunks_mut::<16>().0 {
        let cipher_text = *block;
        decrypt(block);
        for (byte, chained) in block.iter_mut().zip(previous) {
            *byte ^= chained;
        }
        previous = cipher_text;
    }
    let pad = usize::from(*data.last().ok_or_else(malformed)?);
    if pad == 0
        || pad > 16
        || data[data.len() - pad..]
            .iter()
            .any(|b| usize::from(*b) != pad)
    {
        return Err(malformed());
    }
    let len = data.len() - pad;
    data.truncate(len);
    Ok(())
}

fn cut_off() -> Error {
    Error::Parse("the copy is cut off".into())
}

fn malformed() -> Error {
    Error::Parse("the copy is malformed".into())
}

#[cfg(test)]
mod tests {
    use keepass::config::{CompressionConfig, DatabaseConfig, KdfConfig, OuterCipherConfig};
    use keepass::{Database, DatabaseKey};

    use super::*;

    /// A small database written with `cipher` and `kdf`, without
    /// compression, and two attachments.
    fn written(cipher: OuterCipherConfig, kdf: KdfConfig) -> Vec<u8> {
        let mut config = DatabaseConfig::default();
        config.outer_cipher_config = cipher;
        config.kdf_config = kdf;
        config.compression_config = CompressionConfig::None;
        let mut db = Database::with_config(config);
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.set_unprotected(keepass::db::fields::TITLE, "Mail <&> ü");
            entry.add_attachment("a.txt", keepass::db::Value::unprotected(b"one".to_vec()));
            entry.add_attachment("b.bin", keepass::db::Value::protected(vec![7; 100]));
        }
        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password("secret"))
            .unwrap();
        bytes
    }

    #[test]
    fn the_payload_decrypts_as_the_keepass_crate_reads_it() {
        let cheap_argon = |id: bool| {
            let (iterations, memory, parallelism) = (2, 1024 * 1024, 2);
            let version = argon2::Version::Version13;
            if id {
                KdfConfig::Argon2id {
                    iterations,
                    memory,
                    parallelism,
                    version,
                }
            } else {
                KdfConfig::Argon2 {
                    iterations,
                    memory,
                    parallelism,
                    version,
                }
            }
        };
        let secret = SecretString::from("secret");
        for (cipher, kdf) in [
            (OuterCipherConfig::AES256, cheap_argon(false)),
            (OuterCipherConfig::Twofish, KdfConfig::Aes { rounds: 1000 }),
            (OuterCipherConfig::ChaCha20, cheap_argon(true)),
        ] {
            let bytes = written(cipher.clone(), kdf);
            let payload = decrypt(&bytes, &secret).unwrap();
            let start = xml_start(&payload, 2).unwrap();
            let xml =
                Database::get_xml(&mut &bytes[..], DatabaseKey::new().with_password("secret"))
                    .unwrap();
            // The same XML; the `keepass` crate leaves Twofish's padding on.
            let ours = &payload[start..];
            let rest = &xml[ours.len().min(xml.len())..];
            assert!(xml.starts_with(ours), "{cipher:?}");
            assert!(
                rest.iter().all(|b| usize::from(*b) == rest.len()),
                "{cipher:?}: {rest:?}"
            );
            // Past the most attachments allowed: refused.
            assert!(xml_start(&payload, 1).is_err());
            // Another secret: the header's check fails.
            assert!(matches!(
                decrypt(&bytes, &SecretString::from("other")),
                Err(Error::WrongPassphrase)
            ));
        }
    }

    #[test]
    fn a_changed_block_is_refused() {
        let mut bytes = written(OuterCipherConfig::AES256, KdfConfig::Aes { rounds: 10 });
        let last = bytes.len() - 40;
        bytes[last] ^= 1;
        assert!(decrypt(&bytes, &SecretString::from("secret")).is_err());
    }
}
