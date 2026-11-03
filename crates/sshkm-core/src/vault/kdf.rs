//! Limits on the key derivation cost a file may ask for.
//!
//! Both of the vault's files name their own key derivation parameters: the
//! password slot in `vault.keys` and the header of a `.kdbx` file. Whoever can
//! write them — anyone with access to a synced folder, or a KeePass file
//! brought from elsewhere — could ask for terabytes of memory or years of
//! work, and the app would try before the password is even checked. The
//! parameters are checked against generous maxima first; nothing this app or
//! KeePassXC writes by default comes near them.

use crate::{Error, Result};

/// Most Argon2 memory accepted, in KiB: 2 GiB.
const MAX_MEMORY_KIB: u64 = 2 * 1024 * 1024;
/// Most Argon2 passes accepted.
const MAX_ITERATIONS: u64 = 1000;
/// Most Argon2 lanes: Argon2's own maximum. Lanes add neither memory nor
/// work, and KeePassXC uses one per processor thread (128 and more on big
/// workstations); Argon2 also needs 8 KiB of memory per lane.
const MAX_LANES: u64 = (1 << 24) - 1;
/// Most memory × passes accepted, in KiB: e.g. 1 GiB × 64 or 64 MiB × 1000.
const MAX_WORK_KIB: u64 = 64 * 1024 * 1024;
/// Most AES-KDF rounds accepted (KDBX 3 and some KDBX 4 files): about a
/// minute on a current computer.
const MAX_AES_ROUNDS: u64 = 1 << 30;

/// The first four bytes of every KeePass file, and the second four of a
/// KDBX 3 or 4 one.
const KDBX_SIGNATURE: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];
const KDBX_VERSION_2: [u8; 4] = [0x67, 0xFB, 0x4B, 0xB5];
/// Outer header field ids.
const HEADER_END: u8 = 0;
const KDBX3_TRANSFORM_ROUNDS: u8 = 6;
const KDBX4_KDF_PARAMETERS: u8 = 11;
/// Value types of a KDBX 4 variant dictionary.
const VARIANT_U32: u8 = 0x04;
const VARIANT_U64: u8 = 0x05;

/// Checks an Argon2 cost (memory in KiB) against the maxima.
pub(crate) fn check_argon2(memory_kib: u64, iterations: u64, lanes: u64) -> Result<()> {
    let within = (1..=MAX_MEMORY_KIB).contains(&memory_kib)
        && (1..=MAX_ITERATIONS).contains(&iterations)
        && (1..=MAX_LANES).contains(&lanes)
        && memory_kib >= lanes.saturating_mul(8)
        && memory_kib.saturating_mul(iterations) <= MAX_WORK_KIB;
    if within { Ok(()) } else { Err(too_costly()) }
}

/// Reads the key derivation parameters from the outer header of a KDBX 3 or
/// 4 file and checks them, before anything derives a key with them. Other
/// files are left for the KeePass reader to refuse.
pub(crate) fn check_kdbx(bytes: &[u8]) -> Result<()> {
    if bytes.get(0..4) != Some(&KDBX_SIGNATURE[..]) || bytes.get(4..8) != Some(&KDBX_VERSION_2[..])
    {
        return Ok(());
    }
    let major = bytes.get(10..12).map(|v| u16::from_le_bytes([v[0], v[1]]));
    match major {
        Some(3) => check_kdbx3(bytes),
        Some(4) => check_kdbx4(bytes),
        _ => Ok(()),
    }
}

/// KDBX 3: fields with 16-bit lengths; the AES-KDF rounds are field 6.
fn check_kdbx3(bytes: &[u8]) -> Result<()> {
    let mut pos = 12;
    loop {
        let id = *bytes.get(pos).ok_or_else(truncated)?;
        let len = usize::from(u16::from_le_bytes(take(bytes, pos + 1)?));
        let value = bytes.get(pos + 3..pos + 3 + len).ok_or_else(truncated)?;
        pos += 3 + len;
        match id {
            HEADER_END => return Ok(()),
            KDBX3_TRANSFORM_ROUNDS => {
                let rounds = u64::from_le_bytes(value.try_into().map_err(|_| malformed())?);
                check_aes(rounds)?;
            }
            _ => {}
        }
    }
}

/// KDBX 4: fields with 32-bit lengths; the KDF parameters are field 11, a
/// variant dictionary. Every occurrence is checked, since a reader keeps the
/// last one.
fn check_kdbx4(bytes: &[u8]) -> Result<()> {
    let mut pos = 12;
    loop {
        let id = *bytes.get(pos).ok_or_else(truncated)?;
        let len = length(u32::from_le_bytes(take(bytes, pos + 1)?))?;
        let value = bytes.get(pos + 5..pos + 5 + len).ok_or_else(truncated)?;
        pos += 5 + len;
        match id {
            HEADER_END => return Ok(()),
            KDBX4_KDF_PARAMETERS => check_kdf_parameters(value)?,
            _ => {}
        }
    }
}

/// The Argon2 (`M` bytes, `I`, `P`) or AES-KDF (`R`) cost in a variant
/// dictionary. A reader keeps the last value of a repeated key, so does this.
fn check_kdf_parameters(dict: &[u8]) -> Result<()> {
    let (mut memory, mut iterations, mut lanes) = (None, None, None);
    let mut pos = 2;
    while pos < dict.len() {
        let kind = dict[pos];
        if kind == HEADER_END {
            break;
        }
        let key_len = length(u32::from_le_bytes(take(dict, pos + 1)?))?;
        let key = dict.get(pos + 5..pos + 5 + key_len).ok_or_else(truncated)?;
        pos += 5 + key_len;
        let value_len = length(u32::from_le_bytes(take(dict, pos)?))?;
        let value = dict
            .get(pos + 4..pos + 4 + value_len)
            .ok_or_else(truncated)?;
        pos += 4 + value_len;
        // A fixed-size value of the wrong size would make a reader panic.
        let number = match (kind, value_len) {
            (VARIANT_U32, 4) => u64::from(u32::from_le_bytes(take(value, 0)?)),
            (VARIANT_U64, 8) => u64::from_le_bytes(take(value, 0)?),
            (VARIANT_U32 | VARIANT_U64, _) => return Err(malformed()),
            _ => continue,
        };
        match key {
            b"M" => memory = Some(number.div_ceil(1024)),
            b"I" => iterations = Some(number),
            b"P" => lanes = Some(number),
            b"R" => check_aes(number)?,
            _ => {}
        }
    }
    if memory.is_some() || iterations.is_some() || lanes.is_some() {
        check_argon2(
            memory.unwrap_or(1),
            iterations.unwrap_or(1),
            lanes.unwrap_or(1),
        )?;
    }
    Ok(())
}

fn check_aes(rounds: u64) -> Result<()> {
    if rounds <= MAX_AES_ROUNDS {
        Ok(())
    } else {
        Err(too_costly())
    }
}

fn take<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N]> {
    bytes
        .get(at..at + N)
        .and_then(|v| v.try_into().ok())
        .ok_or_else(truncated)
}

fn length(len: u32) -> Result<usize> {
    usize::try_from(len).map_err(|_| malformed())
}

fn too_costly() -> Error {
    Error::Unsupported(
        "key derivation settings that would take too much memory or time; \
         lower them in KeePassXC (Database Settings → Security)"
            .into(),
    )
}

fn truncated() -> Error {
    Error::Parse("the KeePass file's header is cut short".into())
}

fn malformed() -> Error {
    Error::Parse("the KeePass file's header is malformed".into())
}

#[cfg(test)]
mod tests {
    use keepass::Database;
    use keepass::DatabaseKey;
    use keepass::config::{DatabaseConfig, KdfConfig};

    use super::*;

    fn kdbx(kdf: KdfConfig) -> Vec<u8> {
        let mut config = DatabaseConfig::default();
        config.kdf_config = kdf;
        let db = Database::with_config(config);
        let mut bytes = Vec::new();
        db.save(&mut bytes, DatabaseKey::new().with_password("pw"))
            .unwrap();
        bytes
    }

    /// Rewrites the first 64-bit value named `key` in a KDBX 4 header.
    fn patch(mut bytes: Vec<u8>, key: u8, value: u64) -> Vec<u8> {
        let at = bytes
            .windows(6)
            .position(|w| w == [VARIANT_U64, 1, 0, 0, 0, key])
            .unwrap();
        // Type, key length, key, value length, then the value.
        let start = at + 1 + 4 + 1 + 4;
        bytes[start..start + 8].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    #[test]
    fn argon2_costs_have_maxima() {
        assert!(check_argon2(128 * 1024, 3, 4).is_ok());
        assert!(check_argon2(1024 * 1024, 64, 8).is_ok());
        assert!(check_argon2(64 * 1024, 1000, 2).is_ok());
        // KeePassXC on a 128-thread workstation.
        assert!(check_argon2(64 * 1024, 10, 128).is_ok());
        for (memory, iterations, lanes) in [
            (4 * 1024 * 1024 * 1024, 1, 1),
            (128 * 1024, 1_000_000, 4),
            (128 * 1024, 3, 1 << 20),
            (2 * 1024 * 1024, 100, 4),
            (0, 1, 1),
            (1024, 0, 1),
        ] {
            assert!(
                matches!(
                    check_argon2(memory, iterations, lanes),
                    Err(Error::Unsupported(_))
                ),
                "{memory} {iterations} {lanes}"
            );
        }
    }

    #[test]
    fn ordinary_keepass_files_pass() {
        let argon = kdbx(KdfConfig::Argon2id {
            iterations: 2,
            memory: 64 * 1024 * 1024,
            parallelism: 2,
            version: argon2::Version::Version13,
        });
        assert!(check_kdbx(&argon).is_ok());
        assert!(check_kdbx(&kdbx(KdfConfig::Aes { rounds: 60_000 })).is_ok());
        // Not a KeePass file at all: left for the reader.
        assert!(check_kdbx(b"name,url,username,password\n").is_ok());
    }

    #[test]
    fn a_header_asking_for_terabytes_is_refused_before_parsing() {
        let bytes = kdbx(KdfConfig::Argon2id {
            iterations: 2,
            memory: 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        });
        let huge = patch(bytes.clone(), b'M', 4 << 40);
        assert!(matches!(check_kdbx(&huge), Err(Error::Unsupported(_))));
        let endless = patch(bytes, b'I', u64::MAX);
        assert!(matches!(check_kdbx(&endless), Err(Error::Unsupported(_))));
        let aes = patch(kdbx(KdfConfig::Aes { rounds: 1000 }), b'R', u64::MAX);
        assert!(matches!(check_kdbx(&aes), Err(Error::Unsupported(_))));
    }

    #[test]
    fn a_cut_header_is_refused() {
        let bytes = kdbx(KdfConfig::Aes { rounds: 1000 });
        assert!(matches!(check_kdbx(&bytes[..20]), Err(Error::Parse(_))));
    }
}
