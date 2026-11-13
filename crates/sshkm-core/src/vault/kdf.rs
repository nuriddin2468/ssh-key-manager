//! Limits on the key derivation cost a file may ask for, and on the shape of
//! a KeePass file's header.
//!
//! Both of the vault's files name their own key derivation parameters: the
//! password slot in `vault.keys` and the header of a `.kdbx` file. Whoever can
//! write them — anyone with access to a synced folder, or a KeePass file
//! brought from elsewhere — could ask for terabytes of memory or years of
//! work, and the app would try before the password is even checked. The
//! parameters are checked against generous maxima first; nothing this app or
//! KeePassXC writes by default comes near them.
//!
//! The KeePass reader also takes some header values for granted: a number
//! shorter than its type stops the whole app. Those values are checked here
//! too, before the reader sees the file, and KeePass 1 files, which this app
//! never opens or writes, are refused.

use crate::{Error, Result};

/// Most Argon2 memory accepted, in KiB: 2 GiB.
const MAX_MEMORY_KIB: u64 = 2 * 1024 * 1024;
/// Most Argon2 passes accepted.
const MAX_ITERATIONS: u64 = 1000;
/// Most Argon2 lanes accepted. Lanes add no work to the hashing itself, but
/// rust-argon2, which derives the key slots' keys and the KeePass reader's,
/// starts a thread per lane for each quarter of every pass. With 65 536
/// lanes one pass took two minutes; at 256 lanes × [`MAX_ITERATIONS`] the
/// thread starts take about 10 seconds, less than the memory × passes
/// maximum allows anyway. KeePassXC uses one lane per processor thread, so
/// even a 192-thread workstation stays below. Argon2 also needs 8 KiB of
/// memory per lane.
const MAX_LANES: u64 = 256;
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
const COMPRESSION: u8 = 3;
const KDBX3_TRANSFORM_ROUNDS: u8 = 6;
const KDBX3_STREAM_START: u8 = 9;
const KDBX3_INNER_STREAM: u8 = 10;
const KDBX4_KDF_PARAMETERS: u8 = 11;
const KDBX4_PUBLIC_CUSTOM_DATA: u8 = 12;
/// Value types of a KDBX 4 variant dictionary.
const VARIANT_U32: u8 = 0x04;
const VARIANT_U64: u8 = 0x05;
const VARIANT_I32: u8 = 0x0C;
const VARIANT_I64: u8 = 0x0D;

/// Checks an Argon2 cost (memory in KiB) against the maxima.
pub(crate) fn check_argon2(memory_kib: u64, iterations: u64, lanes: u64) -> Result<()> {
    let within = (1..=MAX_MEMORY_KIB).contains(&memory_kib)
        && (1..=MAX_ITERATIONS).contains(&iterations)
        && (1..=MAX_LANES).contains(&lanes)
        && memory_kib >= lanes.saturating_mul(8)
        && memory_kib.saturating_mul(iterations) <= MAX_WORK_KIB;
    if within { Ok(()) } else { Err(too_costly()) }
}

/// Checks the outer header of a KeePass file before anything derives a key
/// with it or the KeePass reader parses it: the key derivation parameters of
/// a KDBX 3 or 4 file, and the size of every value the reader takes as a
/// fixed-size number. KeePass 1 files are refused; files that aren't KeePass
/// files at all are left for the reader to refuse.
pub(crate) fn check_kdbx(bytes: &[u8]) -> Result<()> {
    if bytes.get(0..4) != Some(&KDBX_SIGNATURE[..]) {
        return Ok(());
    }
    if bytes.get(4..8) != Some(&KDBX_VERSION_2[..]) {
        // The reader would derive a KeePass 1 file's key with however many
        // rounds its header asks for.
        return Err(Error::Unsupported(
            "KeePass 1 databases (.kdb); open it in KeePassXC and save it as .kdbx".into(),
        ));
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
        // The numbers the reader reads without looking at their length, and
        // the bytes that tell a wrong key: with fewer, any key would pass.
        let size = match id {
            COMPRESSION | KDBX3_INNER_STREAM => Some(4),
            KDBX3_TRANSFORM_ROUNDS => Some(8),
            KDBX3_STREAM_START => Some(32),
            _ => None,
        };
        if size.is_some_and(|size| size != len) {
            return Err(malformed());
        }
        match id {
            HEADER_END => return Ok(()),
            KDBX3_TRANSFORM_ROUNDS => check_aes(u64::from_le_bytes(take(value, 0)?))?,
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
            COMPRESSION if len != 4 => return Err(malformed()),
            KDBX4_KDF_PARAMETERS => check_kdf_parameters(value)?,
            KDBX4_PUBLIC_CUSTOM_DATA => drop(numbers(value)?),
            _ => {}
        }
    }
}

/// The Argon2 (`M` bytes, `I`, `P`) or AES-KDF (`R`) cost in a variant
/// dictionary. A reader keeps the last value of a repeated key, so does this.
fn check_kdf_parameters(dict: &[u8]) -> Result<()> {
    let (mut memory, mut iterations, mut lanes) = (None, None, None);
    for (key, number) in numbers(dict)? {
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

/// The unsigned numbers of a variant dictionary and their keys, in order,
/// after checking that every fixed-size number has its size: the reader
/// would stop the app on a shorter one.
fn numbers(dict: &[u8]) -> Result<Vec<(&[u8], u64)>> {
    let mut numbers = Vec::new();
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
        let number = match (kind, value_len) {
            (VARIANT_U32, 4) => u64::from(u32::from_le_bytes(take(value, 0)?)),
            (VARIANT_U64, 8) => u64::from_le_bytes(take(value, 0)?),
            (VARIANT_I32, 4) | (VARIANT_I64, 8) => continue,
            (VARIANT_U32 | VARIANT_U64 | VARIANT_I32 | VARIANT_I64, _) => {
                return Err(malformed());
            }
            _ => continue,
        };
        numbers.push((key, number));
    }
    Ok(numbers)
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

    /// The same for a 32-bit value, such as the lanes (`P`).
    fn patch_u32(mut bytes: Vec<u8>, key: u8, value: u32) -> Vec<u8> {
        let at = bytes
            .windows(6)
            .position(|w| w == [VARIANT_U32, 1, 0, 0, 0, key])
            .unwrap();
        let start = at + 1 + 4 + 1 + 4;
        bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
        bytes
    }

    #[test]
    fn argon2_costs_have_maxima() {
        assert!(check_argon2(128 * 1024, 3, 4).is_ok());
        assert!(check_argon2(1024 * 1024, 64, 8).is_ok());
        assert!(check_argon2(64 * 1024, 1000, 2).is_ok());
        // KeePassXC on a 128-thread workstation.
        assert!(check_argon2(64 * 1024, 10, 128).is_ok());
        // The most threads: 256 lanes, every pass allowed.
        assert!(check_argon2(64 * 1024, 1000, 256).is_ok());
        for (memory, iterations, lanes) in [
            (4 * 1024 * 1024 * 1024, 1, 1),
            (128 * 1024, 1_000_000, 4),
            (128 * 1024, 3, 1 << 20),
            (2 * 1024 * 1024, 100, 4),
            (0, 1, 1),
            (1024, 0, 1),
            (1024, 1, 0),
            // Enough memory for every lane and within the work maximum, but
            // a thread per lane each quarter pass: hours (tampered files).
            (512 * 1024, 128, 65_536),
            (2 * 1024 * 1024, 32, 262_144),
            (64 * 1024, 1, 257),
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
    fn a_header_asking_for_a_thread_per_lane_for_hours_is_refused() {
        let bytes = kdbx(KdfConfig::Argon2id {
            iterations: 2,
            memory: 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        });
        // 512 MiB, 128 passes, 65 536 lanes: within the memory and work
        // maxima, and about four hours of thread starts.
        let bytes = patch(bytes, b'M', 512 << 20);
        let bytes = patch(bytes, b'I', 128);
        let many_lanes = patch_u32(bytes.clone(), b'P', 65_536);
        assert!(matches!(
            check_kdbx(&many_lanes),
            Err(Error::Unsupported(_))
        ));
        let few_lanes = patch_u32(bytes, b'P', 8);
        assert!(check_kdbx(&few_lanes).is_ok());
    }

    #[test]
    fn a_cut_header_is_refused() {
        let bytes = kdbx(KdfConfig::Aes { rounds: 1000 });
        assert!(matches!(check_kdbx(&bytes[..20]), Err(Error::Parse(_))));
    }

    /// A KDBX 4 file with `field` put first in its outer header. The header
    /// hash is checked only after the reader parsed the header.
    fn with_field(mut bytes: Vec<u8>, field: &[u8]) -> Vec<u8> {
        bytes.splice(12..12, field.iter().copied());
        bytes
    }

    /// A field of a KDBX 4 header: id, 32-bit length, value.
    fn field4(id: u8, value: &[u8]) -> Vec<u8> {
        let mut field = vec![id];
        field.extend(u32::try_from(value.len()).unwrap().to_le_bytes());
        field.extend(value);
        field
    }

    /// A KDBX 3 header with `fields` (id, value) and nothing else.
    fn kdbx3(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut bytes = [KDBX_SIGNATURE, KDBX_VERSION_2].concat();
        bytes.extend([1, 0, 3, 0]);
        for (id, value) in fields {
            bytes.push(*id);
            bytes.extend(u16::try_from(value.len()).unwrap().to_le_bytes());
            bytes.extend(value);
        }
        bytes.extend([HEADER_END, 4, 0, 0x0D, 0x0A, 0x0D, 0x0A]);
        bytes
    }

    /// Whether the KeePass reader panics on `bytes`. The release build
    /// aborts on a panic, so `check_kdbx` must refuse every such file.
    fn reader_panics(bytes: &[u8]) -> bool {
        std::panic::catch_unwind(|| {
            let _ = Database::parse(bytes, DatabaseKey::new().with_password("pw"));
        })
        .is_err()
    }

    #[test]
    fn no_header_field_of_any_size_gets_past_the_check_and_stops_the_reader() {
        let base = kdbx(KdfConfig::Aes { rounds: 1000 });
        for id in 0..=13u8 {
            for len in 0..=40 {
                let bytes = with_field(base.clone(), &field4(id, &vec![0; len]));
                if check_kdbx(&bytes).is_ok() {
                    assert!(!reader_panics(&bytes), "KDBX 4 field {id}, {len} bytes");
                }
            }
        }
        for id in 1..=10u8 {
            for len in 0..=40 {
                let bytes = kdbx3(&[(id, vec![0; len])]);
                if check_kdbx(&bytes).is_ok() {
                    assert!(!reader_panics(&bytes), "KDBX 3 field {id}, {len} bytes");
                }
            }
        }
        // What the audit of the header found: a 0-byte compression field.
        let short = with_field(base, &field4(COMPRESSION, &[]));
        assert!(matches!(check_kdbx(&short), Err(Error::Parse(_))));
        let short = kdbx3(&[(COMPRESSION, Vec::new())]);
        assert!(matches!(check_kdbx(&short), Err(Error::Parse(_))));
    }

    #[test]
    fn no_dictionary_number_of_any_size_gets_past_the_check_and_stops_the_reader() {
        let base = kdbx(KdfConfig::Aes { rounds: 1000 });
        for field in [KDBX4_KDF_PARAMETERS, KDBX4_PUBLIC_CUSTOM_DATA] {
            for kind in [
                VARIANT_U32,
                VARIANT_U64,
                0x08,
                VARIANT_I32,
                VARIANT_I64,
                0x18,
                0x42,
            ] {
                for len in 0..=9usize {
                    let mut dict = vec![0x00, 0x01, kind, 1, 0, 0, 0, b'x'];
                    dict.extend(u32::try_from(len).unwrap().to_le_bytes());
                    dict.extend(std::iter::repeat_n(0, len));
                    dict.push(HEADER_END);
                    let bytes = with_field(base.clone(), &field4(field, &dict));
                    if check_kdbx(&bytes).is_ok() {
                        assert!(
                            !reader_panics(&bytes),
                            "field {field}, type {kind:#04x}, {len} bytes"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn keepass_1_files_are_refused_before_any_key_is_derived() {
        let mut kdb = [KDBX_SIGNATURE, [0x65, 0xFB, 0x4B, 0xB5]].concat();
        kdb.extend(2u32.to_le_bytes()); // AES
        kdb.extend(0x0003_0002u32.to_le_bytes());
        kdb.extend([7; 32]); // master seed, IV
        kdb.extend([0; 8]); // groups, entries
        kdb.extend([0; 32]); // contents hash
        kdb.extend([9; 32]); // transform seed
        kdb.extend(u32::MAX.to_le_bytes()); // rounds: minutes of work
        kdb.extend([0; 16]);
        assert!(matches!(check_kdbx(&kdb), Err(Error::Unsupported(_))));
    }
}
