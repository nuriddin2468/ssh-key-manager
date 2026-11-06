//! Secrets made for one job, for the generator on the Tools page: passwords
//! that go into a connection URL, a shell or a `.env` file as they are, API
//! tokens and UUIDs, framework keys, Wi-Fi passwords, passphrases and PINs.
//! Like the vault's passwords they come from the operating system's random
//! number generator.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{DIGITS, GenerateOptions, LOWER, UPPER, generate, random_password, uniform};
use crate::{Error, Result};

/// With letters and digits: nothing a connection URL has to percent-encode.
const URL_SAFE_SYMBOLS: &str = "-_";
/// With letters and digits: nothing bash, zsh, fish, PowerShell or cmd treats
/// specially in an unquoted word.
const SHELL_SAFE_SYMBOLS: &str = "-_.+:";
/// With letters and digits: nothing `.env` parsers expand or cut off (`$`,
/// `#`, quotes, `\`, spaces), nor a shell that sources the file (`~`, `!`).
const ENV_SAFE_SYMBOLS: &str = "%+,-./:@_";
/// The alphabet of Django's `get_random_secret_key`, which `startproject`
/// uses.
const DJANGO: &str = "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)";
/// Lowercase letters and digits without `i l o 0 1`: easy to read off a
/// sticker and to type on a phone or a TV remote.
const WIFI: &str = "abcdefghjkmnpqrstuvwxyz23456789";
const WIFI_GROUP: usize = 4;

/// Lengths of the passwords made for a connection URL, a shell or `.env`.
const SAFE_LENGTH: std::ops::RangeInclusive<u16> = 16..=64;

/// A secret for one job. Each kind says what it is for in the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum SecretPreset {
    /// Letters, digits, `-` and `_`, so it goes into a connection URL
    /// without escaping. 16 to 64 characters.
    DatabasePassword {
        length: u16,
    },
    /// Letters, digits and `- _ . + :`, safe unquoted in any shell. 16 to 64
    /// characters.
    ShellPassword {
        length: u16,
    },
    /// Letters, digits and `% + , - . / : @ _`, safe unquoted in `.env`
    /// files. 16 to 64 characters.
    EnvPassword {
        length: u16,
    },
    /// 32 random bytes.
    ApiToken {
        encoding: TokenEncoding,
    },
    Uuid {
        version: UuidVersion,
    },
    /// 64 random bytes: the block size of HMAC-SHA-256, so the key is used
    /// as it is.
    JwtSecret {
        encoding: TokenEncoding,
    },
    /// `base64:` and 32 random bytes, as `php artisan key:generate` writes.
    LaravelAppKey,
    /// 50 characters from Django's own alphabet, as `startproject` makes.
    DjangoSecretKey,
    /// 64 random bytes in hex, as `rails secret` prints.
    RailsSecretKeyBase,
    /// Groups of four lowercase letters and digits without look-alikes,
    /// joined by `-`. 3 to 8 groups.
    WifiPassword {
        groups: u16,
    },
    /// Words from the EFF long list joined by `-`. 3 to 12 words.
    Passphrase {
        words: u16,
    },
    /// 4 to 12 digits, never all the same or a straight run like `1234`.
    Pin {
        digits: u16,
    },
}

/// How random bytes are written out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum TokenEncoding {
    /// Lowercase hexadecimal: two characters a byte.
    Hex,
    /// Base64 with `-` and `_` and no padding (RFC 4648 §5).
    Base64url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum UuidVersion {
    /// Random.
    V4,
    /// The time in milliseconds, then random: sorts by creation.
    V7,
}

/// A generated secret and how many random bits it holds.
pub struct Generated {
    pub value: SecretString,
    /// Rounded down; for a UUID, only its random part.
    pub bits: u16,
}

/// Makes a secret of the kind `preset` names.
pub fn generate_preset(preset: &SecretPreset) -> Result<Generated> {
    match *preset {
        SecretPreset::DatabasePassword { length } => safe_password(length, URL_SAFE_SYMBOLS),
        SecretPreset::ShellPassword { length } => safe_password(length, SHELL_SAFE_SYMBOLS),
        SecretPreset::EnvPassword { length } => safe_password(length, ENV_SAFE_SYMBOLS),
        SecretPreset::ApiToken { encoding } => Ok(token(32, encoding)),
        SecretPreset::JwtSecret { encoding } => Ok(token(64, encoding)),
        SecretPreset::Uuid { version } => Ok(uuid(version)),
        SecretPreset::LaravelAppKey => {
            let bytes = random_bytes(32);
            Ok(Generated {
                value: SecretString::from(format!("base64:{}", Base64::encode_string(&bytes))),
                bits: 256,
            })
        }
        SecretPreset::DjangoSecretKey => {
            let alphabet: Vec<char> = DJANGO.chars().collect();
            let value: String = (0..50).map(|_| alphabet[uniform(alphabet.len())]).collect();
            Ok(Generated {
                value: SecretString::from(value),
                bits: bits(50, alphabet.len()),
            })
        }
        SecretPreset::RailsSecretKeyBase => Ok(token(64, TokenEncoding::Hex)),
        SecretPreset::WifiPassword { groups } => wifi_password(groups),
        SecretPreset::Passphrase { words } => {
            let value = generate(&GenerateOptions::Passphrase {
                words,
                separator: "-".to_owned(),
                capitalize: false,
                number: false,
            })?;
            let list = diceware_wordlists::Wordlist::EffLong.get_list();
            Ok(Generated {
                value,
                bits: bits(words.into(), list.len()),
            })
        }
        SecretPreset::Pin { digits } => pin(digits),
    }
}

/// Lowercase, uppercase, digits and `symbols`, each at least once, never
/// starting with a symbol: a leading `-` reads as an option to many tools.
fn safe_password(length: u16, symbols: &str) -> Result<Generated> {
    if !SAFE_LENGTH.contains(&length) {
        return Err(Error::invalid("length must be 16 to 64"));
    }
    let classes: Vec<Vec<char>> = [LOWER, UPPER, DIGITS, symbols]
        .iter()
        .map(|set| set.chars().collect())
        .collect();
    let alphabet = classes.iter().map(Vec::len).sum();
    loop {
        let value = random_password(usize::from(length), &classes);
        if value
            .expose_secret()
            .starts_with(|c: char| c.is_ascii_alphanumeric())
        {
            return Ok(Generated {
                value,
                bits: bits(length.into(), alphabet),
            });
        }
    }
}

fn token(bytes: usize, encoding: TokenEncoding) -> Generated {
    let random = random_bytes(bytes);
    let value = match encoding {
        TokenEncoding::Hex => hex(&random),
        TokenEncoding::Base64url => Base64UrlUnpadded::encode_string(&random),
    };
    Generated {
        value: SecretString::from(value),
        bits: u16::try_from(bytes * 8).unwrap_or(u16::MAX),
    }
}

fn uuid(version: UuidVersion) -> Generated {
    let (id, bits) = match version {
        UuidVersion::V4 => {
            let mut bytes = [0; 16];
            OsRng.fill_bytes(&mut bytes);
            (uuid::Builder::from_random_bytes(bytes).into_uuid(), 122)
        }
        UuidVersion::V7 => {
            let millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
            let mut random = [0; 10];
            OsRng.fill_bytes(&mut random);
            let id = uuid::Builder::from_unix_timestamp_millis(millis, &random).into_uuid();
            (id, 74)
        }
    };
    Generated {
        value: SecretString::from(id.hyphenated().to_string()),
        bits,
    }
}

fn wifi_password(groups: u16) -> Result<Generated> {
    if !(3..=8).contains(&groups) {
        return Err(Error::invalid("groups must be 3 to 8"));
    }
    let alphabet: Vec<char> = WIFI.chars().collect();
    let groups = usize::from(groups);
    let mut value = String::with_capacity(groups * (WIFI_GROUP + 1));
    for group in 0..groups {
        if group > 0 {
            value.push('-');
        }
        value.extend((0..WIFI_GROUP).map(|_| alphabet[uniform(alphabet.len())]));
    }
    Ok(Generated {
        value: SecretString::from(value),
        bits: bits(groups * WIFI_GROUP, alphabet.len()),
    })
}

fn pin(digits: u16) -> Result<Generated> {
    if !(4..=12).contains(&digits) {
        return Err(Error::invalid("digits must be 4 to 12"));
    }
    let digits = usize::from(digits);
    loop {
        let pin: Zeroizing<Vec<u8>> = Zeroizing::new(
            (0..digits)
                .map(|_| u8::try_from(uniform(10)).unwrap_or(0))
                .collect(),
        );
        if !is_guessable_pin(&pin) {
            let value: String = pin.iter().map(|d| char::from(b'0' + d)).collect();
            return Ok(Generated {
                value: SecretString::from(value),
                bits: bits(digits, 10),
            });
        }
    }
}

/// The PINs anyone tries first: one digit repeated, or a straight run up or
/// down (`1234`, `9876`).
fn is_guessable_pin(digits: &[u8]) -> bool {
    let all = |step: fn(u8, u8) -> bool| digits.windows(2).all(|pair| step(pair[0], pair[1]));
    all(|a, b| a == b) || all(|a, b| b == a + 1) || all(|a, b| a == b + 1)
}

fn random_bytes(n: usize) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(vec![0; n]);
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bits of `length` characters picked uniformly from `alphabet` of them.
fn bits(length: usize, alphabet: usize) -> u16 {
    #[allow(clippy::cast_precision_loss)]
    let total = length as f64 * (alphabet as f64).log2();
    // Rounded down and small: the longest is 64 characters of 66.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bits = total.floor() as u16;
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(preset: SecretPreset) -> (String, u16) {
        let generated = generate_preset(&preset).unwrap();
        (generated.value.expose_secret().to_owned(), generated.bits)
    }

    fn only(value: &str, symbols: &str) -> bool {
        value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || symbols.contains(c))
    }

    #[test]
    fn safe_passwords_keep_to_their_alphabet() {
        for (preset, symbols) in [
            (
                SecretPreset::DatabasePassword { length: 16 },
                URL_SAFE_SYMBOLS,
            ),
            (
                SecretPreset::ShellPassword { length: 16 },
                SHELL_SAFE_SYMBOLS,
            ),
            (SecretPreset::EnvPassword { length: 16 }, ENV_SAFE_SYMBOLS),
        ] {
            for _ in 0..100 {
                let (value, _) = make(preset);
                assert_eq!(value.len(), 16);
                assert!(only(&value, symbols), "{value}");
                assert!(value.starts_with(|c: char| c.is_ascii_alphanumeric()));
                assert!(value.chars().any(|c| c.is_ascii_lowercase()));
                assert!(value.chars().any(|c| c.is_ascii_uppercase()));
                assert!(value.chars().any(|c| c.is_ascii_digit()));
                assert!(value.chars().any(|c| symbols.contains(c)));
            }
        }
    }

    #[test]
    fn database_passwords_need_no_percent_encoding() {
        // RFC 3986 unreserved characters, which userinfo carries as they are.
        let (value, bits) = make(SecretPreset::DatabasePassword { length: 32 });
        assert!(only(&value, "-._~"));
        assert_eq!(bits, 32 * 6);
        for symbols in [URL_SAFE_SYMBOLS, SHELL_SAFE_SYMBOLS, ENV_SAFE_SYMBOLS] {
            assert!(!symbols.contains(['$', '#', '\'', '"', '`', '\\', ' ', '~', '!']));
        }
    }

    #[test]
    fn lengths_out_of_range_are_rejected() {
        for preset in [
            SecretPreset::DatabasePassword { length: 15 },
            SecretPreset::ShellPassword { length: 65 },
            SecretPreset::WifiPassword { groups: 2 },
            SecretPreset::WifiPassword { groups: 9 },
            SecretPreset::Passphrase { words: 2 },
            SecretPreset::Pin { digits: 3 },
            SecretPreset::Pin { digits: 13 },
        ] {
            assert!(generate_preset(&preset).is_err(), "{preset:?}");
        }
    }

    #[test]
    fn tokens_are_32_or_64_bytes() {
        let (value, bits) = make(SecretPreset::ApiToken {
            encoding: TokenEncoding::Hex,
        });
        assert_eq!(value.len(), 64);
        assert!(value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        assert_eq!(bits, 256);

        let (value, _) = make(SecretPreset::ApiToken {
            encoding: TokenEncoding::Base64url,
        });
        assert_eq!(value.len(), 43);
        assert_eq!(Base64UrlUnpadded::decode_vec(&value).unwrap().len(), 32);

        let (value, bits) = make(SecretPreset::JwtSecret {
            encoding: TokenEncoding::Base64url,
        });
        assert_eq!(Base64UrlUnpadded::decode_vec(&value).unwrap().len(), 64);
        assert!(only(&value, "-_"));
        assert_eq!(bits, 512);
        let (value, _) = make(SecretPreset::JwtSecret {
            encoding: TokenEncoding::Hex,
        });
        assert_eq!(value.len(), 128);

        let (a, _) = make(SecretPreset::ApiToken {
            encoding: TokenEncoding::Hex,
        });
        let (b, _) = make(SecretPreset::ApiToken {
            encoding: TokenEncoding::Hex,
        });
        assert_ne!(a, b);
    }

    #[test]
    fn uuids_have_their_version() {
        let (value, bits) = make(SecretPreset::Uuid {
            version: UuidVersion::V4,
        });
        let id = uuid::Uuid::parse_str(&value).unwrap();
        assert_eq!(id.get_version_num(), 4);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
        assert_eq!(value, value.to_lowercase());
        assert_eq!(bits, 122);

        let before = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let (value, _) = make(SecretPreset::Uuid {
            version: UuidVersion::V7,
        });
        let id = uuid::Uuid::parse_str(&value).unwrap();
        assert_eq!(id.get_version_num(), 7);
        let bytes = id.as_bytes();
        let millis = bytes[..6]
            .iter()
            .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
        let diff = i128::from(millis) - i128::try_from(before.as_millis()).unwrap();
        assert!((0..5_000).contains(&diff), "{diff}");
    }

    #[test]
    fn framework_keys_look_like_their_own() {
        let (value, bits) = make(SecretPreset::LaravelAppKey);
        let encoded = value.strip_prefix("base64:").unwrap();
        assert_eq!(encoded.len(), 44);
        assert_eq!(Base64::decode_vec(encoded).unwrap().len(), 32);
        assert_eq!(bits, 256);

        let (value, _) = make(SecretPreset::DjangoSecretKey);
        assert_eq!(value.chars().count(), 50);
        assert!(value.chars().all(|c| DJANGO.contains(c)));

        let (value, bits) = make(SecretPreset::RailsSecretKeyBase);
        assert_eq!(value.len(), 128);
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(bits, 512);
    }

    #[test]
    fn wifi_passwords_come_in_readable_groups() {
        let (value, bits) = make(SecretPreset::WifiPassword { groups: 5 });
        let groups: Vec<&str> = value.split('-').collect();
        assert_eq!(groups.len(), 5);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(groups.iter().all(|g| g.chars().all(|c| WIFI.contains(c))));
        assert!(!value.contains(['i', 'l', 'o', '0', '1', 'I', 'O']));
        assert_eq!(bits, 99);
        // WPA2 takes 8 to 63 characters.
        let (longest, _) = make(SecretPreset::WifiPassword { groups: 8 });
        assert!(longest.len() <= 63);
        let (shortest, _) = make(SecretPreset::WifiPassword { groups: 3 });
        assert!(shortest.len() >= 8);
    }

    #[test]
    fn passphrases_use_the_word_list() {
        let list = diceware_wordlists::Wordlist::EffLong.get_list();
        let (value, bits) = make(SecretPreset::Passphrase { words: 6 });
        let words: Vec<&str> = value.split('-').collect();
        assert_eq!(words.len(), 6);
        assert!(words.iter().all(|w| list.contains(w)));
        assert_eq!(bits, 77);
    }

    #[test]
    fn pins_are_digits_and_never_obvious() {
        for _ in 0..300 {
            let (value, _) = make(SecretPreset::Pin { digits: 4 });
            assert_eq!(value.len(), 4);
            assert!(value.chars().all(|c| c.is_ascii_digit()));
            let digits: Vec<u8> = value.bytes().map(|b| b - b'0').collect();
            assert!(!is_guessable_pin(&digits), "{value}");
        }
        let (_, bits) = make(SecretPreset::Pin { digits: 6 });
        assert_eq!(bits, 19);
    }

    #[test]
    fn guessable_pins_are_recognised() {
        for pin in [[0, 0, 0, 0], [1, 2, 3, 4], [9, 8, 7, 6], [7, 7, 7, 7]] {
            assert!(is_guessable_pin(&pin), "{pin:?}");
        }
        for pin in [[1, 2, 3, 5], [0, 9, 0, 9], [2, 0, 2, 6]] {
            assert!(!is_guessable_pin(&pin), "{pin:?}");
        }
    }

    #[test]
    fn presets_deserialise_from_the_ui() {
        let preset: SecretPreset =
            serde_json::from_str(r#"{"kind":"apiToken","encoding":"base64url"}"#).unwrap();
        assert_eq!(
            preset,
            SecretPreset::ApiToken {
                encoding: TokenEncoding::Base64url
            }
        );
        let preset: SecretPreset = serde_json::from_str(r#"{"kind":"laravelAppKey"}"#).unwrap();
        assert_eq!(preset, SecretPreset::LaravelAppKey);
        let preset: SecretPreset =
            serde_json::from_str(r#"{"kind":"uuid","version":"v7"}"#).unwrap();
        assert_eq!(
            preset,
            SecretPreset::Uuid {
                version: UuidVersion::V7
            }
        );
    }
}
