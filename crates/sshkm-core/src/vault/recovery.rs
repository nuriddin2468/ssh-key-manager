//! Recovery keys: 256 random bits written as Crockford base32 in groups of
//! four, e.g. `7K3M-…-Q8`.
//!
//! The canonical form (upper case, with dashes) is the KeePass password of the
//! database, so typing the key exactly as printed opens the file in KeePassXC.
//! In the app the key may be typed in any case, with or without dashes and
//! spaces, and with the look-alikes `O`, `I` and `L` for `0`, `1` and `1`.

use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

/// Crockford's base32 alphabet: no `I`, `L`, `O` or `U`.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// 256 bits in 5-bit symbols.
const SYMBOLS: usize = 52;
const GROUP: usize = 4;

/// A new random recovery key in canonical form.
pub(crate) fn generate() -> SecretString {
    let mut bytes = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    encode(&bytes)
}

fn encode(bytes: &[u8; 32]) -> SecretString {
    let mut out = String::with_capacity(SYMBOLS + SYMBOLS / GROUP);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    let mut written = 0;
    let mut push = |out: &mut String, index: u32| {
        if written > 0 && written % GROUP == 0 {
            out.push('-');
        }
        out.push(char::from(ALPHABET[index as usize]));
        written += 1;
    };
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            push(&mut out, (buffer >> bits) & 31);
        }
    }
    if bits > 0 {
        push(&mut out, (buffer << (5 - bits)) & 31);
    }
    SecretString::from(out)
}

/// The canonical form of `input` if it reads as a recovery key, otherwise
/// `None` (it may still be the password of a KeePass database the user brought
/// along).
pub(crate) fn normalize(input: &SecretString) -> Option<SecretString> {
    let mut symbols = Zeroizing::new(String::with_capacity(SYMBOLS));
    for c in input.expose_secret().chars() {
        let c = match c.to_ascii_uppercase() {
            ' ' | '-' | '\t' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c if ALPHABET.contains(&(c as u8)) && c.is_ascii() => c,
            _ => return None,
        };
        symbols.push(c);
    }
    if symbols.len() != SYMBOLS {
        return None;
    }
    let mut out = String::with_capacity(SYMBOLS + SYMBOLS / GROUP);
    for (i, c) in symbols.chars().enumerate() {
        if i > 0 && i % GROUP == 0 {
            out.push('-');
        }
        out.push(c);
    }
    Some(SecretString::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_52_symbols_in_groups_of_four() {
        let key = generate();
        let key = key.expose_secret();
        assert_eq!(key.len(), 52 + 12);
        assert!(key.split('-').all(|g| g.len() == 4));
        assert!(
            key.chars()
                .all(|c| c == '-' || ALPHABET.contains(&(c as u8)))
        );
        assert_ne!(key, generate().expose_secret());
    }

    #[test]
    fn encoding_is_big_endian_base32() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0b0000_1000; // first symbol 00001, second 000|00
        bytes[31] = 0x01; // the last symbol holds the final bit, padded: 10000
        let key = encode(&bytes);
        let key = key.expose_secret();
        assert!(key.starts_with("10"));
        assert!(key.ends_with('G')); // 16
    }

    #[test]
    fn normalize_accepts_sloppy_typing() {
        let key = generate();
        let sloppy = key
            .expose_secret()
            .replace('-', " ")
            .to_lowercase()
            .replace('0', "o")
            .replace('1', "l");
        let normalized = normalize(&SecretString::from(sloppy)).unwrap();
        assert_eq!(normalized.expose_secret(), key.expose_secret());
    }

    #[test]
    fn normalize_rejects_other_text() {
        assert!(normalize(&SecretString::from("correct horse battery staple")).is_none());
        assert!(normalize(&SecretString::from("ABCD")).is_none());
        assert!(normalize(&SecretString::from("U".repeat(52))).is_none());
    }
}
