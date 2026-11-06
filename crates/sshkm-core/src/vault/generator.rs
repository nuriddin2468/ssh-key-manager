//! Random passwords and passphrases, and how strong a password looks.

use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

mod presets;

pub use presets::{Generated, SecretPreset, TokenEncoding, UuidVersion, generate_preset};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// No quotes, backslash or space, so the result survives shells and forms.
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{}~";
/// Characters that are easy to mix up when read aloud or retyped.
const AMBIGUOUS: &str = "Il1O0o";

/// What to generate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "mode",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub enum GenerateOptions {
    /// Random characters.
    Password {
        /// 8 to 128 characters.
        length: u16,
        lowercase: bool,
        uppercase: bool,
        digits: bool,
        symbols: bool,
        /// Leave out `I l 1 O 0 o`.
        avoid_ambiguous: bool,
    },
    /// Random words from the EFF long word list (12.9 bits per word).
    Passphrase {
        /// 3 to 12 words.
        words: u16,
        /// Up to 3 characters between words.
        separator: String,
        /// Start every word with a capital letter.
        capitalize: bool,
        /// Append a digit to one random word.
        number: bool,
    },
}

/// Generates a password or passphrase with the operating system's random
/// number generator.
pub fn generate(options: &GenerateOptions) -> Result<SecretString> {
    match options {
        GenerateOptions::Password {
            length,
            lowercase,
            uppercase,
            digits,
            symbols,
            avoid_ambiguous,
        } => {
            if !(8..=128).contains(length) {
                return Err(Error::invalid("length must be 8 to 128"));
            }
            let classes: Vec<Vec<char>> = [
                (*lowercase, LOWER),
                (*uppercase, UPPER),
                (*digits, DIGITS),
                (*symbols, SYMBOLS),
            ]
            .into_iter()
            .filter(|(on, _)| *on)
            .map(|(_, set)| {
                set.chars()
                    .filter(|c| !*avoid_ambiguous || !AMBIGUOUS.contains(*c))
                    .collect()
            })
            .collect();
            if classes.is_empty() {
                return Err(Error::invalid("choose at least one kind of character"));
            }
            Ok(random_password(usize::from(*length), &classes))
        }
        GenerateOptions::Passphrase {
            words,
            separator,
            capitalize,
            number,
        } => {
            if !(3..=12).contains(words) {
                return Err(Error::invalid("words must be 3 to 12"));
            }
            if separator.chars().count() > 3 || separator.chars().any(char::is_control) {
                return Err(Error::invalid("separator must be up to 3 characters"));
            }
            Ok(random_passphrase(
                usize::from(*words),
                separator,
                *capitalize,
                *number,
            ))
        }
    }
}

/// Every chosen class appears at least once; the positions are uniform.
fn random_password(length: usize, classes: &[Vec<char>]) -> SecretString {
    let all: Vec<char> = classes.iter().flatten().copied().collect();
    loop {
        let password: String = (0..length).map(|_| all[uniform(all.len())]).collect();
        if classes
            .iter()
            .all(|class| password.chars().any(|c| class.contains(&c)))
        {
            return SecretString::from(password);
        }
    }
}

fn random_passphrase(
    words: usize,
    separator: &str,
    capitalize: bool,
    number: bool,
) -> SecretString {
    let list = diceware_wordlists::Wordlist::EffLong.get_list();
    let with_number = if number { Some(uniform(words)) } else { None };
    let mut out = String::new();
    for i in 0..words {
        if i > 0 {
            out.push_str(separator);
        }
        let word = list[uniform(list.len())];
        if capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                out.extend(first.to_uppercase());
                out.push_str(chars.as_str());
            }
        } else {
            out.push_str(word);
        }
        if with_number == Some(i) {
            out.push(char::from(b'0' + u8::try_from(uniform(10)).unwrap_or(0)));
        }
    }
    SecretString::from(out)
}

/// A uniformly distributed index below `n` (rejection sampling, no modulo bias).
fn uniform(n: usize) -> usize {
    let n = u32::try_from(n).expect("small range");
    let zone = u32::MAX - u32::MAX % n;
    loop {
        let x = OsRng.next_u32();
        if x < zone {
            return (x % n) as usize;
        }
    }
}

/// How hard a password is to guess, by the zxcvbn estimator.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS), ts(export, export_to = crate::TS_DIR))]
pub struct Strength {
    /// 0 (guessed almost at once) to 4 (more than 10¹⁰ guesses).
    pub score: u8,
    /// Estimated number of guesses, as a power of ten.
    pub guesses_log10: f64,
}

/// Estimates the strength of `password`. `context` lists words an attacker
/// would try first, such as the entry's title and user name.
pub fn strength(password: &SecretString, context: &[&str]) -> Strength {
    // zxcvbn is quadratic in the length; anything this long is strong anyway.
    let text: String = password.expose_secret().chars().take(100).collect();
    if text.is_empty() {
        return Strength {
            score: 0,
            guesses_log10: 0.0,
        };
    }
    let estimate = zxcvbn::zxcvbn(&text, context);
    Strength {
        score: estimate.score().into(),
        guesses_log10: estimate.guesses_log10(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn password(length: u16, symbols: bool, avoid_ambiguous: bool) -> String {
        let options = GenerateOptions::Password {
            length,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols,
            avoid_ambiguous,
        };
        generate(&options).unwrap().expose_secret().to_owned()
    }

    #[test]
    fn passwords_have_the_length_and_every_class() {
        for _ in 0..50 {
            let p = password(12, true, false);
            assert_eq!(p.chars().count(), 12);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn ambiguous_characters_can_be_left_out() {
        let p = password(128, false, true);
        assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
    }

    #[test]
    fn bad_options_are_rejected() {
        assert!(
            generate(&GenerateOptions::Password {
                length: 7,
                lowercase: true,
                uppercase: false,
                digits: false,
                symbols: false,
                avoid_ambiguous: false
            })
            .is_err()
        );
        assert!(
            generate(&GenerateOptions::Password {
                length: 20,
                lowercase: false,
                uppercase: false,
                digits: false,
                symbols: false,
                avoid_ambiguous: false
            })
            .is_err()
        );
        assert!(
            generate(&GenerateOptions::Passphrase {
                words: 2,
                separator: "-".into(),
                capitalize: false,
                number: false
            })
            .is_err()
        );
    }

    #[test]
    fn passphrases_join_words_from_the_list() {
        let list = diceware_wordlists::Wordlist::EffLong.get_list();
        assert_eq!(list.len(), 7776);
        let p = generate(&GenerateOptions::Passphrase {
            words: 5,
            separator: "-".into(),
            capitalize: true,
            number: true,
        })
        .unwrap();
        let words: Vec<&str> = p.expose_secret().split('-').collect();
        assert_eq!(words.len(), 5);
        assert!(
            words
                .iter()
                .all(|w| w.starts_with(|c: char| c.is_uppercase()))
        );
        assert_eq!(
            words
                .iter()
                .filter(|w| w.ends_with(|c: char| c.is_ascii_digit()))
                .count(),
            1
        );
        let base = |w: &str| {
            w.trim_end_matches(|c: char| c.is_ascii_digit())
                .to_lowercase()
        };
        assert!(words.iter().all(|w| list.contains(&base(w).as_str())));
    }

    #[test]
    fn strength_tells_weak_from_strong() {
        let weak = strength(&SecretString::from("password1"), &[]);
        let strong = strength(&SecretString::from("Vq7#mZ2!pL9@xR4$"), &[]);
        assert!(weak.score <= 1);
        assert_eq!(strong.score, 4);
        let named = strength(&SecretString::from("github2024"), &["github"]);
        assert!(named.score <= 2);
        assert_eq!(strength(&SecretString::from(""), &[]).score, 0);
    }

    #[test]
    fn uniform_stays_in_range() {
        for n in [1, 2, 7, 26, 7776] {
            for _ in 0..200 {
                assert!(uniform(n) < n);
            }
        }
    }
}
